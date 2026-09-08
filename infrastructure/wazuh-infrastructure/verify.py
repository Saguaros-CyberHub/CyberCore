#!/usr/bin/env python3
"""Validate this pack; optionally exercise the installed Wazuh rules in logtest only.

No network, package installation, configuration writes, or real alert injection.
Run: python3 verify.py [--manager-tests]
The manager mode requires the pack's rule XML already installed under etc/rules.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent
APP_LOCATION = '/home/cactus-admin/CyberCore/logs/security-2026-09-07.jsonl'
NODES = [f'cyberhub-node-{n}' for n in [0, 1, 2, 3, 4, 5, 6, 10, 11]]
HOSTS = NODES + ['250-CyberCore', '251-netbox', '252-heimdall-dashboard']


def wrapped_xml(name):
    return ET.fromstring('<root>' + (ROOT / name).read_text(encoding='utf-8') + '</root>')


def sample(fixture):
    if 'log' in fixture:
        return fixture['location'], fixture['log'], fixture['decoder']
    event = {'integration': 'cybercore', 'schema_version': 1,
             'event_id': '00000000-0000-4000-8000-000000000001',
             'timestamp': '2026-09-07T20:00:00.000Z', **fixture['event']}
    return APP_LOCATION, json.dumps(event, separators=(',', ':')), 'json'


def static_checks(fixtures):
    config = wrapped_xml('agent.conf')
    blocks = config.findall('agent_config')
    assert len(blocks) == 3
    expected = [HOSTS, NODES, ['250-CyberCore']]
    for block, hosts in zip(blocks, expected):
        pattern = re.compile(block.attrib['name'])
        assert all(pattern.fullmatch(host) for host in hosts)
        assert all(not pattern.fullmatch(host) for host in HOSTS if host not in hosts)
        for outside in ['cle-cybr400-inperson-10811-610811', 'cyberhub-node-100',
                        '250-CyberCore-student', 'prefix-cyberhub-node-1']:
            assert not pattern.search(outside), outside
    assert config.find('.//frequency').text == '900'
    assert config.find('.//nodiff').text == '^/'
    for directory in config.findall('.//directories'):
        assert directory.attrib['report_changes'] == 'no'
        assert directory.attrib.get('whodata', 'no') == 'no'
        assert directory.attrib['check_all'] == 'yes'
    collectors = config.findall('.//localfile')
    assert len(collectors) == 1
    assert collectors[0].findtext('log_format') == 'json'
    assert collectors[0].findtext('location') == '/home/cactus-admin/CyberCore/logs/security-*.jsonl'
    assert not config.findall('.//command')
    assert not config.findall('.//active-response')
    ignores = config.findall('.//ignore')
    assert len(ignores) == 1
    terms = ignores[0].text.split('|')
    assert sorted(terms) == sorted(f'^/etc/pve/nodes/{node}/lrm_status$' for node in NODES)
    # OSMatch/sregex is intentionally not treated as PCRE. Literal periods are literal here.
    for term in terms:
        assert term.startswith('^') and term.endswith('$')
        assert not any(c in term for c in '[]()\\?+*')
    watched = ','.join(x.text for x in config.findall('.//directories'))
    for required in ['/etc/pve/user.cfg', '/etc/pve/domains.cfg', '/etc/pve/storage.cfg',
                     '/etc/pve/firewall/cluster.fw', '/etc/shadow', '/etc/ssh', '/var/spool/cron',
                     '/home/cactus-admin/.ssh',
                     '/home/cactus-admin/CyberCore/.env', '/home/cactus-admin/CyberCore/front-end/src']:
        assert required in watched
    rules_root = wrapped_xml('cybercore-infrastructure-rules.xml')
    rules = rules_root.findall('.//rule')
    indexed = {int(rule.attrib['id']): rule for rule in rules}
    assert len(indexed) == len(rules)
    assert all(111900 <= n <= 111939 for n in indexed)
    for rule in rules:
        assert rule.attrib.get('overwrite', 'no') == 'no'
        assert rule.findtext('description')
        for field in rule.findall('field') + rule.findall('match') + rule.findall('location') + rule.findall('action'):
            assert field.attrib.get('type') == 'pcre2'
            re.compile(field.text)
        for field in rule.findall('field'):
            assert field.attrib['name'] not in {'action', 'srcip', 'dstip', 'srcport', 'dstport',
                                               'user', 'srcuser', 'dstuser', 'id', 'url', 'status',
                                               'protocol', 'data', 'extra_data', 'system_name'}
        for ref in rule.findall('if_sid') + rule.findall('if_matched_sid'):
            assert all(int(n) in indexed or int(n) == 504 for n in re.split(r'[,\s]+', ref.text))
        if int(rule.attrib['id']) >= 111920 and int(rule.attrib['level']) > 0:
            assert 'no_full_log' in [option.text for option in rule.findall('options')]
    names = [f['name'] for f in fixtures]
    assert len(names) == len(set(names))
    for fixture in fixtures:
        _, log, _ = sample(fixture)
        assert '\n' not in log
        if 'event' in fixture:
            assert 'event_type' not in fixture['event'], 'Reserved Suricata discriminator must not appear.'
            assert fixture['event']['cybercore_event'] in {'audit', 'http', 'health'}
        expected_rule = fixture['rule']
        if expected_rule in indexed:
            assert int(indexed[expected_rule].attrib['level']) == fixture['level']
    print(f'PASS: 3 scoped profiles, {len(rules)} additive rules, {len(fixtures)} fixtures; static safety checks.')


def manager_tests(fixtures):
    binary = '/var/ossec/bin/wazuh-logtest'
    assert Path(binary).is_file(), 'Run --manager-tests on the Wazuh manager after staging the rules.'
    subprocess.run(['/var/ossec/bin/verify-agent-conf', '-f', str(ROOT / 'agent.conf')],
                   check=True, timeout=30)
    for fixture in fixtures:
        location, log, decoder = sample(fixture)
        expectation = f"{fixture['rule']}:{fixture['level']}:{decoder}"
        result = subprocess.run([binary, '-U', expectation, '-l', location], input=log + '\n',
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
        if result.returncode:
            raise AssertionError(f"{fixture['name']}: expected {expectation}\n{result.stdout}")
        print(f"PASS: {fixture['name']}")
    # Correlation is tested in one sandbox session, using synthetic documentation-range IPs.
    auth = next(f for f in fixtures if f['name'] == 'authentication failed')
    location, log, _ = sample(auth)
    burst = subprocess.run([binary, '-v', '-l', location], input=(log + '\n') * 12,
                           text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
    assert burst.returncode == 0, burst.stdout
    assert re.search(r"\bid:\s*'111925'", burst.stdout), 'Auth burst correlation did not fire: ' + burst.stdout
    print('PASS: repeated same-source authentication failure correlation; no production alerts injected.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manager-tests', action='store_true')
    args = parser.parse_args()
    fixtures = json.loads((ROOT / 'fixtures.json').read_text(encoding='utf-8'))
    static_checks(fixtures)
    if args.manager_tests:
        manager_tests(fixtures)
