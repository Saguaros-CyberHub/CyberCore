#!/usr/bin/env python3
"""Validate this pack; optionally exercise the installed Wazuh rules in logtest only.

No network, package installation, configuration writes, or real alert injection.
Run: python3 verify.py [--manager-tests]
Manager mode requires the pack's rules and decoder installed under etc/rules
and etc/decoders respectively.
"""
import argparse
from decimal import Decimal
import ipaddress
import json
from pathlib import Path
import re
import subprocess
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent
APP_LOCATION = '(250-CyberCore) any->/home/cactus-admin/CyberCore/logs/security-2026-09-07.jsonl'
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
    return fixture.get('location', APP_LOCATION), json.dumps(event, separators=(',', ':')), 'json'


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
            assert all(int(n) in indexed or int(n) in {504, 87702} for n in re.split(r'[,\s]+', ref.text))
        if int(rule.attrib['id']) >= 111920 and int(rule.attrib['level']) > 0:
            assert 'no_full_log' in [option.text for option in rule.findall('options')]
    names = [f['name'] for f in fixtures]
    assert len(names) == len(set(names))
    for fixture in fixtures:
        _, log, _ = sample(fixture)
        assert '\n' not in log
        assert 1 <= fixture.get('repeat', 1) <= 54
        assert all('\n' not in line for line in fixture.get('prefix_logs', []))
        if 'event' in fixture:
            assert 'event_type' not in fixture['event'], 'Reserved Suricata discriminator must not appear.'
            assert fixture['event']['cybercore_event'] in {'audit', 'http', 'health'}
        expected_rule = fixture.get('rule')
        if expected_rule in indexed:
            assert int(indexed[expected_rule].attrib['level']) == fixture['level']
    boundary = indexed[111901]
    assert boundary.findtext('if_sid') == '87702'
    assert boundary.findtext('location') == r'^100\.100\.20\.1$'
    assert boundary.findtext('srcip') == '100.100.60.0/22'
    assert [n.text for n in boundary.findall('dstip')] == ['100.100.10.0/24', '100.100.20.10/32']
    assert boundary.find('if_matched_sid') is None
    assert 'frequency' not in boundary.attrib and boundary.attrib['ignore'] == '240'
    for ip in boundary.findall('srcip') + boundary.findall('dstip'):
        ipaddress.ip_network(ip.text, strict=True)
    app_location = re.compile(indexed[111920].findtext('location'))
    assert app_location.fullmatch(APP_LOCATION)
    assert not app_location.fullmatch(APP_LOCATION.split('->', 1)[1])
    assert not app_location.fullmatch(APP_LOCATION.replace('250-CyberCore', 'student-vm'))
    decoder_root = wrapped_xml('cybercore-infrastructure-decoders.xml')
    assert len(decoder_root) == 1
    decoder = decoder_root[0]
    assert decoder.tag == 'decoder' and decoder.attrib == {'name': 'json'}
    assert [node.tag for node in decoder] == ['program_name', 'prematch', 'plugin_decoder']
    program = decoder.find('program_name')
    assert program.attrib == {'type': 'pcre2'} and program.text == '^suricata$'
    assert re.fullmatch(program.text, 'suricata')
    assert not any(re.search(program.text, other) for other in ['not-suricata', 'suricata-other', 'sshd', 'cybercore'])
    prematch = decoder.find('prematch')
    assert prematch.attrib == {'type': 'pcre2'}
    assert re.search(prematch.text, '{"event_type":"alert"}')
    assert not re.search(prematch.text, 'engine started')
    assert decoder.findtext('plugin_decoder') == 'JSON_Decoder'
    assert decoder.find('plugin_decoder').attrib == {}
    print(f'PASS: 3 scoped profiles, {len(rules)} additive rules, 1 scoped decoder, {len(fixtures)} fixtures; static safety checks.')


def manager_tests(fixtures):
    binary = '/var/ossec/bin/wazuh-logtest'
    assert Path(binary).is_file(), 'Run --manager-tests on the Wazuh manager after staging the rules.'
    subprocess.run(['/var/ossec/bin/verify-agent-conf', '-f', str(ROOT / 'agent.conf')],
                   check=True, timeout=30)
    for fixture in fixtures:
        location, log, decoder = sample(fixture)
        reject_local = fixture.get('reject_local_rules', False)
        negative = reject_local or fixture.get('reject_rules') or fixture.get('reject_decoders')
        expectation = 'no prohibited rule/decoder' if negative else f"{fixture['rule']}:{fixture['level']}:{decoder}"
        logs = fixture.get('prefix_logs', []) + [log] * fixture.get('repeat', 1)
        command = [binary, '-l', location]
        if len(logs) == 1 and not negative:
            command += ['-U', expectation]
        result = subprocess.run(command, input='\n'.join(logs) + '\n',
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
        if result.returncode:
            raise AssertionError(f"{fixture['name']}: expected {expectation}\n{result.stdout}")
        if reject_local:
            assert not re.search(r"\bid:\s*'1119[0-3][0-9]'", result.stdout), f"{fixture['name']}: untrusted location matched a local rule\n{result.stdout}"
        for forbidden in fixture.get('reject_rules', []):
            assert not re.search(r"\bid:\s*'" + str(forbidden) + "'", result.stdout), f"{fixture['name']}: prohibited rule {forbidden}"
        for forbidden in fixture.get('reject_decoders', []):
            assert not re.search(r"\bname:\s*'" + re.escape(forbidden) + "'", result.stdout), f"{fixture['name']}: prohibited decoder {forbidden}"
        if 'expected_signature_id' in fixture:
            signature = re.search(r"alert\.signature_id:\s*'([^']+)'", result.stdout)
            assert signature and Decimal(signature.group(1)) == fixture['expected_signature_id'], f"{fixture['name']}: signature ID not preserved"
        if len(logs) > 1:
            # Phase 3 reports the MATCHED rule, even when its ignore timer would suppress
            # emission. Upstream logtest sets generated_rule before checking ignore_time.
            # Verify counter/matching behavior here; emitted-alert suppression needs a live test.
            phases = result.stdout.split('**Phase 1:')[1:]
            assert len(phases) == len(logs), f"{fixture['name']}: missing per-event results\n{result.stdout}"
            filtered = []
            for phase in phases:
                match = re.search(r"\*\*Phase 3:[\s\S]*?\bid:\s*'([0-9]+)'\s+level:\s*'([0-9]+)'", phase)
                filtered.append(match.groups() if match else None)
            matches = [n for n, item in enumerate(filtered, 1)
                       if item == (str(fixture['rule']), str(fixture['level']))]
            assert len(matches) == fixture['expected_count'], f"{fixture['name']}: unexpected escalation count {matches}"
            assert matches[0] == fixture['expected_first_position'], f"{fixture['name']}: counter changed {matches}"
            if 'expected_positions' in fixture:
                assert matches == fixture['expected_positions'], f"{fixture['name']}: counter positions changed {matches}"
            assert all(item is None or int(item[0]) in {fixture['rule'], fixture['remainder_rule']}
                       for item in filtered), f"{fixture['name']}: unexpected rule chain {filtered}"
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
