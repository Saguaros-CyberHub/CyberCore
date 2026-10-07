"""Renders the bake's cloud-init user-data and parses it as YAML.

`bash -n` validates the shell AROUND the heredocs and sees nothing inside them,
so an indentation slip in a `content: |` block passes every check in the repo and
then fails at bake time as "bake did not complete" forty minutes later, with
nothing pointing at the cause. That happened once: a tidy-up collapsed
`      ExecStart=` to ` ExecStart=`, which ends the block scalar early and makes
the whole document unparseable, so cloud-init ran nothing at all.

Run before every bake:

    python scripts/check-bake-userdata.py

front-end/test/bake-payloads.test.js carries a narrower version of the same
check in JS, so the suite catches it without needing Python or PyYAML.
"""
import io
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
BAKE = os.path.join(ROOT, 'infrastructure', 'proxmox-templates', 'vm-templates',
                    'bake-cybr400-loggen-template.sh')

try:
    import yaml
except ImportError:
    print('This needs PyYAML:  pip install pyyaml')
    print('(the JS guard in front-end/test/bake-payloads.test.js needs nothing.)')
    sys.exit(2)

if not os.path.exists(BAKE):
    print('bake script not found at %s' % BAKE)
    sys.exit(2)

src = io.open(BAKE, encoding='utf-8', newline='').read().replace('\r\n', '\n')

# The two CLOUDINIT heredocs, concatenated the way the script writes them.
blocks = re.findall(r'<<CLOUDINIT\n(.*?)\nCLOUDINIT\n', src, re.S)
if len(blocks) != 2:
    print('expected 2 CLOUDINIT heredocs, found %d' % len(blocks))
    sys.exit(1)

doc = blocks[0] + '\n' + blocks[1]

# Stand-ins for the shell expansions. Base64 payloads collapse to a short token
# so the document stays readable if it has to be dumped.
doc = re.sub(r'\$\{(CC_EMIT_B64|HOST_PB_B64|LOGGEN_TUNE_B64|LOGGEN_ROTATE_B64)\}', 'QkFTRTY0', doc)
doc = re.sub(r'\$\{[A-Za-z_][A-Za-z0-9_]*\}', 'X', doc)
doc = doc.replace('\\$', '$')

try:
    parsed = yaml.safe_load(doc)
except yaml.YAMLError as err:
    print('USER-DATA IS NOT VALID YAML -- cloud-init would run NOTHING')
    print(err)
    sys.exit(1)

files = {f['path']: f for f in parsed.get('write_files', [])}
print('user-data parses. %d write_files, %d runcmd entries.'
      % (len(files), len(parsed.get('runcmd', []))))

fail = 0
for p in ['/etc/sysconfig/qemu-ga', '/etc/elastic-agent/elastic-agent.yml',
          '/opt/cybercore/cc-emit.js', '/opt/cybercore/host-baseline.json',
          '/etc/systemd/system/cc-hostbase.service',
          '/etc/systemd/system/loggen-baseline.service',
          '/etc/systemd/system/loggen-rotate.service',
          '/etc/systemd/system/loggen-rotate.timer',
          '/opt/cybercore/loggen-tune.sh', '/opt/cybercore/loggen-rotate.sh',
          '/etc/ssh/sshd_config.d/00-cybercore.conf']:
    if p not in files:
        print('  MISSING write_files entry: %s' % p)
        fail = 1

# A truncated block scalar leaves a unit file that is still syntactically fine
# and simply missing its ExecStart -- which systemd reports only when the
# service is first started, on a student's lane rather than during the bake.
for p, f in sorted(files.items()):
    if not p.endswith(('.service', '.timer')):
        continue
    body = f.get('content', '')
    need = ['[Timer]', '[Install]', 'WantedBy='] if p.endswith('.timer') else ['[Service]', 'ExecStart=']
    if p.endswith('.service') and 'oneshot' not in body:
        need.append('[Install]')
    for k in need:
        if k not in body:
            print('  %s has no %s -- the block was truncated' % (p, k))
            fail = 1

svc = files.get('/etc/systemd/system/cc-hostbase.service', {}).get('content', '')
if '--daemon' not in svc or 'host-baseline.json' not in svc:
    print('  cc-hostbase.service does not launch the emitter')
    fail = 1

# Declarations only. The surrounding comments explain why the order matters and
# naturally mention both processors by name, so counting bare occurrences counts
# the prose too.
agent = files.get('/etc/elastic-agent/elastic-agent.yml', {}).get('content', '')
decls = [(i, ln.strip()) for i, ln in enumerate(agent.split('\n'))
         if re.match(r'^\s*- drop_(event|fields):\s*$', ln)]
events = [i for i, ln in decls if 'drop_event' in ln]
fields = [i for i, ln in decls if 'drop_fields' in ln]
# One drop_event (attack input only), and one drop_fields PER INPUT.
#
# The attack tree strips loggen.mitre and log.file.path; the baseline tree strips
# log.file.path. BOTH halves are required. Stripping the path from only the attack
# tree would leave its absence as the same oracle inverted: a NOT _exists_ query
# on log.file.path would then select precisely the attack events, which is no
# better than the direct match and considerably harder to notice.
if len(events) != 1 or len(fields) != 2:
    print('  expected one drop_event and two drop_fields processors, got %d and %d'
          % (len(events), len(fields)))
    fail = 1
else:
    # Order still decides whether the feature works at all: drop_event tests the
    # technique, so the drop_fields that removes it must come afterwards.
    if not [i for i in fields if i > events[0]]:
        print('  the attack input declares no drop_fields after drop_event -- the mitre')
        print('  label would ship stamped on every attack event, naming the answer')
        fail = 1
    if 'log.file.path' not in agent:
        print('  log.file.path is not dropped -- filestream stamps the source path on')
        print('  every document, so the two trees give it two values and the field')
        print('  list in Discover becomes a one-click answer key for every run')
        fail = 1

print('OK' if not fail else 'FAILED')
sys.exit(fail)
