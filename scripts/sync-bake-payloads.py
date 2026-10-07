"""Injects cc-emit.js and host-baseline.json into the bake script.

The bake runs standalone on a Proxmox node with no checkout, so both have to be
embedded. Generated between markers so a test can prove the copies match and
nobody has to remember to hand-sync them.
"""
import io, os, sys

ROOT = 'f:/Projects/CyberCore'
BAKE = ROOT + '/infrastructure/proxmox-templates/vm-templates/bake-cybr400-loggen-template.sh'
# E1 moved the engine out of the CLE plugin into shared core (src/incident/).
EMIT = ROOT + '/front-end/src/incident/cc-emit.js'
HOSTPB = ROOT + '/front-end/src/incident/playbooks/host-baseline.json'

BEGIN = '# ---- BEGIN GENERATED PAYLOADS (sync_bake.py) ----'
END = '# ---- END GENERATED PAYLOADS ----'

emit_src = io.open(EMIT, encoding='utf-8').read()
host_src = io.open(HOSTPB, encoding='utf-8').read()

for name, src in (('cc-emit.js', emit_src), ('host-baseline.json', host_src)):
    for term in ('CC_EMIT_EOF', 'HOST_PB_EOF'):
        assert not any(l.strip() == term for l in src.splitlines()), \
            '%s contains the heredoc terminator %s' % (name, term)

block = BEGIN + '''
# cc-emit.js and host-baseline.json, embedded verbatim.
#
# The bake runs on a Proxmox node with no checkout, so the engine cannot be read
# from the repo the way attack-runner.js reads cc-attack.sh. Quoted heredocs, so
# every $, backtick and backslash in the JavaScript survives untouched, then
# base64 into cloud-init exactly like the other helpers.
#
# GENERATED. Do not edit between these markers -- run scripts/sync-bake-payloads
# and let bake-payloads.test.js prove the copies still match.

EMIT_TMP="$(mktemp)"
cat > "$EMIT_TMP" <<'CC_EMIT_EOF'
''' + emit_src.rstrip('\n') + '''
CC_EMIT_EOF
CC_EMIT_B64="$(base64 -w0 "$EMIT_TMP")"
rm -f "$EMIT_TMP"

HOST_PB_TMP="$(mktemp)"
cat > "$HOST_PB_TMP" <<'HOST_PB_EOF'
''' + host_src.rstrip('\n') + '''
HOST_PB_EOF
HOST_PB_B64="$(base64 -w0 "$HOST_PB_TMP")"
rm -f "$HOST_PB_TMP"
''' + END

s = io.open(BAKE, encoding='utf-8').read()

if BEGIN in s:
    a = s.index(BEGIN)
    b = s.index(END) + len(END)
    s = s[:a] + block + s[b:]
    action = 'refreshed'
else:
    anchor = '# ---------- 1. cloud-init user-data ----------'
    assert anchor in s, 'anchor not found in bake script'
    s = s.replace(anchor, block + '\n\n' + anchor, 1)
    action = 'inserted'

io.open(BAKE, 'w', encoding='utf-8', newline='\n').write(s)
print('%s embedded payloads: cc-emit.js %d bytes, host-baseline.json %d bytes'
      % (action, len(emit_src), len(host_src)))
