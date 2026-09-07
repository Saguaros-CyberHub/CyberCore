const { posix } = require('node:path');

const quote = value => `'${value.replace(/'/g, `'\\''`)}'`;

/** Publish completion only after the controller's playbook log has been flushed. */
function buildGoadPlaybookLaunch({ logPath, donePath, argv }) {
  if (!Array.isArray(argv) || !argv.length
    || [logPath, donePath, ...argv].some(value => typeof value !== 'string' || value.includes('\0'))
    || !logPath || !donePath || !argv[0] || logPath === donePath) {
    throw new TypeError('Invalid GOAD playbook launch paths or arguments');
  }
  const log = quote(logPath);
  const done = quote(donePath);
  const script = [
    'umask 077',
    `${argv.map(quote).join(' ')} > ${log} 2>&1`,
    'run_rc=$?',
    // Preserve Ansible's failure code; a successful run with an unflushed log
    // must also fail. Nothing containing playbook arguments reaches stderr.
    `if ! sync -f ${log}; then [ "$run_rc" -ne 0 ] || run_rc=125; fi`,
    `done_tmp=${quote(`${donePath}.tmp.`)}$$`,
    `trap 'rm -f -- "$done_tmp"' 0`,
    `printf '%s\\n' "$run_rc" > "$done_tmp" && sync -f "$done_tmp" && mv -f -- "$done_tmp" ${done} && sync -f ${quote(posix.dirname(donePath))} || exit 125`,
    'exit "$run_rc"',
  ].join('\n');
  return [
    "for tool in nohup setsid sync mv; do command -v \"$tool\" >/dev/null 2>&1 || { printf '%s\\n' 'GOAD launcher tools unavailable' >&2; exit 125; }; done",
    `rm -f -- ${done} || { printf '%s\\n' 'GOAD completion status could not be cleared' >&2; exit 125; }`,
    // One shell quoting layer protects literal quotes, $, backticks and newlines
    // in credentials and arguments from the shell that launches this wrapper.
    `nohup setsid /bin/sh -c ${quote(script)} </dev/null >/dev/null 2>&1 &`,
  ].join('\n');
}

module.exports = { buildGoadPlaybookLaunch };
