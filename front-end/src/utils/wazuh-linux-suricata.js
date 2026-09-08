'use strict';

const SURICATA_WARNINGS = Object.freeze({
  'suricata-preflight-failed': 'The Linux network sensor could not complete its initial checks.',
  'suricata-unsupported-distribution': 'Automatic Suricata setup currently supports Debian, Ubuntu and Kali Linux.',
  'suricata-unsupported-version': 'Automatic setup expects Suricata 6.x, 7.x or 8.x configuration formats.',
  'suricata-unsafe-path': 'A sensor path has unexpected ownership, permissions or a symbolic link.',
  'suricata-unmanaged-configuration': 'Existing sensor files need administrator review before automatic setup.',
  'suricata-unmanaged-installation': 'An existing Suricata installation was preserved; configure its Wazuh collection manually.',
  'suricata-interface-unavailable': 'No suitable IPv4 interface and connected subnet were found for the sensor.',
  'suricata-interface-ambiguous': 'Multiple default-route interfaces need an administrator to select the sensor interface.',
  'suricata-package-install-failed': 'Suricata packages could not be installed from the configured distribution repositories.',
  'suricata-dependency-unavailable': 'A required Suricata package or helper is unavailable.',
  'suricata-configuration-unavailable': 'The distribution Suricata configuration is missing or invalid.',
  'suricata-configuration-failed': 'The managed Suricata configuration could not be written.',
  'suricata-rule-update-failed': 'ET Open rules could not be downloaded or prepared; check repository connectivity.',
  'suricata-configuration-test-failed': 'Suricata rejected the sensor configuration or detection rules.',
  'suricata-service-start-failed': 'The sensor or log-rotation timer did not start successfully.',
  'suricata-eve-unavailable': 'The sensor has not created its expected EVE JSON log.',
  'suricata-collector-conflict': 'An existing Wazuh log collector conflicts with the sensor JSON source.',
  'suricata-rollback-failed': 'The previous sensor configuration could not be fully restored; inspect the guest service.',
});

// Dedicated passive sensor; distro configuration and unrelated services stay owned
// by their administrator. Primary references:
// https://docs.suricata.io/en/suricata-7.0.15/quickstart.html
// https://suricata-update.readthedocs.io/en/latest/update.html
// https://docs.suricata.io/en/suricata-8.0.3/output/log-rotation.html
// https://github.com/OISF/suricata/blob/suricata-7.0.15/suricata.yaml.in
function buildLinuxSuricataFunctions() {
  return String.raw`
import fnmatch
import ipaddress
import json

SURICATA_CONFIG_DIR = Path('/etc/cybercore-suricata')
SURICATA_DATA_DIR = Path('/var/lib/cybercore-suricata')
SURICATA_LOG_DIR = Path('/var/log/cybercore-suricata')
SURICATA_UNIT_DIR = Path('/etc/systemd/system')
SURICATA_RUNTIME_DIR = Path('/run/systemd/system')
SURICATA_DISTRO_CONFIG = Path('/etc/suricata/suricata.yaml')
SURICATA_OWNER = '# Managed by CyberCore Suricata v1\n'
SURICATA_SERVICE = 'cybercore-suricata.service'
SURICATA_RESULT = {'complete': False, 'warnings': []}

class SuricataSetupError(Exception):
    pass

def _suri_require(condition, code):
    if not condition:
        raise SuricataSetupError(code)

def _suri_safe(path, directory=False):
    path = Path(path)
    for item in (path,) + tuple(path.parents):
        _suri_require(not item.is_symlink(), 'suricata-unsafe-path')
    if path.exists():
        info = path.stat()
        _suri_require((path.is_dir() if directory else path.is_file()) and info.st_uid == 0
                      and not (stat.S_IMODE(info.st_mode) & 0o022), 'suricata-unsafe-path')
    return path

def _suri_directory(path):
    _suri_safe(path, directory=True)
    path.mkdir(mode=0o750, parents=False, exist_ok=True)

def _suri_write(path, content, mode=0o600, owned=True):
    _suri_safe(path)
    _suri_safe(path.parent, directory=True)
    if owned and path.exists():
        _suri_require(path.read_text(encoding='utf-8').startswith(SURICATA_OWNER), 'suricata-unmanaged-configuration')
    handle, staging = tempfile.mkstemp(prefix='.cybercore-', dir=str(path.parent))
    try:
        with os.fdopen(handle, 'w', encoding='utf-8') as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(staging, mode)
        os.replace(staging, str(path))
    finally:
        if os.path.exists(staging):
            os.unlink(staging)

def _suri_run(args, timeout=60, env=None):
    # Output is never returned to the web application or included in warnings.
    return run(args, timeout=timeout, env=env)

def _suri_active(service):
    try:
        _suri_run(['systemctl', 'is-active', '--quiet', service], timeout=15)
        return True
    except subprocess.CalledProcessError:
        return False

def _suri_unmanaged_process(owned):
    for process in Path('/proc').glob('[0-9]*'):
        try:
            # Suricata 7 names its main thread Suricata-Main (src/suricata.c).
            if process.joinpath('comm').read_text().strip().lower() not in ('suricata', 'suricata-main'):
                continue
            cgroup = process.joinpath('cgroup').read_text()
            if not owned or not any(line.endswith('/' + SURICATA_SERVICE) for line in cgroup.splitlines()):
                return True
        except FileNotFoundError:
            continue
    return False

def _suri_interface():
    routes = json.loads(_suri_run(['ip', '-j', '-4', 'route', 'show', 'default'], timeout=15).stdout)
    routes = [route for route in routes if route.get('dev') and route.get('type', 'unicast') == 'unicast']
    _suri_require(routes, 'suricata-interface-unavailable')
    metric = min(int(route.get('metric', 0)) for route in routes)
    interfaces = set(route['dev'] for route in routes if int(route.get('metric', 0)) == metric)
    _suri_require(len(interfaces) == 1, 'suricata-interface-ambiguous')
    interface = interfaces.pop()
    _suri_require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,14}', interface) and interface != 'lo',
                  'suricata-interface-unavailable')
    addresses = json.loads(_suri_run(['ip', '-j', '-4', 'address', 'show', 'dev', interface], timeout=15).stdout)
    networks = set()
    for item in addresses:
        for address in item.get('addr_info', []):
            if address.get('family') == 'inet' and address.get('scope') == 'global':
                network = ipaddress.ip_network(str(address['local']) + '/' + str(address['prefixlen']), strict=False)
                _suri_require(network.version == 4 and network.prefixlen > 0, 'suricata-interface-unavailable')
                networks.add(str(network))
    _suri_require(networks, 'suricata-interface-unavailable')
    return interface, sorted(networks)

def _suri_install_packages():
    # Runtime masking prevents the newly installed distro unit starting with its
    # default interface. Only a mask created here is removed in the finally block.
    mask = SURICATA_RUNTIME_DIR / 'suricata.service'
    _suri_require(not mask.exists() and not mask.is_symlink(), 'suricata-unmanaged-configuration')
    _suri_safe(mask.parent, directory=True)
    environment = {key: value for key, value in os.environ.items() if not key.startswith(('WAZUH_', 'OSSEC_'))}
    environment['DEBIAN_FRONTEND'] = 'noninteractive'
    masked = False
    try:
        _suri_run(['systemctl', 'mask', '--runtime', 'suricata.service'])
        masked = True
        _suri_run(['apt-get', '-o', 'Acquire::Retries=1', '-o', 'Acquire::http::Timeout=30',
                   '-o', 'Acquire::https::Timeout=30', 'update'], timeout=180, env=environment)
        _suri_run(['apt-get', '-y', '--no-remove', '--no-install-recommends',
                   '-o', 'APT::Get::AllowUnauthenticated=false', 'install',
                   'suricata', 'suricata-update', 'python3-yaml', 'logrotate', 'iproute2'], timeout=300, env=environment)
    finally:
        if masked:
            try:
                # This unit belonged to the fresh package, never a preexisting sensor.
                _suri_run(['systemctl', 'disable', 'suricata.service'])
            finally:
                _suri_run(['systemctl', 'unmask', '--runtime', 'suricata.service'])

def _suri_configure_yaml(interface, networks):
    import yaml
    _suri_safe(SURICATA_DISTRO_CONFIG)
    _suri_require(SURICATA_DISTRO_CONFIG.is_file() and SURICATA_DISTRO_CONFIG.stat().st_size < 1024 * 1024,
                  'suricata-configuration-unavailable')
    config = yaml.safe_load(SURICATA_DISTRO_CONFIG.read_text(encoding='utf-8'))
    _suri_require(isinstance(config, dict), 'suricata-configuration-unavailable')
    # Never carry includes/plugins or privileged/custom capture commands into the
    # managed copy. Leave the original distro configuration untouched.
    for key in ('include', 'includes', 'plugins', 'run-as', 'pcap', 'af-xdp', 'dpdk', 'netmap', 'nfq', 'nflog'):
        config.pop(key, None)
    config.setdefault('vars', {}).setdefault('address-groups', {})['HOME_NET'] = '[' + ','.join(networks) + ']'
    # Include same-lane lateral activity in rules matching EXTERNAL_NET -> HOME_NET.
    # This passive lab profile accepts the additional noise; it never blocks traffic.
    config['vars']['address-groups']['EXTERNAL_NET'] = 'any'
    config['default-log-dir'] = str(SURICATA_LOG_DIR)
    config['default-rule-path'] = str(SURICATA_DATA_DIR / 'rules')
    config['rule-files'] = ['suricata.rules']
    config['runmode'] = 'workers'
    config['max-pending-packets'] = 1024
    config['af-packet'] = [{'interface': interface, 'threads': 2, 'cluster-id': 97,
                            'cluster-type': 'cluster_flow', 'defrag': True, 'use-mmap': True,
                            # Accept mirrored frames delivered to this NIC. This
                            # does not configure mirroring or enable inline mode.
                            'tpacket-v3': True, 'disable-promisc': False}]
    config['stats'] = {'enabled': True, 'interval': 60}
    config['unix-command'] = {'enabled': False}
    config['outputs'] = [{'eve-log': {'enabled': True, 'filetype': 'regular', 'filename': 'eve.json',
        'threaded': False, 'community-id': True, 'types': [
            {'alert': {'payload': False, 'payload-printable': False, 'packet': False,
                       'http-body': False, 'http-body-printable': False, 'tagged-packets': False,
                       'metadata': False}},
            {'stats': {'totals': True, 'threads': False}},
            {'dns': {'requests': True, 'responses': True, 'types': ['a', 'aaaa', 'cname', 'mx', 'ns', 'ptr']}},
            {'tls': {'extended': False}}, 'flow']}}]
    config['logging'] = {'default-log-level': 'notice', 'outputs': [{'console': {'enabled': True}}]}
    config.setdefault('flow', {})['memcap'] = '64mb'
    config.setdefault('stream', {})['memcap'] = '64mb'
    config['stream'].setdefault('reassembly', {})['memcap'] = '128mb'
    return SURICATA_OWNER + '%YAML 1.1\n---\n' + yaml.safe_dump(config, sort_keys=False)

def _suri_units(binary):
    config_path = str(SURICATA_CONFIG_DIR / 'suricata.yaml')
    sensor = SURICATA_OWNER + '''[Unit]
Description=CyberCore passive Suricata endpoint sensor
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=120
StartLimitBurst=3

[Service]
Type=simple
ExecStart=''' + binary + ' --af-packet -c ' + config_path + '''
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=10
TimeoutStopSec=60
UMask=0027
Nice=10
CPUQuota=150%
MemoryHigh=512M
MemoryMax=1G
NoNewPrivileges=true
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=''' + str(SURICATA_LOG_DIR) + ' ' + str(SURICATA_DATA_DIR) + '''

[Install]
WantedBy=multi-user.target
'''
    rotation = SURICATA_OWNER + str(SURICATA_LOG_DIR / 'eve.json') + ''' {
    daily
    maxsize 50M
    rotate 3
    missingok
    notifempty
    nocompress
    create 0640 root root
    sharedscripts
    postrotate
        /bin/systemctl kill --kill-who=main --signal=HUP cybercore-suricata.service >/dev/null 2>&1 || true
    endscript
}
'''
    rotate_service = SURICATA_OWNER + '''[Unit]
Description=Rotate CyberCore Suricata metadata logs

[Service]
Type=oneshot
ExecStart=/usr/sbin/logrotate --state ''' + str(SURICATA_DATA_DIR / 'logrotate.state') + ' ' + str(SURICATA_CONFIG_DIR / 'logrotate.conf') + '''
'''
    rotate_timer = SURICATA_OWNER + '''[Unit]
Description=Check CyberCore Suricata log size every minute

[Timer]
OnBootSec=1min
OnUnitActiveSec=1min
AccuracySec=10s

[Install]
WantedBy=timers.target
'''
    return {
        SURICATA_CONFIG_DIR / 'logrotate.conf': rotation,
        SURICATA_UNIT_DIR / SURICATA_SERVICE: sensor,
        SURICATA_UNIT_DIR / 'cybercore-suricata-logrotate.service': rotate_service,
        SURICATA_UNIT_DIR / 'cybercore-suricata-logrotate.timer': rotate_timer,
    }

def _suri_backup(paths, directory):
    backups = []
    for number, location in enumerate(paths):
        _suri_safe(location)
        backup = Path(directory) / str(number)
        if location.exists():
            shutil.copy2(str(location), str(backup))
            backups.append((location, backup))
        else:
            backups.append((location, None))
    return backups

def _suri_restore(backups):
    for location, backup in backups:
        _suri_safe(location)
        if backup is None:
            if location.exists():
                location.unlink()
            continue
        handle, staging = tempfile.mkstemp(prefix='.cybercore-restore-', dir=str(location.parent))
        os.close(handle)
        try:
            shutil.copy2(str(backup), staging)
            os.replace(staging, str(location))
        finally:
            if os.path.exists(staging):
                os.unlink(staging)

def configure_suricata():
    global SURICATA_RESULT
    SURICATA_RESULT = {'complete': False, 'warnings': []}
    stage = 'suricata-preflight-failed'
    backups = []
    backup_directory = None
    service_attempted = False
    previously_active = False
    try:
        release = Path('/etc/os-release').read_text(encoding='utf-8')
        distro = re.search(r'^ID=["\x27]?([a-z0-9_-]+)', release, re.M)
        _suri_require(distro and distro.group(1) in ('debian', 'ubuntu', 'kali') and shutil.which('apt-get'),
                      'suricata-unsupported-distribution')
        marker = SURICATA_CONFIG_DIR / 'managed'
        _suri_safe(SURICATA_CONFIG_DIR, directory=True)
        _suri_safe(marker)
        owned = marker.is_file() and marker.read_text(encoding='utf-8') == SURICATA_OWNER
        _suri_require(owned or not SURICATA_CONFIG_DIR.exists(), 'suricata-unmanaged-configuration')
        _suri_require(not _suri_active('suricata.service') and not _suri_unmanaged_process(owned),
                      'suricata-unmanaged-installation')
        previously_active = owned and _suri_active(SURICATA_SERVICE)
        if not owned:
            _suri_require(not shutil.which('suricata') and not SURICATA_DISTRO_CONFIG.parent.exists(),
                          'suricata-unmanaged-installation')
            for location in (SURICATA_DATA_DIR, SURICATA_LOG_DIR):
                _suri_require(not location.exists() and not location.is_symlink(), 'suricata-unmanaged-configuration')
            for filename in (SURICATA_SERVICE, 'cybercore-suricata-logrotate.service', 'cybercore-suricata-logrotate.timer'):
                location = SURICATA_UNIT_DIR / filename
                _suri_require(not location.exists() and not location.is_symlink(), 'suricata-unmanaged-configuration')
        # Resolve the sensor boundary before package or configuration changes.
        interface, networks = _suri_interface()
        _suri_directory(SURICATA_CONFIG_DIR)
        _suri_write(marker, SURICATA_OWNER)
        try:
            import yaml
            has_yaml = True
        except ImportError:
            has_yaml = False
        if not all(shutil.which(command) for command in ('suricata', 'suricata-update', 'logrotate')) or not has_yaml:
            stage = 'suricata-package-install-failed'
            _suri_install_packages()
        stage = 'suricata-dependency-unavailable'
        binary = shutil.which('suricata')
        updater = shutil.which('suricata-update')
        _suri_require(binary and updater and Path('/usr/sbin/logrotate').is_file(), stage)
        _suri_require(re.fullmatch(r'/[A-Za-z0-9_./-]+', binary) and re.fullmatch(r'/[A-Za-z0-9_./-]+', updater), stage)
        version = _suri_run([binary, '-V'], timeout=15).stdout.decode('utf-8', errors='replace')
        _suri_require(re.search(r'\b(?:6|7|8)\.\d+\.\d+', version), 'suricata-unsupported-version')
        for location in (SURICATA_DATA_DIR, SURICATA_LOG_DIR, SURICATA_DATA_DIR / 'rules'):
            _suri_directory(location)
        _suri_safe(SURICATA_LOG_DIR / 'eve.json')
        stage = 'suricata-configuration-failed'
        config_path = SURICATA_CONFIG_DIR / 'suricata.yaml'
        update_path = SURICATA_CONFIG_DIR / 'update.yaml'
        rules = SURICATA_DATA_DIR / 'rules/suricata.rules'
        units = _suri_units(binary)
        backup_directory = tempfile.TemporaryDirectory(prefix='.setup-', dir=str(SURICATA_DATA_DIR))
        backups = _suri_backup([config_path, update_path, rules] + list(units), backup_directory.name)
        config_text = _suri_configure_yaml(interface, networks)
        _suri_write(config_path, config_text)
        _suri_write(update_path, SURICATA_OWNER + 'sources:\n  - https://rules.emergingthreats.net/open/suricata-%(__version__)s/emerging.rules.tar.gz\n')
        stage = 'suricata-rule-update-failed'
        _suri_run([updater, '--config', str(update_path), '--data-dir', str(SURICATA_DATA_DIR),
                   '--suricata-conf', str(config_path), '--output', str(SURICATA_DATA_DIR / 'rules'),
                   '--no-reload', '--no-test'], timeout=240)
        _suri_safe(rules)
        _suri_require(rules.is_file() and rules.stat().st_size > 0, stage)
        stage = 'suricata-configuration-test-failed'
        _suri_run([binary, '-T', '-c', str(config_path), '-l', str(SURICATA_LOG_DIR)], timeout=120)
        for location, content in units.items():
            _suri_write(location, content, mode=0o644 if location.parent == SURICATA_UNIT_DIR else 0o600)
        stage = 'suricata-service-start-failed'
        _suri_run(['systemctl', 'daemon-reload'])
        service_attempted = True
        _suri_run(['systemctl', 'enable', SURICATA_SERVICE, 'cybercore-suricata-logrotate.timer'])
        _suri_run(['systemctl', 'restart', SURICATA_SERVICE], timeout=120)
        _suri_run(['systemctl', 'start', 'cybercore-suricata-logrotate.timer'])
        time.sleep(2)
        _suri_require(_suri_active(SURICATA_SERVICE) and _suri_active('cybercore-suricata-logrotate.timer'), stage)
        _suri_safe(SURICATA_LOG_DIR / 'eve.json')
        _suri_require((SURICATA_LOG_DIR / 'eve.json').is_file(), 'suricata-eve-unavailable')
        SURICATA_RESULT['complete'] = True
    except Exception as error:
        code = str(error) if isinstance(error, SuricataSetupError) else stage
        SURICATA_RESULT['warnings'].append(code)
        try:
            if service_attempted and not previously_active:
                _suri_run(['systemctl', 'stop', SURICATA_SERVICE, 'cybercore-suricata-logrotate.timer'])
                _suri_run(['systemctl', 'disable', SURICATA_SERVICE, 'cybercore-suricata-logrotate.timer'])
            if backups:
                _suri_restore(backups)
                _suri_run(['systemctl', 'daemon-reload'])
            if service_attempted and previously_active:
                _suri_run(['systemctl', 'restart', SURICATA_SERVICE], timeout=120)
        except Exception:
            SURICATA_RESULT['warnings'].append('suricata-rollback-failed')
    finally:
        if backup_directory is not None:
            try:
                backup_directory.cleanup()
            except Exception:
                SURICATA_RESULT['complete'] = False
                if 'suricata-rollback-failed' not in SURICATA_RESULT['warnings']:
                    SURICATA_RESULT['warnings'].append('suricata-rollback-failed')
    return SURICATA_RESULT

def add_suricata_collector(document):
    if not SURICATA_RESULT['complete']:
        return False
    location = str(SURICATA_LOG_DIR / 'eve.json')
    def text(node):
        return ''.join(item.data for item in node.childNodes if item.nodeType == item.TEXT_NODE).strip()
    for collector in document.getElementsByTagName('localfile'):
        locations = collector.getElementsByTagName('location')
        if any(fnmatch.fnmatchcase(location, text(item)) for item in locations):
            formats = collector.getElementsByTagName('log_format')
            if len(formats) == 1 and text(formats[0]) == 'json':
                return True
            SURICATA_RESULT['complete'] = False
            SURICATA_RESULT['warnings'].append('suricata-collector-conflict')
            return False
    roots = document.getElementsByTagName('ossec_config')
    if not roots:
        SURICATA_RESULT['complete'] = False
        SURICATA_RESULT['warnings'].append('suricata-collector-conflict')
        return False
    collector = document.createElement('localfile')
    roots[0].appendChild(collector)
    for tag, value in (('log_format', 'json'), ('location', location)):
        node = document.createElement(tag)
        node.appendChild(document.createTextNode(value))
        collector.appendChild(node)
    return True
`;
}

module.exports = { buildLinuxSuricataFunctions, SURICATA_WARNINGS };
