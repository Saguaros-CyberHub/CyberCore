# WinDivert and Suricata on existing Windows VMs

Research verified on **2026-09-07** against the official Suricata **8.0.6**
packages, stable/development source, and WinDivert documentation. Inspection was
limited to package extraction, static imports/build strings, file hashes, and
Authenticode verification. No Suricata executable, installer action, or capture
driver was run or installed.

The requested architecture is **each existing Windows VM -> local Suricata EVE
JSON -> its existing Wazuh agent -> Wazuh**. It needs no additional sensor VM or
traffic mirror. WinDivert captures that endpoint's IP traffic; it does not give
one endpoint visibility into every other VM. Sysmon, PowerShell and Defender
remain complementary endpoint sources.

## Current package choices

| Option | What is available | Remaining consideration |
| --- | --- | --- |
| Ordinary Suricata 8.0.6 Windows MSI | WinDivert disabled; Npcap capture enabled | Uses the conventional Windows capture dependency |
| Separate Suricata 8.0.6 WinDivert MSI | Official current package; WinDivert enabled | Still imports `wpcap.dll`; bundled driver uses WinDivert 1.4.3 |
| Build Suricata with WinDivert and without Npcap support | Upstream build options permit selecting different libpcap dependencies | Requires a verified build/runtime package and endpoint compatibility testing |
| Existing Sysmon/Wazuh only | Endpoint connection and DNS events, plus security detections | Provides metadata, not Suricata packet inspection |

**Correction to the initial research:** the main download page links the ordinary
MSI, but the official Windows directory also publishes a separate current
WinDivert MSI and ZIP. A custom build is not inherently required to obtain
Suricata with WinDivert enabled. The ZIP inspected here contains the MSI, not a
portable directory of loose binaries. The main page labels 8.0.6 stable and
7.0.17 end-of-life. [Official releases](https://suricata.io/download/),
[all official Windows packages](https://www.openinfosecfoundation.org/download/windows/).

## Static inspection of both 8.0.6 packages

| Finding | Ordinary MSI | WinDivert MSI |
| --- | --- | --- |
| Filename | `Suricata-8.0.6-1-64bit.msi` | `Suricata-8.0.6-windivert-1-64bit.msi` |
| Size | 36,577,280 bytes | 36,683,776 bytes |
| Embedded WinDivert build flag | `no` | `yes` |
| Embedded Npcap build flag | `yes` | `yes` |
| Main executable imports `wpcap.dll` | Yes | Yes |
| Main executable imports `WinDivert.dll` | No | Yes |
| Package supplies `wpcap.dll` | No | No |

Observed SHA-256 hashes, identifying the inspected downloads:

```text
Ordinary MSI:
AC7E2DB129FCBC5136BC15E4A40BEFA6435253523780D5D4E97E3E7B172AB442
WinDivert MSI:
60F7D617DE2AD8938D98A25F86F42026E78EDDF665CE3A8059E253C753197574
```

These observed hashes are not separately published vendor checksums.
[Ordinary MSI](https://www.openinfosecfoundation.org/download/windows/Suricata-8.0.6-1-64bit.msi),
[WinDivert MSI](https://www.openinfosecfoundation.org/download/windows/Suricata-8.0.6-windivert-1-64bit.msi).

The WinDivert package's `suricata.exe` directly imports both capture libraries.
Inspection of every bundled DLL found no additional `wpcap.dll` import:
`WinDivert.dll` itself imports only `ADVAPI32.dll` and `KERNEL32.dll`. Thus the
pcap-runtime dependency comes from this Suricata build, not from WinDivert itself.
Windows must resolve that dependency even when selecting `--windivert` or asking
for `--build-info`. This does **not** prove the Npcap driver is used by WinDivert;
it means the official MSI is not yet a verified deployment without the external
pcap runtime. Do not assume copying a different DLL or renaming an unrelated
libpcap build produces a compatible runtime.

The MSI's Authenticode status was **Valid**, signed by Open Information Security
Foundation Inc. Its extracted executable and `WinDivert.dll` were individually
**NotSigned**. The bundled `WinDivert64.sys` was **Valid**, signed by Ars Nova
Systems, with resource version `1.4`. Both the DLL and driver matched the files
in the official **WinDivert 1.4.3-A** archive byte-for-byte. Signature verification
on this workstation does not establish driver acceptance under every target
Windows 11, Secure Boot, or memory-integrity configuration.
[Official matching WinDivert release](https://github.com/basil00/Divert/releases/tag/v1.4.3).

## Stable versus development compatibility

Suricata 8.0.6's WinDivert backend uses the 1.x API and its CI builds against
WinDivert 1.4.3-A. The `main-8.0.x` branch inspected on September 7 still did so.
Current development `main` has already been ported to the 2.x API and its CI uses
WinDivert **2.2.2-A**; the current development documentation identifies itself as
**9.0.0-dev**. This work should not be mistaken for a released 8.0.6 capability.
Do not replace the stable package's 1.4.3 DLL/driver with 2.2: the receive-call
argument order and address structure differ.
[Stable backend](https://github.com/OISF/suricata/blob/suricata-8.0.6/src/source-windivert.c),
[stable CI](https://github.com/OISF/suricata/blob/suricata-8.0.6/.github/workflows/builds.yml),
[development backend at the inspected commit](https://github.com/OISF/suricata/blob/928ac012156fb8d393ce5ac4a496fde3c2e87b00/src/source-windivert.c),
[development CI](https://github.com/OISF/suricata/blob/928ac012156fb8d393ce5ac4a496fde3c2e87b00/.github/workflows/builds.yml).

Both inspected backends set WinDivert flags to `0`: **inline processing**.
Packets selected by the filter enter Suricata's receive/verdict/reinjection
path. Using only alert rules avoids intentional rule-based blocking, but does
not turn this into passive packet copying. WinDivert itself supports a sniff
flag; the existing Suricata backend does not expose a passive switch. Changing
that flag alone without changing reinjection behavior can duplicate traffic.
[Stable Windows IPS guide](https://docs.suricata.io/en/suricata-8.0.6/ips/setting-up-ipsinline-for-windows.html),
[WinDivert API and flags](https://www.reqrypt.org/windivert-doc.html#divert_open).

## Bounded endpoint pilot path

1. Use the separate official WinDivert package, verifying its signature and
   complete DLL dependencies. If avoiding the Npcap runtime is mandatory,
   evaluate a build linked against the MSYS2 offline libpcap implementation
   while explicitly enabling WinDivert; do not declare that combination working
   before a Windows runtime test. Upstream documents the libpcap choice and
   WinDivert build flags, but that does not validate this exact deployment.
   [Stable Windows build guide](https://docs.suricata.io/en/suricata-8.0.6/install/windows.html),
   [development build guide](https://docs.suricata.io/en/latest/install/windows.html).
2. On one existing test VM, prepare a reviewed configuration, current detection
   rules, restricted log directory, and bounded EVE rotation. Begin with alert
   rules and no packet/body/file payload output. The commands below assume this
   preparation and a working WinDivert-enabled binary; they are not an installer.
3. Test configuration, then run an elevated foreground pilot. For endpoint
   traffic, use `--windivert`; `--windivert-forward` is for a Windows gateway.

```powershell
$suricata = 'C:\Program Files\Suricata\suricata.exe'
$config = 'C:\ProgramData\CyberCore\Suricata\suricata.yaml'
$logs = 'C:\ProgramData\CyberCore\Suricata'
& $suricata --build-info
& $suricata -T -c $config -l $logs
& $suricata -c $config -l $logs --windivert 'true'
```

`true` selects endpoint IP traffic in both directions. WinDivert loads its kernel
driver when opened and requires administrator privileges. A foreground pilot
must verify normal networking, DNS, agent reporting, expected benign detection,
service stop/restart behavior, and driver acceptance before any unattended
rollout. [Documented endpoint command](https://docs.suricata.io/en/suricata-8.0.6/ips/setting-up-ipsinline-for-windows.html),
[WinDivert driver loading](https://www.reqrypt.org/windivert-doc.html#installing).

Configure Suricata to write regular EVE JSON to `eve.json` in the log directory.
The existing Wazuh agent can collect it with the following localfile entry;
preserve unrelated collectors and confirm the actual file path:

```xml
<localfile>
  <log_format>json</log_format>
  <location>C:\ProgramData\CyberCore\Suricata\eve.json</location>
</localfile>
```

Wazuh's Suricata integration demonstrates JSON collection and decoding of EVE
alerts. Inspect a harmless test alert through the complete endpoint-to-index
path. EVE flow/DNS metadata is not automatically guaranteed to enter the default
Wazuh alert index merely because the file is collected.
[Wazuh Suricata integration](https://documentation.wazuh.com/current/proof-of-concept-guide/integrate-network-ids-suricata.html).

Before expanding to hundreds of VMs, measure added CPU/RAM, packet loss, network
latency, EVE volume and index growth during normal class activity. Define service
startup, rule updates, log rotation and retry/rollback behavior. These are
remaining deployment tasks, not capabilities installed by this research.
