# Windows network IDS options for CyberCore

Research verified on **2026-09-07** against Suricata **8.0.6**, its official
Windows MSI, and the upstream WinDivert documentation. No Suricata executable,
MSI installer action, or capture driver was run or installed during this review.

For this range, use endpoint Sysmon/PowerShell/Defender telemetry together with
a shared network sensor. A Linux Suricata sensor receiving mirrored lane traffic
gives packet visibility without installing a Windows capture driver on every
student VM. OPNsense IDS is a useful first source for traffic that crosses it;
it does not observe traffic that stays inside a lane's virtual switch.

## Options compared

| Option | Npcap needed on student Windows VMs? | Visibility | Practical assessment |
| --- | --- | --- | --- |
| Official Windows Suricata MSI with normal live capture | Yes, a compatible live-capture runtime/driver | Traffic reaching that Windows capture interface | Supported Windows capture approach, but requires managing its capture dependency and deployment terms |
| Official Windows MSI with `--windivert` | Not a working option in the inspected 8.0.6 binary | None: WinDivert support is compiled out | Bundled WinDivert files do not mean the executable supports that backend |
| Custom Suricata build with WinDivert | Can avoid Npcap live capture when built with the appropriate dependencies | Host IP traffic, or forwarded IP traffic when explicitly configured | Upstream backend is inline; requires a maintained build, matching API/driver, and isolation/performance testing |
| Custom passive WinDivert integration | No Npcap driver | Host IP packets copied to a capture consumer | Possible engineering work, not a supported passive switch in the inspected Suricata backend |
| Pktmon capture and offline Suricata analysis on Linux | No | Recorded packets from the selected Windows networking component | Good investigation/teaching option; delayed analysis rather than a continuous IDS |
| OPNsense Suricata in IDS mode | No | Traffic crossing the selected firewall interface | Fastest shared boundary-monitoring option; lane NAT limits guest attribution |
| Linux Suricata with mirrored lane traffic | No | The traffic explicitly copied from the chosen virtual bridges/taps | Recommended for scalable, passive visibility into Windows/Linux lab traffic |

The official Windows build guide identifies Npcap as the live-capture dependency;
it also describes building with the MSYS2 libpcap implementation for offline
processing without Npcap. Npcap's vendor provides an OEM silent installer for
unattended deployment; choose a distribution and license suitable for the range
before packaging it into automation. [Suricata Windows build guide](https://docs.suricata.io/en/suricata-8.0.6/install/windows.html),
[Npcap OEM deployment](https://npcap.com/oem/).

## What the current Windows MSI actually contains

The official download page lists `Suricata-8.0.6-1-64bit.msi`. The downloaded
artifact was 36,577,280 bytes, with observed SHA-256:

```text
AC7E2DB129FCBC5136BC15E4A40BEFA6435253523780D5D4E97E3E7B172AB442
```

This hash identifies the inspected download; it is not a separately published
vendor signature. [Official Suricata downloads](https://suricata.io/download/),
[inspected MSI](https://www.openinfosecfoundation.org/download/windows/Suricata-8.0.6-1-64bit.msi).

Read-only inspection used the Windows Installer database in mode `0`, selected
CAB file extraction, and static Portable Executable import/string inspection:

- The MSI File table contains `WinDivert.dll` and `WinDivert64.sys`.
- The packaged `suricata.exe` directly imports **`wpcap.dll`**.
- Its embedded build information states **`WinDivert enabled: no`** and
  **`Npcap support: yes`**, and includes **`WINDIVERT(DISABLED)`**.
- The MSI File table does not supply `wpcap.dll`, `Packet.dll`, or an Npcap
  installer. A compatible external capture runtime is still needed.

Therefore, installing the bundled WinDivert driver or copying a newer WinDivert
DLL beside this executable cannot enable its missing backend. Even invoking
`--build-info` or offline PCAP mode on this particular binary remains subject to
Windows resolving its direct DLL imports. The executable was not run; actual
capture, driver loading, and Windows 11 compatibility were not validated.

## Why a custom WinDivert build needs care

Suricata's Windows IPS guide describes a separate build with
`--enable-windivert=yes` and matching include/library paths. Its backend is
explicitly for inline processing. In the tagged 8.0.6 source, the queue uses
flags `0`, which diverts packets for processing/reinjection instead of copying
them for passive observation. Alert-only detection rules do not remove that
packet-path dependency. [Suricata Windows IPS guide](https://docs.suricata.io/en/suricata-8.0.6/ips/setting-up-ipsinline-for-windows.html),
[8.0.6 WinDivert backend](https://github.com/OISF/suricata/blob/suricata-8.0.6/src/source-windivert.c#L292).

The tagged 8.0.6 CI workflow uses **WinDivert 1.4.3-A**. Current WinDivert
documentation describes **2.2**, whose `WinDivertRecv` argument order and address
structure differ from the calls in the 8.0.6 backend. Treat 2.2 as a porting and
testing task, not a replacement DLL. The old build recipe establishes the API
used by CI; it does not establish that its driver will load under every current
Windows 11 security configuration. Do not disable driver-signing or platform
protections to force an incompatible driver to load.
[Suricata 8.0.6 build workflow](https://github.com/OISF/suricata/blob/suricata-8.0.6/.github/workflows/builds.yml#L3316),
[WinDivert 2.2 API](https://www.reqrypt.org/windivert-doc.html#divert_recv).

WinDivert itself supports a sniff flag that copies packets. Suricata's existing
inline receive/verdict path does not expose that as a passive capture option;
changing a flag alone without changing reinjection behavior can duplicate traffic.
A maintained passive adapter would need to handle those semantics, loss/backlog,
shutdown, and API compatibility. WinDivert also loads a signed kernel driver on
demand and requires administrative privileges: it avoids Npcap, not capture
drivers altogether. [WinDivert flags and installation](https://www.reqrypt.org/windivert-doc.html#divert_open).

## Sensor placement in this environment

The known example lane uses guest addresses **`10.42.59.0/24`** behind gateway
**`100.100.62.68`**. Its gateway translates outbound traffic before OPNsense sees
it on `vlan060_lab`. Thus an OPNsense alert sourced from `100.100.62.68` identifies
the lane gateway; it does not by itself identify VM 610811 or a student.

Keep time-bounded gateway-to-lane ownership history in CyberCore and correlate
it with endpoint connection events. To observe original guest addresses and
traffic between guests in the same lane, capture before that translation or
mirror the relevant virtual bridge/tap traffic to a sensor. A VM attached to a
switched network does not automatically receive every other guest's packets:
the mirror must explicitly supply both directions and retain lane identity.
Overlapping/reused address ranges require the lane/deployment identity as well
as an IP address. [OPNsense interface and NAT guidance](https://docs.opnsense.org/manual/ips.html#choosing-an-interface).

For the OPNsense path, begin with **IDS/alert-only capture**, selected rules, and
EVE syslog forwarding. Its documented EVE syslog option exports alerts; do not
assume it supplies every DNS, flow, or packet event. Configure the receiving
collector and verify decoding before using the Wazuh network dashboard.
[OPNsense Suricata settings](https://docs.opnsense.org/manual/ips.html#general-setup),
[Wazuh Suricata integration](https://documentation.wazuh.com/current/proof-of-concept-guide/integrate-network-ids-suricata.html).

For a short Windows investigation, built-in Pktmon can record traffic and export
PCAPNG for analysis elsewhere. Select an appropriate capture component to avoid
counting copies of the same packet at multiple stack layers; the export loses
some ETL drop/component detail. Apply capture duration/size limits and restricted
storage because packet payloads can contain sensitive data.
[Microsoft Pktmon](https://learn.microsoft.com/en-us/windows-server/networking/technologies/pktmon/pktmon),
[PCAPNG conversion](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/pktmon-etl2pcap).

## Before a broad rollout

Pilot one class with a harmless detection test; confirm the sensor receives the
intended traffic, the Wazuh decoder preserves source/destination fields, and the
dashboard distinguishes expected exercises from traffic crossing lane boundaries.
Measure capture loss, CPU, event volume, disk growth, and detection latency during
simultaneous class activity. Check encrypted-traffic limits: packet inspection
does not automatically reveal TLS application payloads. Keep response decisions
separate from student detections so expected lessons do not trigger blanket
blocking across a shared lane gateway.
