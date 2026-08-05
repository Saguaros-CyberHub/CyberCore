# v2 lane gateway template

Builds the **v2 lane-gateway LXC template at VMID 1694** — the subnet-agnostic
router that fronts every `subnet_scheme='v2'` lane.

```
./bake.sh                                    # first build
FORCE=1 ./bake.sh                            # rebuild, replacing 1694
CYBERCORE_ORCHESTRATOR_URL=https://staging.example.org ./bake.sh
```

Run as **root on a Proxmox node where template 1692 lives**. This is a one-time
build, not something the deploy path calls — deploys just `pct clone 1694`.

## Why this isn't Packer

Packer's Proxmox plugin (`proxmox-iso`, `proxmox-clone`) builds QEMU VMs only —
there is no LXC/CT builder. The gateway is a container, so the build is driven by
`pct`. The layout still mirrors the Packer templates next door: payloads in
`files/`, ordered build steps in `scripts/`, configuration in `vars.env`.

## What v2 changes

| | v1 (1692) | v2 (1694) |
|---|---|---|
| Lane subnet | hardcoded `192.18.0.0/24`, shared by every lane | any `/24` in `10.0.0.0/8`, set per-deploy |
| dnsmasq | baked `dnsmasq.conf` | rendered at every boot from `lan0`'s actual IP |
| NAT / firewall | baked into `50-gateway.start` | rendered by the firstboot hook |
| Lane uniqueness | VXLAN only | VXLAN **and** addressing |

1692 is never modified — v1 lanes keep working, and `bake-lane-gateway-v3.sh`
clones the 1694 this produces to build the segmented v3 gateway at 1695.

## Layout

```
bake.sh                                 driver: clone → patch → install → verify
vars.env                                CTIDs, storage, orchestrator URLs
files/
  local.d/00-cybercore-firstboot.start  THE payload — renders everything at boot
  local.d/50-gateway.start.stub         no-op replacing v1's hardcoded hook
  cybercore-gateway.env.tpl             /etc/cybercore-gateway.env (@…@ substituted)
  dnsmasq.conf.placeholder              shipped config; firstboot overwrites it
  conf.d/tailscale                      userspace-networking mode
scripts/                                ordered in-CT patch steps
  10-rewrite-lan0-iface.sh              lan0 → `inet manual` so Proxmox owns the IP
  20-neutralize-v1-hooks.sh             stub 50-gateway.start, sweep 192.18.0.x
  30-sweep-dnsmasq-dropins.sh           move aside v1 /etc/dnsmasq.d drop-ins
  40-install-https-tooling.sh           GNU wget + ca-certificates, enable services
  50-install-tailscale.sh               install + userspace mode + smoke test
  60-scrub-v1-iptables.sh               purge v1 rules from rules-save
verify/assertions.sh                    post-bake checks against a booted clone
```

## The firstboot hook is the whole point

`files/local.d/00-cybercore-firstboot.start` runs on **every** boot, not just the
first. It waits up to 15s for `lan0` to have an address, then renders from it:

- `/etc/dnsmasq.conf` — DHCP pool `.10–.200`, router/DNS pointing at the gateway,
  a hostname-matched `dhcp-host=kali,<base>.50` reservation, and
  `conf-dir=/etc/dnsmasq.d/` so the deploy path can drop MAC reservations in
- `GOAD-CONTROLLER-SSH` — ACCEPT for `<base>.5` → `lan0:22`
- lane MASQUERADE out `wan0`
- `CYBERCORE-KALI-RDP` — fallback DNAT `wan0:3389` → `<base>.50:3389`
- `CYBERCORE-IMAGE-PULL` — narrow ACCEPT at FORWARD position 2, above the base
  template's perimeter DROPs, so vuln-app image pulls survive

It then fetches a single-use Tailscale auth key from
`<CYBERCORE_ORCHESTRATOR_URL>/api/lane-bootstrap`, claiming it with the `b<16hex>`
secret the orchestrator embeds in the LXC hostname. Retry window is 10 minutes,
matching the token's server-side TTL. If the fetch fails the lane still works —
just without BYOAB.

Editing this file changes runtime behavior for **new clones only**; existing lanes
keep whatever they were cloned from until they are redeployed.

## Two config files, don't confuse them

- **`vars.env`** — bake-time. Which CTIDs, which storage, which orchestrator URL
  gets written into the image. Read only by `bake.sh`.
- **`files/cybercore-gateway.env.tpl`** → `/etc/cybercore-gateway.env` — runtime.
  Read by the firstboot hook on every boot, and overwritable per-lane with
  `pct push`. Holds `DNS_FORWARDER`, `LANE_DOMAIN`, `CONTROLLER_OCTET`,
  `KALI_OCTET`, the DHCP octet range, and both orchestrator URLs.

`CYBERCORE_INTERNAL_URL` must match `LANE_ORCH_URL` in
`front-end/modules/crucible/plugins/ciab/utils/vuln-app-builder.js` — firstboot
keys its `CYBERCORE-IMAGE-PULL` rule on that host, and a mismatch makes every
lane's vuln-app install fail with exit 11.

## Verification

After installing 1694, `bake.sh` clones it to a scratch CTID with a deliberately
fake `lan0` (`10.99.0.1/24` by default — override with `VERIFY_LANE_BASE`), boots
it, and runs `verify/assertions.sh`. Because the assertions are written against
whatever base was passed, passing them *is* the proof that the image is
subnet-agnostic. The verify clone is always destroyed; on failure 1694 is left in
place and `bake.sh` exits 1, so inspect before using it.

## Guardrails

- Aborts unless 1692 exists **and** is flagged as a template.
- Refuses to overwrite an existing 1694 without `FORCE=1`.
- Refuses to run if scratch CTIDs 9994/9995 are in use (`TMP_VMID`/`VERIFY_VMID`
  to move them).
- Missing payload files are caught before anything is cloned.

## Related

- `../bake-lane-gateway-v3.sh` — segmented 3-NIC v3 gateway (1695), clones 1694
- `../patch-goad-gateway-key.sh` — controller pubkey; applied to 1692, so 1694
  inherits it through the clone
- `../../vm-templates/bake-goad-controller-vm.sh` — GOAD controller template
