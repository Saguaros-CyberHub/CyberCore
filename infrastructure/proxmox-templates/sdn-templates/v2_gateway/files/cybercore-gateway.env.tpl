# /etc/cybercore-gateway.env
# Overrides for /etc/local.d/00-cybercore-firstboot.start.
# The deploy path may overwrite this file at deploy time via `pct push`.
#
# Generated from files/cybercore-gateway.env.tpl at bake time — the @…@ markers
# below are substituted by bake.sh from vars.env.

# Upstream DNS (defaults to OPNsense lab gateway)
DNS_FORWARDER=100.100.60.1

# Internal lane domain (suffix appended to short hostnames in dnsmasq)
LANE_DOMAIN=cybercore.lan

# Convention: the GOAD controller VM gets <lan-base>.5 in every lane
CONTROLLER_OCTET=5

# Convention: the lane's primary console box gets <lan-base>.50 — Kali on a
# challenge lane, or workstation slot 0 on a lane-deployer lane. Firstboot
# installs the wan0:3389 DNAT to this IP.
#
# The address is delivered by DHCP RESERVATION, not a static pin: the Kali cloud
# image's cloud-ifupdown helper races a cloud-init ipconfig0 and wins, which left
# the box on a random lease and the DNAT pointing at nothing. See
# challenge-lane-deployer.writeLaneReservations and lane-deployer's
# applyGatewayWorkstationAccess, both of which key the reservation on MAC.
KALI_OCTET=50

# DHCP scope for lane VMs. NOTE this range CONTAINS .5 and .50 — it is a pool,
# not a set of exclusions. Those addresses stay free because dnsmasq never hands
# a reserved address to a client that doesn't match the reservation, so a pool
# lease only lands there for the host the reservation names.
DHCP_START_OCTET=10
DHCP_END_OCTET=200

# --- Tailscale subnet router (BYOAB) ---
# The Tailscale auth key is NOT stored here. firstboot pulls it from the
# orchestrator at boot via GET <CYBERCORE_ORCHESTRATOR_URL>/api/lane-bootstrap,
# identified by the lane's claim secret (or WAN source IP). If the orchestrator
# is unreachable or has no pending token for this lane, Tailscale setup is
# skipped silently and the lane still works (just without BYOAB).
#
# Override the orchestrator URL here if it lives elsewhere:
CYBERCORE_ORCHESTRATOR_URL=@CYBERCORE_ORCHESTRATOR_URL@

# Lab-internal URL the LANE uses to pull prebuilt vuln-app images. Read by
# firstboot's iptables block (CYBERCORE-IMAGE-PULL) to whitelist this exact
# destination through the perimeter DROPs. Must match vuln-app-builder.js's
# LANE_ORCH_URL — if you change one, change both.
CYBERCORE_INTERNAL_URL=@CYBERCORE_INTERNAL_URL@
