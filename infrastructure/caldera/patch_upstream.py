"""Apply small, fail-fast compatibility/security changes to Caldera 5.3.0."""
from pathlib import Path


def replace_once(path, old, new):
    source = path.read_text(encoding="utf-8")
    if source.count(old) != 1:
        raise RuntimeError(f"Recheck the CyberCore patch for {path} before upgrading Caldera")
    path.write_text(source.replace(old, new), encoding="utf-8")


def add_trimmed_profile_group(path):
    old = ("func (a *Agent) GetTrimmedProfile() map[string]interface{} {\n"
           "\treturn map[string]interface{}{\n"
           '\t\t"paw":           a.paw,\n'
           '\t\t"server":        a.server,')
    new = old.replace('\n\t\t"server":', '\n\t\t"group":         a.group,\n\t\t"server":')
    replace_once(path, old, new)


def main():
    # Stock Sandcat disables certificate verification. Capability-bearing HTTPS
    # connections must validate the server certificate normally.
    replace_once(Path("plugins/sandcat/gocat/contact/api.go"),
                 "InsecureSkipVerify: true", "MinVersion: tls.VersionTLS12")

    # Result-only HTTP posts use GetTrimmedProfile, which upstream omits group
    # from. Include it so both ordinary beacons and result submissions satisfy
    # the same server-side lane identity guard.
    add_trimmed_profile_group(Path("plugins/sandcat/gocat/agent/agent.go"))

    contact = Path("app/contacts/contact_http.py")
    replace_once(contact, "import json\n", "import json\nfrom cybercore_agent_guard import authorized_beacon\n")
    decode_profile = "            profile = json.loads(self.contact_svc.decode_bytes(await request.read()))"
    replace_once(contact, decode_profile, decode_profile + "\n"
                 "            if not await authorized_beacon(profile, request.headers, self.app_svc.find_link):\n"
                 "                return web.Response(status=403)")

    # Preserve deterministic 24-character paws; upstream assumes six characters.
    replace_once(Path("app/api/rest_api.py"), "agent_name=agent[-6:]",
                 'agent_name=request.headers.get("X-Paw", agent[-6:])')

    # Manual file-upload abilities can run without a currently active operation.
    operation_dir = "        path = os.path.join((dir_name), ''.join(agent_opid[0]))"
    replace_once(Path("app/service/file_svc.py"), operation_dir,
                 "        if not agent_opid:\n            return dir_name\n" + operation_dir)


if __name__ == "__main__":
    main()
