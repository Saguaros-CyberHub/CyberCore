"""Run with: python -m unittest discover -s infrastructure/caldera -p test_*.py"""
import unittest
import re
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

from agent_guard import authorized_beacon
from patch_upstream import add_trimmed_profile_group

PAW = "a" * 24
GROUP = "lane-12345678-abcd-abcd-abcd-123456789abc"
HEADERS = {"X-Caldera-Paw": PAW, "X-Caldera-Group": GROUP}

# GetTrimmedProfile from Sandcat commit
# 0a35cd525f1cfabfcf602282428055c41f144513, gocat/agent/agent.go.
TRIMMED_PROFILE = '''func (a *Agent) GetTrimmedProfile() map[string]interface{} {
\treturn map[string]interface{}{
\t\t"paw":           a.paw,
\t\t"server":        a.server,
\t\t"platform":      a.platform,
\t\t"host":          a.host,
\t\t"contact":       a.GetCurrentContactName(),
\t\t"upstream_dest": a.upstreamDest,
\t}
}
'''


class SandcatProfilePatchTests(unittest.TestCase):
    def test_result_profile_keeps_paw_and_includes_group_exactly_once(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "agent.go"
            target.write_text(TRIMMED_PROFILE, encoding="utf-8")
            add_trimmed_profile_group(target)
            keys = re.findall(r'"([a-z_]+)":', target.read_text(encoding="utf-8"))
            self.assertEqual(keys.count("paw"), 1)
            self.assertEqual(keys.count("group"), 1)
            self.assertIn("platform", keys)
            # A moved/already applied upstream patch must fail at image build.
            with self.assertRaises(RuntimeError):
                add_trimmed_profile_group(target)
            target.write_text(TRIMMED_PROFILE + TRIMMED_PROFILE, encoding="utf-8")
            with self.assertRaises(RuntimeError):
                add_trimmed_profile_group(target)


class AgentGuardTests(unittest.IsolatedAsyncioTestCase):
    async def test_valid_beacon_and_own_result(self):
        find_link = AsyncMock(return_value=SimpleNamespace(paw=PAW))
        profile = {"paw": PAW, "group": GROUP}
        self.assertTrue(await authorized_beacon(profile, HEADERS, find_link))
        find_link.assert_not_awaited()
        profile["results"] = [{"id": "own-link", "output": "dHJhaW5pbmc="}]
        self.assertTrue(await authorized_beacon(profile, HEADERS, find_link))
        find_link.assert_awaited_once_with("own-link")

    async def test_missing_or_malformed_trusted_identity_fails_closed(self):
        profile = {"paw": PAW, "group": GROUP}
        for headers in [{}, {"X-Caldera-Paw": PAW},
                        {**HEADERS, "X-Caldera-Paw": "arbitrary"},
                        {**HEADERS, "X-Caldera-Group": "another-group"}]:
            self.assertFalse(await authorized_beacon(profile, headers, AsyncMock()))

    async def test_cross_agent_paw_or_group_is_rejected(self):
        for profile in [{"paw": "b" * 24, "group": GROUP},
                        {"paw": PAW, "group": GROUP.replace("abcd", "ffff")},
                        {"paw": PAW}, [], None]:
            find_link = AsyncMock()
            self.assertFalse(await authorized_beacon(profile, HEADERS, find_link))
            find_link.assert_not_awaited()

    async def test_foreign_or_unknown_result_link_is_rejected(self):
        profile = {"paw": PAW, "group": GROUP, "results": [{"id": "foreign-link"}]}
        self.assertFalse(await authorized_beacon(profile, HEADERS,
                         AsyncMock(return_value=SimpleNamespace(paw="b" * 24))))
        self.assertFalse(await authorized_beacon(profile, HEADERS, AsyncMock(return_value=None)))

    async def test_every_result_is_checked_and_malformed_results_are_rejected(self):
        profile = {"paw": PAW, "group": GROUP}
        for results in [None, {}, ["not-a-result"], [{}], [{"id": 123}]]:
            self.assertFalse(await authorized_beacon({**profile, "results": results}, HEADERS, AsyncMock()))
        results = [{"id": "own-link"}, {"id": "foreign-link"}]
        find_link = AsyncMock(side_effect=[SimpleNamespace(paw=PAW), SimpleNamespace(paw="b" * 24)])
        self.assertFalse(await authorized_beacon({**profile, "results": results}, HEADERS, find_link))
        self.assertEqual(find_link.await_count, 2)


if __name__ == "__main__":
    unittest.main()
