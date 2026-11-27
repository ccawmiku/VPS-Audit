"""Unit tests for the Spamhaus DROP reconciliation script.

The script ships without a ``.py`` suffix, so it is loaded through an explicit
source-file loader.  Every test works on a throw-away temporary directory and
never invokes the real ``nft`` binary or the Spamhaus HTTP endpoints.
"""

import errno
import importlib.machinery
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock

# The script has no .py suffix; keep its import from leaving __pycache__ behind.
sys.dont_write_bytecode = True

SCRIPT = Path(__file__).resolve().parents[1] / "vless-audit-blocklist"
_loader = importlib.machinery.SourceFileLoader("vless_audit_blocklist", str(SCRIPT))
_spec = importlib.util.spec_from_loader(_loader.name, _loader)
blocklist = importlib.util.module_from_spec(_spec)
_loader.exec_module(blocklist)


class FakeResponse:
    def __init__(self, body):
        self._body = body

    def read(self, size=-1):
        return self._body if size < 0 else self._body[:size]

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False


class TempStateMixin(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.state = self.root / "state"
        self.state.mkdir()
        self.request = self.root / "blocklist-request"
        for patcher in (
            mock.patch.object(blocklist, "STATE", self.state),
            mock.patch.object(blocklist, "REQUEST", self.request),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def tearDown(self):
        self._tmp.cleanup()


class ParseFeedTests(unittest.TestCase):
    def test_skips_metadata_and_collapses_overlapping_ipv4_networks(self):
        body = "\n".join(
            [
                '{"type":"metadata","timestamp":1}',
                '{"cidr":"192.0.2.0/24"}',
                '{"cidr":"192.0.2.128/25"}',
                '{"cidr":"203.0.113.0/24"}',
                "",
            ]
        )
        self.assertEqual(
            blocklist.parse_feed(body.encode(), 4),
            ["192.0.2.0/24", "203.0.113.0/24"],
        )

    def test_accepts_minimum_ipv4_and_ipv6_prefixes(self):
        self.assertEqual(
            blocklist.parse_feed(b'{"cidr":"10.0.0.0/8"}', 4), ["10.0.0.0/8"]
        )
        self.assertEqual(
            blocklist.parse_feed(b'{"cidr":"2000::/12"}', 6), ["2000::/12"]
        )

    def test_rejects_ipv4_prefix_shorter_than_eight(self):
        with self.assertRaises(ValueError):
            blocklist.parse_feed(b'{"cidr":"10.0.0.0/7"}', 4)

    def test_rejects_ipv6_prefix_shorter_than_twelve(self):
        with self.assertRaises(ValueError):
            blocklist.parse_feed(b'{"cidr":"2000::/11"}', 6)

    def test_rejects_network_of_the_wrong_address_family(self):
        with self.assertRaises(ValueError):
            blocklist.parse_feed(b'{"cidr":"2001:db8::/32"}', 4)

    def test_rejects_feed_without_any_network(self):
        with self.assertRaises(ValueError):
            blocklist.parse_feed(b'\n{"type":"metadata"}\n', 4)

    def test_rejects_malformed_json_line(self):
        with self.assertRaises(ValueError):
            blocklist.parse_feed(b'{"cidr":', 4)


class ScopeTests(unittest.TestCase):
    def test_defaults_to_eth0_without_ports(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(blocklist.scope(), ("eth0", []))

    def test_sorts_and_deduplicates_inbound_ports(self):
        env = {"VLESS_AUDIT_IFACE": "eth0.100", "VLESS_AUDIT_INBOUND_PORT": "8443,443,443"}
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertEqual(blocklist.scope(), ("eth0.100", [443, 8443]))

    def test_accepts_249_ports_but_rejects_250(self):
        with mock.patch.dict(
            os.environ,
            {"VLESS_AUDIT_IFACE": "eth0", "VLESS_AUDIT_INBOUND_PORT": ",".join(map(str, range(1, 250)))},
            clear=True,
        ):
            self.assertEqual(len(blocklist.scope()[1]), 249)
        with mock.patch.dict(
            os.environ,
            {"VLESS_AUDIT_IFACE": "eth0", "VLESS_AUDIT_INBOUND_PORT": ",".join(map(str, range(1, 251)))},
            clear=True,
        ):
            with self.assertRaises(ValueError):
                blocklist.scope()

    def test_rejects_interface_names_outside_the_safe_character_set(self):
        for iface in ("eth0;rm", "a" * 16, ""):
            with mock.patch.dict(
                os.environ,
                {"VLESS_AUDIT_IFACE": iface, "VLESS_AUDIT_INBOUND_PORT": "443"},
                clear=True,
            ):
                with self.assertRaises(ValueError):
                    blocklist.scope()

    def test_rejects_out_of_range_ports(self):
        for ports in ("0", "65536", "443,70000"):
            with mock.patch.dict(
                os.environ,
                {"VLESS_AUDIT_IFACE": "eth0", "VLESS_AUDIT_INBOUND_PORT": ports},
                clear=True,
            ):
                with self.assertRaises(ValueError):
                    blocklist.scope()


class AuditFileTests(TempStateMixin):
    def test_missing_file_returns_none(self):
        self.assertIsNone(blocklist.read_audit_file(self.request, 8))

    def test_reads_content_within_limit(self):
        self.request.write_bytes(b"on\n")
        self.assertEqual(blocklist.read_audit_file(self.request, 8), b"on\n")

    def test_rejects_content_over_limit(self):
        self.request.write_bytes(b"on\noff\n!!")
        with self.assertRaises(ValueError):
            blocklist.read_audit_file(self.request, 8)

    def test_rejects_symlink_without_following_it(self):
        target = self.root / "target"
        target.write_bytes(b"on\n")
        self.request.symlink_to(target)
        with self.assertRaises(OSError) as caught:
            blocklist.read_audit_file(self.request, 8)
        self.assertEqual(caught.exception.errno, errno.ELOOP)

    def test_rejects_non_regular_file(self):
        directory = self.root / "dir"
        directory.mkdir()
        with self.assertRaises(OSError) as caught:
            blocklist.read_audit_file(directory, 8)
        self.assertEqual(caught.exception.errno, errno.EISDIR)

    def test_requested_maps_control_file_values(self):
        self.request.write_bytes(b"on\n")
        self.assertTrue(blocklist.requested())
        self.request.write_bytes(b"off\n")
        self.assertFalse(blocklist.requested())
        self.request.write_bytes(b"ON\n")
        with self.assertRaises(ValueError):
            blocklist.requested()
        self.request.unlink()
        self.assertFalse(blocklist.requested())


class JsonHelperTests(TempStateMixin):
    def test_write_json_is_atomic_compact_and_private(self):
        path = self.state / "status.json"
        blocklist.write_json(path, {"active": True, "rows": [1]}, 0o640)
        self.assertEqual(path.read_bytes(), b'{"active":true,"rows":[1]}')
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o640)
        self.assertEqual(sorted(p.name for p in self.state.iterdir()), ["status.json"])

    def test_read_json_returns_empty_mapping_for_missing_or_corrupt_file(self):
        self.assertEqual(blocklist.read_json(self.state / "missing.json"), {})
        (self.state / "broken.json").write_bytes(b"{not json")
        self.assertEqual(blocklist.read_json(self.state / "broken.json"), {})


class RefreshFeedTests(TempStateMixin):
    def _cache(self, updated_at):
        return {"updated_at": updated_at, "v4": ["192.0.2.0/24"], "v6": ["2001:db8::/32"]}

    def test_fresh_cache_skips_network(self):
        cache = self._cache(int(blocklist.time.time()) - 60)
        (self.state / "cache.json").write_text(json.dumps(cache))
        with mock.patch.object(blocklist, "urlopen") as urlopen:
            self.assertEqual(blocklist.refresh_feed(), (cache, False))
        urlopen.assert_not_called()

    def test_recent_attempt_skips_network_and_returns_stale_flag(self):
        attempt = {"at": int(blocklist.time.time()) - 120}
        (self.state / "attempt.json").write_text(json.dumps(attempt))
        with mock.patch.object(blocklist, "urlopen") as urlopen:
            self.assertEqual(blocklist.refresh_feed(), ({}, True))
        urlopen.assert_not_called()

    def test_successful_refresh_parses_both_feeds_and_writes_cache(self):
        responses = [
            FakeResponse(b'{"cidr":"192.0.2.0/24"}'),
            FakeResponse(b'{"cidr":"2001:db8::/32"}'),
        ]
        with mock.patch.object(blocklist, "urlopen", side_effect=responses) as urlopen:
            cache, stale = blocklist.refresh_feed()
        self.assertFalse(stale)
        self.assertEqual(cache["v4"], ["192.0.2.0/24"])
        self.assertEqual(cache["v6"], ["2001:db8::/32"])
        self.assertIsInstance(cache["updated_at"], int)
        self.assertEqual(
            urlopen.call_args_list,
            [
                mock.call(blocklist.SOURCES[4], timeout=12),
                mock.call(blocklist.SOURCES[6], timeout=12),
            ],
        )
        self.assertEqual(json.loads((self.state / "cache.json").read_text()), cache)

    def test_download_failure_keeps_previous_cache_and_records_attempt(self):
        previous = self._cache(int(blocklist.time.time()) - 2 * 86400)
        (self.state / "cache.json").write_text(json.dumps(previous))
        with mock.patch.object(blocklist, "urlopen", side_effect=OSError("offline")):
            self.assertEqual(blocklist.refresh_feed(), (previous, True))
        attempt = json.loads((self.state / "attempt.json").read_text())
        self.assertAlmostEqual(attempt["at"], int(blocklist.time.time()), delta=5)

    def test_oversized_download_is_rejected_without_replacing_cache(self):
        previous = self._cache(int(blocklist.time.time()) - 2 * 86400)
        (self.state / "cache.json").write_text(json.dumps(previous))
        oversize = FakeResponse(b"x" * 4_194_305)
        with mock.patch.object(blocklist, "urlopen", return_value=oversize):
            self.assertEqual(blocklist.refresh_feed(), (previous, True))
        self.assertEqual(json.loads((self.state / "cache.json").read_text()), previous)

    def test_empty_feed_is_rejected(self):
        with mock.patch.object(
            blocklist, "urlopen", side_effect=[FakeResponse(b""), FakeResponse(b"")]
        ):
            self.assertEqual(blocklist.refresh_feed(), ({}, True))
        self.assertFalse((self.state / "cache.json").exists())


class NftTests(unittest.TestCase):
    def test_nft_apply_streams_rules_and_raises_on_failure(self):
        failure = mock.Mock(returncode=1, stderr="syntax error\n")
        with mock.patch.object(blocklist.subprocess, "run", return_value=failure) as run:
            with self.assertRaises(RuntimeError) as caught:
                blocklist.nft_apply("destroy table inet vless_audit_drop\n")
        self.assertEqual(str(caught.exception), "syntax error")
        self.assertEqual(run.call_args.kwargs["input"], "destroy table inet vless_audit_drop\n")
        self.assertTrue(run.call_args.kwargs["text"])
        self.assertEqual(run.call_args.args[0], [blocklist.NFT, "-f", "-"])

    def test_drop_sets_parses_json_and_ignores_non_set_entries(self):
        completed = mock.Mock(
            stdout=b'{"nftables":[{"set":{"name":"hits_v4"}},{"rule":{"expr":[]}}]}'
        )
        with mock.patch.object(blocklist.subprocess, "run", return_value=completed) as run:
            sets = blocklist.drop_sets("-t")
        self.assertEqual(sets, {"hits_v4": {"name": "hits_v4"}})
        self.assertEqual(
            run.call_args.args[0],
            [blocklist.NFT, "-j", "-t", "list", "table", "inet", blocklist.TABLE],
        )
        self.assertTrue(run.call_args.kwargs["check"])


class RulesetTests(unittest.TestCase):
    def test_renders_scoped_sets_hit_tracking_and_drop_rules(self):
        cache = {"updated_at": 1, "v4": ["192.0.2.0/24"], "v6": ["2001:db8::/32"]}
        rules = blocklist.ruleset("eth0", [443, 8443], cache)
        self.assertTrue(rules.endswith("\n"))
        for fragment in (
            "add table inet vless_audit_drop\n",
            "add chain inet vless_audit_drop incoming { type filter hook input priority -5; policy accept; }\n",
            "flush chain inet vless_audit_drop incoming\n",
            "add set inet vless_audit_drop targets_v4 { type ipv4_addr; flags interval; auto-merge; }\n",
            "add element inet vless_audit_drop targets_v4 { 192.0.2.0/24 }\n",
            "add element inet vless_audit_drop targets_v6 { 2001:db8::/32 }\n",
            "add set inet vless_audit_drop hits_v4 { type ipv4_addr; flags dynamic,timeout; timeout 86400s; size 4096; }\n",
            "add set inet vless_audit_drop hits_v6 { type ipv6_addr; flags dynamic,timeout; timeout 86400s; size 4096; }\n",
            'add rule inet vless_audit_drop incoming iifname "eth0" tcp dport { 443, 8443 } ip saddr @targets_v4 update @hits_v4 { ip saddr }\n',
            'add rule inet vless_audit_drop incoming iifname "eth0" tcp dport { 443, 8443 } ip saddr @targets_v4 counter drop\n',
            'add rule inet vless_audit_drop incoming iifname "eth0" tcp dport { 443, 8443 } ip6 saddr @targets_v6 update @hits_v6 { ip6 saddr }\n',
            'add rule inet vless_audit_drop incoming iifname "eth0" tcp dport { 443, 8443 } ip6 saddr @targets_v6 counter drop\n',
        ):
            self.assertIn(fragment, rules)


class PublishDropHitsTests(TempStateMixin):
    NOW = 1_700_000_000

    def _status(self, active, tracking_since):
        (self.state / "status.json").write_text(
            json.dumps({"active": active, "tracking_since": tracking_since})
        )

    def test_inactive_report_removes_stale_snapshot(self):
        self._status(False, 1)
        snapshot = self.state / "drop-hits.json"
        snapshot.write_text("{}")
        blocklist.publish_drop_hits()
        self.assertFalse(snapshot.exists())

    def test_active_report_filters_versions_and_expired_elements(self):
        self._status(True, 1_000_000)
        sets = {
            "hits_v4": {
                "elem": [
                    {"elem": {"val": "192.0.2.1", "expires": 3600}},
                    {"elem": {"val": "192.0.2.2", "expires": 0}},
                    {"elem": {"val": "2001:db8::9", "expires": 100}},
                ]
            },
            "hits_v6": {"elem": [{"elem": {"val": "2001:db8::2", "expires": 7200}}]},
        }
        with mock.patch.object(
            blocklist, "drop_sets", return_value=sets
        ), mock.patch.object(blocklist.time, "time", return_value=self.NOW):
            blocklist.publish_drop_hits()
        written = json.loads((self.state / "drop-hits.json").read_text())
        self.assertEqual(written["tracking_since"], 1_000_000)
        self.assertEqual(written["collected_at"], self.NOW)
        self.assertFalse(written["at_capacity"])
        self.assertEqual(
            written["rows"],
            [
                {"ip": "2001:db8::2", "last_seen": self.NOW - 86400 + 7200},
                {"ip": "192.0.2.1", "last_seen": self.NOW - 86400 + 3600},
            ],
        )
        self.assertEqual(
            stat.S_IMODE((self.state / "drop-hits.json").stat().st_mode), 0o640
        )

    def test_hit_set_at_limit_is_reported_as_at_capacity(self):
        self._status(True, 1_000_000)
        elements = [
            {"elem": {"val": str(ipaddress.IPv4Address(0x0A000000 + index)), "expires": 100}}
            for index in range(blocklist.HIT_LIMIT)
        ]
        with mock.patch.object(
            blocklist,
            "drop_sets",
            return_value={"hits_v4": {"elem": elements}, "hits_v6": {"elem": []}},
        ), mock.patch.object(blocklist.time, "time", return_value=self.NOW):
            blocklist.publish_drop_hits()
        written = json.loads((self.state / "drop-hits.json").read_text())
        self.assertTrue(written["at_capacity"])
        self.assertEqual(len(written["rows"]), blocklist.HIT_LIMIT)

    def test_nft_failure_exits_nonzero_and_leaves_previous_snapshot(self):
        self._status(True, 1)
        snapshot = self.state / "drop-hits.json"
        snapshot.write_text('{"tracking_since":1}')
        with mock.patch.object(
            blocklist, "drop_sets", side_effect=ValueError("bad json")
        ):
            with self.assertRaises(SystemExit) as caught:
                blocklist.publish_drop_hits()
        self.assertEqual(caught.exception.code, 1)
        self.assertEqual(snapshot.read_text(), '{"tracking_since":1}')


class ApplySpamhausTests(TempStateMixin):
    def _request(self, value):
        self.request.write_bytes(value)

    def _report(self):
        return json.loads((self.state / "status.json").read_text())

    def test_disabled_request_tears_down_table_and_reports_inactive(self):
        self._request(b"off\n")
        with mock.patch.object(blocklist, "nft_apply") as nft_apply:
            blocklist.apply_spamhaus()
        nft_apply.assert_called_once_with("destroy table inet vless_audit_drop\n")
        report = self._report()
        self.assertEqual(report["interface"], "eth0")
        self.assertEqual(report["ports"], [])
        self.assertFalse(report["processed"])
        self.assertFalse(report["active"])
        self.assertIsNone(report["warning"])
        self.assertIsNone(report["tracking_since"])
        self.assertEqual(
            stat.S_IMODE((self.state / "status.json").stat().st_mode), 0o644
        )

    def test_enabled_without_ports_warns_no_ports(self):
        self._request(b"on\n")
        with mock.patch.object(blocklist, "nft_apply") as nft_apply:
            blocklist.apply_spamhaus()
        nft_apply.assert_called_once_with("destroy table inet vless_audit_drop\n")
        report = self._report()
        self.assertTrue(report["processed"])
        self.assertFalse(report["active"])
        self.assertEqual(report["warning"], "no_ports")

    def test_invalid_scope_warns_and_skips_ruleset(self):
        self._request(b"on\n")
        env = {"VLESS_AUDIT_IFACE": "bad iface", "VLESS_AUDIT_INBOUND_PORT": "443"}
        with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(
            blocklist, "nft_apply"
        ) as nft_apply:
            blocklist.apply_spamhaus()
        nft_apply.assert_called_once_with("destroy table inet vless_audit_drop\n")
        report = self._report()
        self.assertEqual(report["warning"], "invalid_scope")
        self.assertEqual(report["ports"], [])

    def test_enabled_scope_applies_ruleset_and_marks_active(self):
        self._request(b"on\n")
        cache = {"updated_at": 123, "v4": ["192.0.2.0/24"], "v6": ["2001:db8::/32"]}
        env = {"VLESS_AUDIT_IFACE": "eth0", "VLESS_AUDIT_INBOUND_PORT": "443"}
        with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(
            blocklist, "refresh_feed", return_value=(cache, False)
        ), mock.patch.object(blocklist, "drop_sets", return_value={}) as drop_sets, mock.patch.object(
            blocklist, "nft_apply"
        ) as nft_apply, mock.patch.object(
            blocklist.time, "time", return_value=1_700_000_000
        ):
            blocklist.apply_spamhaus()
        drop_sets.assert_called_once_with("-t")
        nft_apply.assert_called_once_with(blocklist.ruleset("eth0", [443], cache))
        report = self._report()
        self.assertTrue(report["active"])
        self.assertEqual(report["updated_at"], 123)
        self.assertEqual(report["ipv4_ranges"], 1)
        self.assertEqual(report["ipv6_ranges"], 1)
        self.assertIsNone(report["warning"])
        self.assertEqual(report["tracking_since"], 1_700_000_000)

    def test_stale_feed_is_reported_while_ruleset_still_applies(self):
        self._request(b"on\n")
        cache = {"updated_at": 123, "v4": ["192.0.2.0/24"], "v6": ["2001:db8::/32"]}
        env = {"VLESS_AUDIT_IFACE": "eth0", "VLESS_AUDIT_INBOUND_PORT": "443"}
        with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(
            blocklist, "refresh_feed", return_value=(cache, True)
        ), mock.patch.object(blocklist, "drop_sets", return_value={}), mock.patch.object(
            blocklist, "nft_apply"
        ):
            blocklist.apply_spamhaus()
        report = self._report()
        self.assertTrue(report["active"])
        self.assertEqual(report["warning"], "stale_feed")

    def test_existing_tracking_since_is_reused_when_hit_sets_survive(self):
        self._request(b"on\n")
        (self.state / "status.json").write_text(
            json.dumps(
                {
                    "active": True,
                    "updated_at": 123,
                    "interface": "eth0",
                    "ports": [443],
                    "tracking_since": 777,
                }
            )
        )
        cache = {"updated_at": 123, "v4": ["192.0.2.0/24"], "v6": ["2001:db8::/32"]}
        env = {"VLESS_AUDIT_IFACE": "eth0", "VLESS_AUDIT_INBOUND_PORT": "443"}
        with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(
            blocklist, "refresh_feed", return_value=(cache, False)
        ), mock.patch.object(
            blocklist,
            "drop_sets",
            return_value={"hits_v4": {"elem": []}, "hits_v6": {"elem": []}},
        ), mock.patch.object(blocklist, "nft_apply") as nft_apply:
            blocklist.apply_spamhaus()
        nft_apply.assert_not_called()
        self.assertEqual(self._report()["tracking_since"], 777)

    def test_firewall_error_preserves_previous_active_state(self):
        self._request(b"on\n")
        (self.state / "status.json").write_text(
            json.dumps(
                {
                    "active": True,
                    "updated_at": 1,
                    "interface": "eth0",
                    "ports": [443],
                    "tracking_since": 55,
                }
            )
        )
        cache = {"updated_at": 123, "v4": ["192.0.2.0/24"], "v6": ["2001:db8::/32"]}
        env = {"VLESS_AUDIT_IFACE": "eth0", "VLESS_AUDIT_INBOUND_PORT": "443"}
        with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(
            blocklist, "refresh_feed", return_value=(cache, False)
        ), mock.patch.object(blocklist, "drop_sets", return_value={}), mock.patch.object(
            blocklist, "nft_apply", side_effect=RuntimeError("nft exploded")
        ):
            blocklist.apply_spamhaus()
        report = self._report()
        self.assertTrue(report["active"])
        self.assertEqual(report["warning"], "firewall_error")
        self.assertEqual(report["tracking_since"], 55)


if __name__ == "__main__":
    unittest.main()
