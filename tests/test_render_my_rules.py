from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

import render_my_rules as renderer


FIXTURES = Path(__file__).resolve().parent / "fixtures"
CUSTOM_CONFIG = (
    REPOSITORY_ROOT
    / "automation"
    / "my-rules"
    / "sr_top500_banlist_ad"
    / "custom.conf"
)
UPSTREAM_COMMIT = "0123456789abcdef0123456789abcdef01234567"


class RendererTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.custom_bytes = CUSTOM_CONFIG.read_bytes()
        cls.custom = renderer.load_custom_config(CUSTOM_CONFIG)
        cls.upstream = (FIXTURES / "upstream.conf").read_bytes()
        cls.expected = (FIXTURES / "expected.conf").read_bytes()

    def render(
        self,
        data: bytes | None = None,
        custom: renderer.CustomConfig | None = None,
    ) -> renderer.RenderResult:
        return renderer.render_bytes(
            self.upstream if data is None else data,
            self.custom if custom is None else custom,
        )

    def load_custom_bytes(self, data: bytes) -> renderer.CustomConfig:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name) / "custom.conf"
        path.write_bytes(data)
        return renderer.load_custom_config(path)

    def custom_with(self, old: bytes, new: bytes) -> renderer.CustomConfig:
        self.assertIn(old, self.custom_bytes)
        return self.load_custom_bytes(self.custom_bytes.replace(old, new))

    def test_render_matches_fixture_and_is_idempotent(self) -> None:
        first = self.render()
        second = renderer.render_bytes(first.output, self.custom)

        self.assertEqual(first.output, self.expected)
        self.assertEqual(second.output, first.output)
        self.assertEqual(first.stats["duplicate_rules_removed"], 2)
        self.assertEqual(first.stats["base_rule_count"], 11)
        self.assertEqual(first.stats["output_rule_count"], 25)
        self.assertEqual(first.stats["output_rule_count"], first.stats["output_unique_rule_count"])
        self.assertEqual(second.stats["duplicate_rules_removed"], 0)
        self.assertEqual(second.stats["added_lines"], 0)
        self.assertEqual(second.stats["removed_lines"], 0)
        self.assertEqual(second.stats["modified_lines"], 0)

    def test_custom_config_contains_complete_customization(self) -> None:
        text = self.custom_bytes.decode("utf-8")

        self.assertIn("[Overlay]\nschema-version = 1\n", text)
        self.assertIn("[General]\nprefer-ipv6 = false\n", text)
        self.assertIn("DOMAIN-SUFFIX,chatgpt.com,Proxy,pre-matching,extended-matching", text)
        self.assertIn(
            "AND,((DOMAIN-SUFFIX,googlevideo.com), (PROTOCOL,UDP)),REJECT", text
        )
        self.assertIn(
            "AND,((DOMAIN,youtubei.googleapis.com), (PROTOCOL,UDP)),REJECT", text
        )
        self.assertIn("YouTube去广告 = type=http-request", text)
        self.assertIn("[Host]\nlocalhost = 127.0.0.1", text)
        self.assertIn("[URL Rewrite]\n\n[MITM]", text)
        self.assertNotIn("max_added_lines", text)

    def test_general_scalar_override_and_custom_first_unions(self) -> None:
        output = self.render().output.decode("utf-8")

        self.assertIn("prefer-ipv6 = false\n", output)
        self.assertNotIn("prefer-ipv6 = true\n", output)
        self.assertIn(
            "skip-proxy = www.baidu.com, yunbusiness.ccb.com, wxh.wo.cn, "
            "gate.lagou.com, www.abchina.com.cn, www.shanbay.com, "
            "login-service.mobile-bank.psbc.com, mobile-bank.psbc.com, id6.me, "
            "www.163.com, localhost\n",
            output,
        )
        self.assertIn(
            "always-real-ip = easy-login.10099.com.cn, *-update.xoyocdn.com, "
            "id6.me, open.e.189.cn, upstream.example\n",
            output,
        )

    def test_host_is_created_before_url_rewrite_and_custom_overrides(self) -> None:
        created = self.render().output.decode("utf-8")
        self.assertLess(created.index("[Host]"), created.index("[URL Rewrite]"))

        upstream = self.upstream.replace(
            b"[URL Rewrite]\n", b"[Host]\nlocalhost = 127.0.0.2\nother = value\n\n[URL Rewrite]\n"
        )
        output = self.render(upstream).output.decode("utf-8")
        self.assertIn("localhost = 127.0.0.1\n", output)
        self.assertNotIn("localhost = 127.0.0.2\n", output)
        self.assertIn("other = value\n", output)

    def test_mitm_hostname_is_case_insensitive_custom_first_union(self) -> None:
        output = self.render().output.decode("utf-8")

        self.assertIn(
            "hostname = *.google.cn, *.googlevideo.com, upstream.example\n", output
        )
        self.assertNotIn("*.GOOGLE.CN", output)
        self.assertIn("enable = true\n", output)
        self.assertNotIn("enable = false\n", output)
        self.assertIn("# Footer must survive.\n", output)

    def test_url_rewrite_custom_first_override_and_upstream_dedupe(self) -> None:
        custom = self.custom_with(
            b"[URL Rewrite]\n\n[MITM]",
            b"[URL Rewrite]\n# Custom rewrite\n"
            b"^https?://custom\\.example https://new.example 302\n\n[MITM]",
        )
        output = self.render(custom=custom).output.decode("utf-8")

        self.assertIn("# Custom rewrite\n", output)
        self.assertIn("^https?://custom\\.example https://new.example 302\n", output)
        self.assertNotIn("https://old.example", output)
        self.assertEqual(output.count("^https?://duplicate\\.example"), 1)
        self.assertIn("https://first.example", output)
        self.assertNotIn("https://second.example", output)
        self.assertEqual(renderer.render_bytes(output.encode(), custom).output, output.encode())

    def test_rule_semantic_identity_and_unknown_fallback(self) -> None:
        output = self.render().output.decode("utf-8")

        self.assertIn("DOMAIN-SUFFIX,bybit.com,Proxy\n", output)
        self.assertNotIn("DOMAIN-SUFFIX,bybit.com,DIRECT\n", output)
        self.assertIn("DOMAIN-SUFFIX, Duplicate.Example, Proxy\n", output)
        self.assertNotIn("DOMAIN-SUFFIX,duplicate.example,DIRECT\n", output)
        self.assertIn("DOMAIN-SUFFIX,modifier.example,Proxy,no-resolve\n", output)
        self.assertIn("DOMAIN-SUFFIX,modifier.example,DIRECT,pre-matching\n", output)
        self.assertEqual(output.count("FUTURE-RULE,value,Proxy\n"), 1)
        self.assertIn("FUTURE-RULE,value,DIRECT\n", output)

    def test_nested_comma_rule_is_one_matcher_and_custom_overrides_action(self) -> None:
        output = self.render().output.decode("utf-8")
        udp_rule = "AND,((DOMAIN-SUFFIX,googlevideo.com), (PROTOCOL,UDP)),REJECT"

        self.assertEqual(output.count(udp_rule), 1)
        self.assertNotIn(
            "AND,((DOMAIN-SUFFIX,GOOGLEVIDEO.COM), (PROTOCOL,UDP)),Proxy", output
        )
        fields = renderer._top_level_comma_fields(udp_rule, "test")
        self.assertEqual(
            fields,
            ("AND", "((DOMAIN-SUFFIX,googlevideo.com), (PROTOCOL,UDP))", "REJECT"),
        )

    def test_named_assignment_is_overridden_before_final(self) -> None:
        lines = self.render().output.decode("utf-8").splitlines()
        assignments = [line for line in lines if line.startswith("YouTube去广告 =")]

        self.assertEqual(len(assignments), 1)
        self.assertIn("script-path=https://choler.github.io", assignments[0])
        self.assertLess(lines.index(assignments[0]), lines.index("FINAL,Proxy"))

    def test_final_is_singleton_inherited_and_last(self) -> None:
        lines = self.render().output.decode("utf-8").splitlines()
        rule_start = lines.index("[Rule]") + 1
        rule_end = lines.index("[Host]")
        rule_lines = lines[rule_start:rule_end]
        self.assertEqual(sum(line.startswith("FINAL,") for line in rule_lines), 1)
        self.assertEqual(next(line for line in reversed(rule_lines) if line and not line.startswith("#")), "FINAL,Proxy")
        self.assertLess(
            rule_lines.index("# Comment after FINAL must move before it."),
            next(index for index, line in enumerate(rule_lines) if line.startswith("FINAL,")),
        )

        custom = self.custom_with(
            "YouTube去广告 = type=http-request".encode(),
            "FINAL,Reject\nYouTube去广告 = type=http-request".encode(),
        )
        overridden = self.render(custom=custom).output.decode("utf-8").splitlines()
        overridden_rule_lines = overridden[
            overridden.index("[Rule]") + 1 : overridden.index("[Host]")
        ]
        self.assertEqual(
            next(
                line
                for line in reversed(overridden_rule_lines)
                if line and not line.startswith("#")
            ),
            "FINAL,Reject",
        )
        self.assertNotIn("FINAL,Proxy", overridden_rule_lines)

    def test_missing_final_fails(self) -> None:
        upstream = self.upstream.replace(b"FINAL,Proxy\n", b"")
        with self.assertRaisesRegex(renderer.RenderError, "must contain a FINAL"):
            self.render(upstream)

    def test_active_rule_after_final_fails_closed_but_trivia_moves(self) -> None:
        active_cases = (
            b"FINAL,Proxy\nDOMAIN-SUFFIX,after.example,Proxy\n",
            b"FINAL,Proxy\nassignment = value\n",
            b"FINAL,Proxy\nFINAL,direct\n",
        )
        for suffix in active_cases:
            with self.subTest(suffix=suffix):
                upstream = self.upstream.replace(
                    b"FINAL,Proxy\n# Comment after FINAL must move before it.\n", suffix
                    + b"# Comment after FINAL must move before it.\n"
                )
                with self.assertRaisesRegex(
                    renderer.RenderError, "active Rule entry appears after terminal FINAL"
                ):
                    self.render(upstream)

        trivia_only = self.upstream.replace(
            b"FINAL,Proxy\n# Comment after FINAL must move before it.\n",
            b"FINAL,Proxy\n# First trailing comment.\n# Second trailing comment.\n",
        )
        output = self.render(trivia_only).output.decode("utf-8")
        rule_lines = output.split("[Rule]\n", 1)[1].split("\n[Host]", 1)[0]
        self.assertLess(
            rule_lines.index("# First trailing comment."),
            rule_lines.index("FINAL,Proxy"),
        )

    def test_matcher_identity_normalizes_nested_protocol_and_ip_networks(self) -> None:
        nested_udp = renderer.parse_rule_entry(
            "AND,((DOMAIN-SUFFIX,Example.COM), (PROTOCOL,udp)),Proxy", "test"
        )
        nested_UDP = renderer.parse_rule_entry(
            "AND,((DOMAIN-SUFFIX,example.com), (PROTOCOL,UDP)),DIRECT", "test"
        )
        self.assertEqual(nested_udp.identity, nested_UDP.identity)

        ipv6_a = renderer.parse_rule_entry(
            "IP-CIDR6,2001:0DB8:0:0::1/64,Proxy", "test"
        )
        ipv6_b = renderer.parse_rule_entry(
            "IP-CIDR6,2001:db8::abcd/64,DIRECT", "test"
        )
        self.assertEqual(ipv6_a.identity, ipv6_b.identity)

        ipv4_a = renderer.parse_rule_entry(
            "IP-CIDR,192.0.2.1/24,Proxy", "test"
        )
        ipv4_b = renderer.parse_rule_entry(
            "IP-CIDR,192.0.2.0/24,DIRECT", "test"
        )
        self.assertEqual(ipv4_a.identity, ipv4_b.identity)

    def test_custom_duplicate_matcher_even_with_different_action_fails(self) -> None:
        custom = self.custom_bytes.replace(
            b"DOMAIN-SUFFIX,ping0.cc,Proxy\n",
            b"DOMAIN-SUFFIX,ping0.cc,Proxy\nDOMAIN-SUFFIX,PING0.CC,DIRECT\n",
        )
        with self.assertRaisesRegex(renderer.RenderError, "duplicate matcher identity"):
            self.load_custom_bytes(custom)

    def test_unknown_custom_rule_fails_but_unknown_upstream_is_opaque(self) -> None:
        custom = self.custom_bytes.replace(
            b"DOMAIN-SUFFIX,ping0.cc,Proxy\n",
            b"CUSTOM-FUTURE,ping0.cc,Proxy\n",
        )
        with self.assertRaisesRegex(renderer.RenderError, "unknown custom rule type"):
            self.load_custom_bytes(custom)
        self.assertIn("FUTURE-RULE,value,Proxy", self.render().output.decode("utf-8"))

    def test_malformed_known_rule_and_parentheses_fail(self) -> None:
        cases = (
            self.upstream.replace(
                b"RULE-SET,https://example.com/rules.list,Proxy\n",
                b"RULE-SET,https://example.com/rules.list\n",
            ),
            self.upstream.replace(
                b"RULE-SET,https://example.com/rules.list,Proxy\n",
                b"AND,((DOMAIN,example.com),(PROTOCOL,UDP),Proxy\n",
            ),
        )
        for data in cases:
            with self.subTest(data=data[-200:]):
                with self.assertRaises(renderer.RenderError):
                    self.render(data)

    def test_custom_comments_are_preserved_without_duplication(self) -> None:
        first = self.render().output.decode("utf-8")
        second = renderer.render_bytes(first.encode(), self.custom).output.decode("utf-8")
        self.assertEqual(first.count("# 自定义规则\n"), 1)
        self.assertEqual(second.count("# 自定义规则\n"), 1)

    def test_missing_core_and_duplicate_sections_fail(self) -> None:
        missing = self.upstream.replace(b"[URL Rewrite]\n", b"[Other]\n")
        duplicate = self.upstream + b"[Rule]\nFINAL,direct\n"
        with self.assertRaisesRegex(renderer.RenderError, "missing core sections"):
            self.render(missing)
        with self.assertRaisesRegex(renderer.RenderError, r"duplicate \[Rule\]"):
            self.render(duplicate)

    def test_strict_utf8_lf_and_final_newline_are_required(self) -> None:
        cases = (
            self.upstream.replace(b"\n", b"\r\n"),
            self.upstream[:-1],
            self.upstream + b"\xff\n",
            b"\xef\xbb\xbf" + self.upstream,
        )
        for data in cases:
            with self.subTest(prefix=data[:8], suffix=data[-8:]):
                with self.assertRaises(renderer.RenderError):
                    renderer.parse_document(data)

    def test_custom_schema_and_sections_are_strict(self) -> None:
        cases = (
            self.custom_bytes.replace(b"schema-version = 1", b"schema-version = 2"),
            self.custom_bytes.replace(b"[Host]\n", b"[Unsupported]\n"),
            self.custom_bytes.replace(b"[Host]\nlocalhost = 127.0.0.1\n\n", b""),
            self.custom_bytes.replace(
                b"schema-version = 1\n", b"schema-version = 1\nbudget = 999\n"
            ),
        )
        for data in cases:
            with self.subTest(data=data[:100]):
                with self.assertRaises(renderer.RenderError):
                    self.load_custom_bytes(data)

    def test_custom_hash_covers_exact_single_file_bytes(self) -> None:
        changed = self.load_custom_bytes(
            self.custom_bytes.replace("# 自定义规则".encode(), b"# Custom rules")
        )
        self.assertEqual(self.custom.digest, renderer.sha256(self.custom_bytes))
        self.assertNotEqual(changed.digest, self.custom.digest)

    def test_fixed_change_budget_rejects_excessive_upstream_cleanup(self) -> None:
        duplicate_lines = b"FUTURE-DUPLICATE,value,Proxy\n" * (
            renderer.MAX_REMOVED_LINES + 2
        )
        upstream = self.upstream.replace(
            b"FUTURE-RULE,value,Proxy\n", duplicate_lines, 1
        )
        with self.assertRaisesRegex(renderer.RenderError, "change budget exceeded"):
            self.render(upstream)


class StateAndCliTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.custom = renderer.load_custom_config(CUSTOM_CONFIG)
        cls.upstream = (FIXTURES / "upstream.conf").read_bytes()

    def render(self) -> renderer.RenderResult:
        return renderer.render_bytes(self.upstream, self.custom)
    def test_render_check_and_verify_schema_2_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            input_path = directory / "upstream.conf"
            output_path = directory / "output.conf"
            state_path = directory / "state.json"
            input_path.write_bytes(self.upstream)

            state = renderer.render_files(
                input_path, output_path, state_path, CUSTOM_CONFIG, UPSTREAM_COMMIT
            )
            checked = renderer.check_files(input_path, output_path, CUSTOM_CONFIG)
            verified = renderer.verify_state_files(output_path, state_path)

            self.assertEqual(state["schema_version"], 2)
            self.assertIn("custom_sha256", state)
            self.assertNotIn("overlay_sha256", state)
            self.assertEqual(state, verified)
            self.assertEqual(checked.output, output_path.read_bytes())
            self.assertEqual(json.loads(state_path.read_text(encoding="utf-8")), state)

            output_path.write_bytes(output_path.read_bytes() + b"# drift\n")
            with self.assertRaisesRegex(renderer.RenderError, "output drift"):
                renderer.verify_state_files(output_path, state_path)
            with self.assertRaisesRegex(renderer.RenderError, "candidate differs"):
                renderer.check_files(input_path, output_path, CUSTOM_CONFIG)

    def test_verify_state_accepts_schema_1_for_output_drift_migration(self) -> None:
        result = self.render()
        state_v2 = renderer.build_state(result, self.upstream, UPSTREAM_COMMIT)
        state_v1 = dict(state_v2)
        state_v1["schema_version"] = 1
        state_v1["overlay_sha256"] = state_v1.pop("custom_sha256")

        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            output_path = directory / "output.conf"
            state_path = directory / "state.json"
            output_path.write_bytes(result.output)
            state_path.write_bytes(renderer.encode_state(state_v1))

            self.assertEqual(renderer.verify_state_files(output_path, state_path), state_v1)
            output_path.write_bytes(result.output + b"# drift\n")
            with self.assertRaisesRegex(renderer.RenderError, "output drift"):
                renderer.verify_state_files(output_path, state_path)

    def test_malformed_schema_1_and_2_states_are_rejected(self) -> None:
        valid = renderer.build_state(self.render(), self.upstream, UPSTREAM_COMMIT)
        cases: list[dict[str, object]] = []

        extra = json.loads(json.dumps(valid))
        extra["unexpected"] = 1
        cases.append(extra)
        boolean_schema = json.loads(json.dumps(valid))
        boolean_schema["schema_version"] = True
        cases.append(boolean_schema)
        bad_commit = json.loads(json.dumps(valid))
        bad_commit["upstream_commit"] = "A" * 40
        cases.append(bad_commit)
        bad_hash = json.loads(json.dumps(valid))
        bad_hash["custom_sha256"] = "A" * 64
        cases.append(bad_hash)
        extra_stat = json.loads(json.dumps(valid))
        extra_stat["stats"]["unexpected"] = 0
        cases.append(extra_stat)
        negative_stat = json.loads(json.dumps(valid))
        negative_stat["stats"]["base_bytes"] = -1
        cases.append(negative_stat)
        mixed_schema = json.loads(json.dumps(valid))
        mixed_schema["schema_version"] = 1
        cases.append(mixed_schema)

        with tempfile.TemporaryDirectory() as temporary:
            state_path = Path(temporary) / "state.json"
            for state in cases:
                with self.subTest(state=state):
                    state_path.write_bytes(renderer.encode_state(state))
                    with self.assertRaises(renderer.RenderError):
                        renderer._load_state(state_path)

    def test_build_state_rejects_malformed_upstream_commit(self) -> None:
        with self.assertRaisesRegex(renderer.RenderError, "40-character"):
            renderer.build_state(self.render(), self.upstream, "not-a-commit")

    def test_cli_uses_custom_config_for_render_check_and_verify(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            input_path = directory / "upstream.conf"
            output_path = directory / "output.conf"
            state_path = directory / "state.json"
            input_path.write_bytes(self.upstream)
            common = [
                "--input",
                str(input_path),
                "--output",
                str(output_path),
                "--custom-config",
                str(CUSTOM_CONFIG),
            ]
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                self.assertEqual(
                    renderer.main(
                        [
                            "render",
                            *common,
                            "--state",
                            str(state_path),
                            "--upstream-commit",
                            UPSTREAM_COMMIT,
                        ]
                    ),
                    0,
                )
                self.assertEqual(renderer.main(["check", *common]), 0)
                self.assertEqual(
                    renderer.main(
                        [
                            "verify-state",
                            "--output",
                            str(output_path),
                            "--state",
                            str(state_path),
                        ]
                    ),
                    0,
                )
            self.assertEqual(len(stdout.getvalue().splitlines()), 3)
            self.assertNotIn("--overlay", renderer.build_argument_parser().format_help())


if __name__ == "__main__":
    unittest.main()
