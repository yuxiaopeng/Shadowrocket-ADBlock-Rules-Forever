from __future__ import annotations

import contextlib
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

import render_my_rules as renderer


FIXTURES = Path(__file__).resolve().parent / "fixtures"
OVERLAY = (
    REPOSITORY_ROOT
    / "automation"
    / "my-rules"
    / "sr_top500_banlist_ad"
    / "overlay.toml"
)
UPSTREAM_COMMIT = "0123456789abcdef0123456789abcdef01234567"


class RendererTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.overlay = renderer.load_overlay(OVERLAY)
        cls.upstream = (FIXTURES / "upstream.conf").read_bytes()
        cls.expected = (FIXTURES / "expected.conf").read_bytes()

    def render(self, data: bytes | None = None) -> renderer.RenderResult:
        return renderer.render_bytes(data or self.upstream, self.overlay)

    def copy_overlay(self, directory: Path) -> Path:
        for source in OVERLAY.parent.iterdir():
            if source.is_file():
                shutil.copy2(source, directory / source.name)
        return directory / "overlay.toml"

    def test_render_matches_fixture_and_is_idempotent(self) -> None:
        first = self.render()
        second = renderer.render_bytes(first.output, self.overlay)

        self.assertEqual(first.output, self.expected)
        self.assertEqual(second.output, first.output)
        self.assertEqual(first.stats["duplicate_rules_removed"], 2)
        self.assertEqual(first.stats["base_rule_count"], 6)
        self.assertEqual(first.stats["output_rule_count"], 20)
        self.assertEqual(first.stats["output_rule_count"], first.stats["output_unique_rule_count"])
        self.assertEqual(second.stats["duplicate_rules_removed"], 0)
        self.assertEqual(second.stats["added_lines"], 0)
        self.assertEqual(second.stats["modified_lines"], 0)

    def test_general_ensure_and_append_unique_are_stable(self) -> None:
        output = self.render().output.decode("utf-8")

        self.assertIn("prefer-ipv6 = false\n", output)
        self.assertIn("fallback-dns-server = system\n", output)
        self.assertIn("always-real-ip = easy-login.10099.com.cn", output)
        self.assertEqual(output.count("www.baidu.com"), 1)
        self.assertEqual(output.count("id6.me"), 2)

    def test_rules_keep_first_normalized_occurrence_and_non_rules(self) -> None:
        output = self.render().output.decode("utf-8")

        self.assertIn("DOMAIN-SUFFIX, duplicate.example, Proxy\n", output)
        self.assertNotIn("DOMAIN-SUFFIX,duplicate.example,Proxy\n", output)
        self.assertIn("DOMAIN-SUFFIX,duplicate.example,DIRECT\n", output)
        self.assertIn("# Duplicate-adjacent comment must survive.\n", output)
        self.assertEqual(output.count("DOMAIN-SUFFIX,bybit.com,Proxy\n"), 1)
        self.assertEqual(output.count("YouTube去广告 = type=http-request"), 1)

    def test_complete_custom_rule_fragment_is_present_in_order(self) -> None:
        output_lines = self.render().output.decode("utf-8").splitlines()
        fragment_lines = (OVERLAY.parent / "rules.prepend.conf").read_text(
            encoding="utf-8"
        ).splitlines()
        rule_index = output_lines.index("[Rule]")

        self.assertEqual(
            output_lines[rule_index + 1 : rule_index + 1 + len(fragment_lines)],
            fragment_lines,
        )
        self.assertIn("DOMAIN-SUFFIX,bybit-global.com,Proxy", fragment_lines)
        self.assertIn(
            "DOMAIN-SUFFIX,chatgpt.com,Proxy,pre-matching,extended-matching",
            fragment_lines,
        )

    def test_missing_core_section_fails(self) -> None:
        data = self.upstream.replace(b"[URL Rewrite]\n", b"[Other]\n")
        with self.assertRaisesRegex(renderer.RenderError, "missing core sections"):
            renderer.render_bytes(data, self.overlay)

    def test_duplicate_section_fails(self) -> None:
        data = self.upstream + b"[Rule]\nFINAL,direct\n"
        with self.assertRaisesRegex(renderer.RenderError, r"duplicate \[Rule\]"):
            renderer.render_bytes(data, self.overlay)

    def test_conflicting_general_value_fails(self) -> None:
        data = self.upstream.replace(
            b"ipv6 = false\n", b"ipv6 = false\nprefer-ipv6 = true\n"
        )
        with self.assertRaisesRegex(renderer.RenderError, "conflicting.*General"):
            renderer.render_bytes(data, self.overlay)

    def test_conflicting_host_value_fails(self) -> None:
        data = self.upstream.replace(
            b"[URL Rewrite]\n",
            b"[Host]\nlocalhost = 127.0.0.2\n\n[URL Rewrite]\n",
        )
        with self.assertRaisesRegex(renderer.RenderError, "conflicting.*Host"):
            renderer.render_bytes(data, self.overlay)

    def test_conflicting_mitm_value_fails(self) -> None:
        data = self.upstream.replace(
            b"[MITM]\n", b"[MITM]\nenable = false\n"
        )
        with self.assertRaisesRegex(renderer.RenderError, "conflicting.*MITM"):
            renderer.render_bytes(data, self.overlay)

    def test_missing_duplicate_and_stale_terminal_anchors_fail(self) -> None:
        cases = (
            self.upstream.replace(b"FINAL,direct\n", b""),
            self.upstream.replace(b"FINAL,direct\n", b"FINAL,direct\nFINAL,direct\n"),
            self.upstream.replace(
                b"FINAL,direct\n", b"FINAL,direct\nDOMAIN,after.example,Proxy\n"
            ),
        )
        for data in cases:
            with self.subTest(data=data[-80:]):
                with self.assertRaisesRegex(renderer.RenderError, "terminal anchor"):
                    renderer.render_bytes(data, self.overlay)

    def test_insertion_anchor_must_be_unique_and_before_terminal(self) -> None:
        anchor = ",".join(self.overlay.insertion_anchor).encode() + b"\n"
        cases = (
            self.upstream.replace(anchor, b""),
            self.upstream.replace(anchor, anchor + anchor),
            self.upstream.replace(anchor + b"FINAL,direct\n", b"FINAL,direct\n" + anchor),
        )
        for data in cases:
            with self.subTest(data=data[-180:]):
                with self.assertRaisesRegex(renderer.RenderError, "insertion anchor"):
                    renderer.render_bytes(data, self.overlay)

    def test_youtube_assignment_is_inserted_before_apple_news_anchor(self) -> None:
        lines = self.render().output.decode("utf-8").splitlines()
        youtube = self.overlay.rules_before_terminal[0]
        anchor = ",".join(self.overlay.insertion_anchor)
        terminal = ",".join(self.overlay.terminal_anchor)

        self.assertLess(lines.index(youtube), lines.index(anchor))
        self.assertLess(lines.index(anchor), lines.index(terminal))

    def test_same_youtube_assignment_is_noop_only_at_canonical_position(self) -> None:
        anchor = ",".join(self.overlay.insertion_anchor).encode() + b"\n"
        youtube = self.overlay.rules_before_terminal[0].encode() + b"\n"
        canonical = self.upstream.replace(anchor, youtube + b"\n" + anchor)
        result = renderer.render_bytes(canonical, self.overlay)
        self.assertEqual(result.output.count(youtube), 1)

        misplaced = self.upstream.replace(anchor, youtube + anchor)
        with self.assertRaisesRegex(renderer.RenderError, "canonical insertion position"):
            renderer.render_bytes(misplaced, self.overlay)

        conflict_assignment = (
            "YouTube去广告 = type=http-request,pattern=conflict\n".encode()
        )
        conflict = self.upstream.replace(
            anchor,
            conflict_assignment + b"\n" + anchor,
        )
        with self.assertRaisesRegex(renderer.RenderError, "conflicting Rule assignment"):
            renderer.render_bytes(conflict, self.overlay)

    def test_moved_rule_fragments_fail_closed(self) -> None:
        rendered = self.render().output
        anchor = ",".join(self.overlay.insertion_anchor).encode() + b"\n"

        prepend_block = (OVERLAY.parent / "rules.prepend.conf").read_bytes() + b"\n"
        moved_prepend = rendered.replace(
            b"[Rule]\n" + prepend_block,
            b"[Rule]\n",
            1,
        ).replace(anchor, prepend_block + anchor, 1)
        with self.assertRaisesRegex(renderer.RenderError, "canonical prefix"):
            renderer.render_bytes(moved_prepend, self.overlay)

        before_block = (
            OVERLAY.parent / "rules.before-terminal.conf"
        ).read_bytes() + b"\n"
        moved_before = rendered.replace(before_block + anchor, anchor, 1).replace(
            b"FINAL,direct\n",
            before_block + b"FINAL,direct\n",
            1,
        )
        with self.assertRaisesRegex(renderer.RenderError, "canonical insertion position"):
            renderer.render_bytes(moved_before, self.overlay)

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

    def test_overlay_hash_covers_toml_and_referenced_fragments(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            overlay_path = self.copy_overlay(directory)
            original = renderer.load_overlay(overlay_path).digest

            fragment = directory / "rules.before-terminal.conf"
            fragment.write_bytes(fragment.read_bytes() + b"# hash probe\n")
            changed_fragment = renderer.load_overlay(overlay_path).digest
            self.assertNotEqual(changed_fragment, original)

            overlay_path.write_text(
                overlay_path.read_text(encoding="utf-8").replace(
                    "max_added_lines = 64", "max_added_lines = 63"
                ),
                encoding="utf-8",
                newline="\n",
            )
            changed_toml = renderer.load_overlay(overlay_path).digest
            self.assertNotEqual(changed_toml, changed_fragment)

    def test_change_budget_is_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            overlay_path = self.copy_overlay(directory)
            overlay_path.write_text(
                overlay_path.read_text(encoding="utf-8").replace(
                    "max_added_lines = 64", "max_added_lines = 0"
                ),
                encoding="utf-8",
                newline="\n",
            )
            with self.assertRaisesRegex(renderer.RenderError, "change budget exceeded"):
                renderer.render_bytes(self.upstream, renderer.load_overlay(overlay_path))

    def test_render_check_and_verify_state_detect_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            input_path = directory / "upstream.conf"
            output_path = directory / "output.conf"
            state_path = directory / "state.json"
            input_path.write_bytes(self.upstream)

            state = renderer.render_files(
                input_path, output_path, state_path, OVERLAY, UPSTREAM_COMMIT
            )
            checked = renderer.check_files(input_path, output_path, OVERLAY)
            verified = renderer.verify_state_files(output_path, state_path)

            self.assertEqual(state, verified)
            self.assertEqual(checked.output, output_path.read_bytes())
            self.assertEqual(json.loads(state_path.read_text(encoding="utf-8")), state)

            output_path.write_bytes(output_path.read_bytes() + b"# drift\n")
            with self.assertRaisesRegex(renderer.RenderError, "output drift"):
                renderer.verify_state_files(output_path, state_path)
            with self.assertRaisesRegex(renderer.RenderError, "candidate differs"):
                renderer.check_files(input_path, output_path, OVERLAY)

    def test_verify_state_ignores_new_input_overlay_and_commit_context(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            overlay_path = self.copy_overlay(directory)
            input_path = directory / "upstream.conf"
            output_path = directory / "output.conf"
            state_path = directory / "state.json"
            input_path.write_bytes(self.upstream)
            state = renderer.render_files(
                input_path, output_path, state_path, overlay_path, UPSTREAM_COMMIT
            )

            input_path.write_bytes(
                self.upstream.replace(b"# Fixture", b"# New upstream fixture")
            )
            fragment = directory / "rules.before-terminal.conf"
            fragment.write_bytes(fragment.read_bytes() + b"# new overlay\n")

            self.assertEqual(
                renderer.verify_state_files(output_path, state_path),
                state,
            )

    def test_malformed_state_is_rejected(self) -> None:
        result = self.render()
        valid = renderer.build_state(result, self.upstream, UPSTREAM_COMMIT)
        cases: list[tuple[str, dict[str, object]]] = []

        extra_top_level = json.loads(json.dumps(valid))
        extra_top_level["unexpected"] = 1
        cases.append(("top-level key", extra_top_level))

        boolean_schema = json.loads(json.dumps(valid))
        boolean_schema["schema_version"] = True
        cases.append(("boolean schema", boolean_schema))

        malformed_commit = json.loads(json.dumps(valid))
        malformed_commit["upstream_commit"] = "A" * 40
        cases.append(("commit", malformed_commit))

        for key in ("base_sha256", "overlay_sha256", "output_sha256"):
            malformed_hash = json.loads(json.dumps(valid))
            malformed_hash[key] = "A" * 64
            cases.append((key, malformed_hash))

        extra_stat = json.loads(json.dumps(valid))
        extra_stat["stats"]["unexpected"] = 0
        cases.append(("extra stat", extra_stat))

        missing_stat = json.loads(json.dumps(valid))
        del missing_stat["stats"]["base_bytes"]
        cases.append(("missing stat", missing_stat))

        boolean_stat = json.loads(json.dumps(valid))
        boolean_stat["stats"]["base_bytes"] = True
        cases.append(("boolean stat", boolean_stat))

        negative_stat = json.loads(json.dumps(valid))
        negative_stat["stats"]["base_bytes"] = -1
        cases.append(("negative stat", negative_stat))

        with tempfile.TemporaryDirectory() as temporary:
            state_path = Path(temporary) / "state.json"
            for name, state in cases:
                with self.subTest(name=name):
                    state_path.write_bytes(renderer.encode_state(state))
                    with self.assertRaises(renderer.RenderError):
                        renderer._load_state(state_path)

            signed_growth = json.loads(json.dumps(valid))
            signed_growth["stats"]["output_growth_bytes"] = -1
            state_path.write_bytes(renderer.encode_state(signed_growth))
            self.assertEqual(
                renderer._load_state(state_path)["stats"]["output_growth_bytes"],
                -1,
            )

    def test_build_state_rejects_malformed_upstream_commit(self) -> None:
        with self.assertRaisesRegex(renderer.RenderError, "40-character"):
            renderer.build_state(self.render(), self.upstream, "not-a-commit")

    def test_cli_render_check_and_verify_state(self) -> None:
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
                "--overlay",
                str(OVERLAY),
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


class HistoryValidatorTestCase(unittest.TestCase):
    def test_valid_two_parent_first_parent_chain(self) -> None:
        commits = (
            renderer.HistoryCommit(
                "merge-1", ("bootstrap", "upstream-1"), renderer.EXPECTED_MERGE_SUBJECT
            ),
            renderer.HistoryCommit(
                "merge-2", ("merge-1", "upstream-2"), renderer.EXPECTED_MERGE_SUBJECT
            ),
        )

        result = renderer.validate_history_records("bootstrap", "merge-2", commits)

        self.assertEqual(result.merge_count, 2)

    def test_non_merge_commit_fails(self) -> None:
        commits = (
            renderer.HistoryCommit(
                "ordinary", ("bootstrap",), renderer.EXPECTED_MERGE_SUBJECT
            ),
        )
        with self.assertRaisesRegex(renderer.RenderError, "two-parent merge"):
            renderer.validate_history_records("bootstrap", "ordinary", commits)

    def test_broken_first_parent_chain_fails(self) -> None:
        commits = (
            renderer.HistoryCommit(
                "merge-1", ("wrong", "upstream-1"), renderer.EXPECTED_MERGE_SUBJECT
            ),
        )
        with self.assertRaisesRegex(renderer.RenderError, "broken first-parent chain"):
            renderer.validate_history_records("bootstrap", "merge-1", commits)

    def test_unexpected_merge_subject_fails(self) -> None:
        commits = (
            renderer.HistoryCommit(
                "merge-1", ("bootstrap", "upstream-1"), "Merge something else"
            ),
        )
        with self.assertRaisesRegex(renderer.RenderError, "unexpected merge subject"):
            renderer.validate_history_records("bootstrap", "merge-1", commits)

    def test_tip_mismatch_fails(self) -> None:
        with self.assertRaisesRegex(renderer.RenderError, "history ended"):
            renderer.validate_history_records("bootstrap", "tip", ())


if __name__ == "__main__":
    unittest.main()
