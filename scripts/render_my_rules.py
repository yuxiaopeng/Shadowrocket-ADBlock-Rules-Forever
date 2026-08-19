#!/usr/bin/env python3
"""Render repository-owned Shadowrocket customizations onto an upstream config."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

BOOTSTRAP_COMMIT = "d804e583d2777a8c609e8e55362365c88a8debae"
EXPECTED_MERGE_SUBJECT = (
    "Merge remote-tracking branch 'origin/upstream-release-history' into my-rules"
)
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OVERLAY = (
    REPOSITORY_ROOT
    / "automation"
    / "my-rules"
    / "sr_top500_banlist_ad"
    / "overlay.toml"
)
SECTION_HEADER = re.compile(r"^\[([^\[\]]+)\]$")
ASSIGNMENT = re.compile(r"^([^=]+?)\s*=\s*(.*)$")


class RenderError(RuntimeError):
    """Raised when an input cannot be rendered deterministically."""


@dataclass
class Section:
    name: str
    body: list[str]


@dataclass
class Document:
    preamble: list[str]
    sections: list[Section]

    def section(self, name: str) -> Section:
        matches = [section for section in self.sections if section.name == name]
        if len(matches) != 1:
            raise RenderError(
                f"expected exactly one [{name}] section, found {len(matches)}"
            )
        return matches[0]

    def serialize(self) -> bytes:
        lines = list(self.preamble)
        for section in self.sections:
            lines.append(f"[{section.name}]")
            lines.extend(section.body)
        return ("\n".join(lines) + "\n").encode("utf-8")


@dataclass(frozen=True)
class Overlay:
    path: Path
    digest: str
    core_sections: tuple[str, ...]
    general_ensure: Mapping[str, str]
    general_append_unique: Mapping[str, tuple[str, ...]]
    host_insert_before: str
    host_ensure: Mapping[str, str]
    mitm_ensure: Mapping[str, str]
    mitm_append_unique: Mapping[str, tuple[str, ...]]
    rules_prepend: tuple[str, ...]
    rules_before_terminal: tuple[str, ...]
    insertion_anchor: tuple[str, ...]
    terminal_anchor: tuple[str, ...]
    budget: Mapping[str, int]


@dataclass
class RenderStats:
    base_bytes: int = 0
    output_bytes: int = 0
    base_lines: int = 0
    output_lines: int = 0
    base_rule_count: int = 0
    output_rule_count: int = 0
    output_unique_rule_count: int = 0
    added_lines: int = 0
    removed_lines: int = 0
    modified_lines: int = 0
    duplicate_rules_removed: int = 0
    general_values_added: int = 0
    list_values_appended: int = 0
    sections_added: int = 0
    rule_fragments_added: int = 0
    output_growth_bytes: int = 0

    def as_dict(self) -> dict[str, int]:
        return {
            key: value
            for key, value in self.__dict__.items()
        }


@dataclass(frozen=True)
class RenderResult:
    output: bytes
    overlay_sha256: str
    stats: Mapping[str, int]


@dataclass(frozen=True)
class HistoryCommit:
    oid: str
    parents: tuple[str, ...]
    subject: str


@dataclass(frozen=True)
class HistoryValidation:
    bootstrap_commit: str
    tip_commit: str
    merge_count: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "bootstrap_commit": self.bootstrap_commit,
            "tip_commit": self.tip_commit,
            "merge_count": self.merge_count,
        }


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def decode_strict_text(data: bytes, source: str) -> str:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise RenderError(f"{source} is not valid UTF-8: {error}") from error
    if text[:1] == chr(0xFEFF):
        raise RenderError(f"{source} must not contain a UTF-8 BOM")
    if "\r" in text:
        raise RenderError(f"{source} must use LF line endings")
    if not text.endswith("\n"):
        raise RenderError(f"{source} must end with a newline")
    return text


def read_strict_file(path: Path) -> bytes:
    try:
        data = path.read_bytes()
    except OSError as error:
        raise RenderError(f"cannot read {path}: {error}") from error
    decode_strict_text(data, str(path))
    return data


def parse_document(data: bytes, source: str = "input") -> Document:
    text = decode_strict_text(data, source)
    lines = text[:-1].split("\n")
    preamble: list[str] = []
    sections: list[Section] = []
    current: Section | None = None
    seen: set[str] = set()

    for line_number, line in enumerate(lines, start=1):
        match = SECTION_HEADER.fullmatch(line)
        if match:
            name = match.group(1)
            if name in seen:
                raise RenderError(
                    f"{source}:{line_number}: duplicate [{name}] section"
                )
            seen.add(name)
            current = Section(name=name, body=[])
            sections.append(current)
        elif current is None:
            preamble.append(line)
        else:
            current.body.append(line)

    return Document(preamble=preamble, sections=sections)


def _expect_table(root: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    value = root.get(key)
    if not isinstance(value, dict):
        raise RenderError(f"overlay key {key!r} must be a table")
    return value


def _expect_string_map(root: Mapping[str, Any], key: str) -> dict[str, str]:
    table = _expect_table(root, key)
    result: dict[str, str] = {}
    for item_key, value in table.items():
        if not isinstance(item_key, str) or not isinstance(value, str):
            raise RenderError(f"overlay table {key!r} must contain string values")
        result[item_key] = value
    return result


def _expect_string_list_map(
    root: Mapping[str, Any], key: str
) -> dict[str, tuple[str, ...]]:
    table = _expect_table(root, key)
    result: dict[str, tuple[str, ...]] = {}
    for item_key, value in table.items():
        if not isinstance(value, list) or not all(
            isinstance(item, str) and item for item in value
        ):
            raise RenderError(
                f"overlay table {key!r} must contain non-empty string arrays"
            )
        if len(value) != len(set(value)):
            raise RenderError(f"overlay list {key}.{item_key} contains duplicates")
        result[item_key] = tuple(value)
    return result


def _resolve_fragment(overlay_path: Path, reference: str) -> Path:
    if not reference:
        raise RenderError("overlay fragment reference must not be empty")
    overlay_directory = overlay_path.parent.resolve()
    fragment = (overlay_directory / reference).resolve()
    try:
        fragment.relative_to(overlay_directory)
    except ValueError as error:
        raise RenderError(
            f"overlay fragment {reference!r} escapes {overlay_directory}"
        ) from error
    return fragment


def _fragment_lines(data: bytes, source: str) -> tuple[str, ...]:
    text = decode_strict_text(data, source)
    lines = tuple(text[:-1].split("\n"))
    if not lines or all(not line for line in lines):
        raise RenderError(f"overlay fragment {source} must not be empty")
    return lines


def _hash_overlay(
    overlay_bytes: bytes, fragments: Sequence[tuple[str, str, bytes]]
) -> str:
    digest = hashlib.sha256()
    entries = [("overlay.toml", "overlay.toml", overlay_bytes), *fragments]
    for role, relative_path, data in entries:
        for part in (role.encode(), relative_path.encode(), data):
            digest.update(len(part).to_bytes(8, "big"))
            digest.update(part)
    return digest.hexdigest()


def load_overlay(path: Path = DEFAULT_OVERLAY) -> Overlay:
    path = path.resolve()
    overlay_bytes = read_strict_file(path)
    try:
        raw = tomllib.loads(overlay_bytes.decode("utf-8"))
    except tomllib.TOMLDecodeError as error:
        raise RenderError(f"invalid overlay TOML {path}: {error}") from error

    if raw.get("schema_version") != 1:
        raise RenderError("overlay schema_version must be 1")
    core_sections_raw = raw.get("core_sections")
    if not isinstance(core_sections_raw, list) or not all(
        isinstance(item, str) and item for item in core_sections_raw
    ):
        raise RenderError("overlay core_sections must be a non-empty string array")
    if not core_sections_raw or len(core_sections_raw) != len(set(core_sections_raw)):
        raise RenderError("overlay core_sections must be non-empty and unique")

    general = _expect_table(raw, "general")
    host = _expect_table(raw, "host")
    mitm = _expect_table(raw, "mitm")
    rules = _expect_table(raw, "rules")
    budget_raw = _expect_table(raw, "budget")

    host_insert_before = host.get("insert_before")
    if not isinstance(host_insert_before, str) or not host_insert_before:
        raise RenderError("overlay host.insert_before must be a non-empty string")

    fragment_specs: list[tuple[str, str, bytes]] = []
    fragment_values: dict[str, tuple[str, ...]] = {}
    for role in ("prepend", "before_terminal"):
        reference = rules.get(role)
        if not isinstance(reference, str):
            raise RenderError(f"overlay rules.{role} must be a string")
        fragment_path = _resolve_fragment(path, reference)
        fragment_bytes = read_strict_file(fragment_path)
        fragment_specs.append((f"rules.{role}", reference, fragment_bytes))
        fragment_values[role] = _fragment_lines(fragment_bytes, str(fragment_path))

    anchors: dict[str, tuple[str, ...]] = {}
    for name in ("insertion_anchor", "terminal_anchor"):
        value = rules.get(name)
        if not isinstance(value, str):
            raise RenderError(f"overlay rules.{name} must be a string")
        normalized = normalize_rule(value)
        if normalized is None:
            raise RenderError(f"overlay rules.{name} must be an active rule")
        anchors[name] = normalized

    expected_budget_keys = {
        "max_added_lines",
        "max_removed_lines",
        "max_modified_lines",
        "max_output_growth_bytes",
    }
    if set(budget_raw) != expected_budget_keys:
        raise RenderError(
            "overlay budget must define exactly " + ", ".join(sorted(expected_budget_keys))
        )
    budget: dict[str, int] = {}
    for key, value in budget_raw.items():
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise RenderError(f"overlay budget {key} must be a non-negative integer")
        budget[key] = value

    return Overlay(
        path=path,
        digest=_hash_overlay(overlay_bytes, fragment_specs),
        core_sections=tuple(core_sections_raw),
        general_ensure=_expect_string_map(general, "ensure"),
        general_append_unique=_expect_string_list_map(general, "append_unique"),
        host_insert_before=host_insert_before,
        host_ensure=_expect_string_map(host, "ensure"),
        mitm_ensure=_expect_string_map(mitm, "ensure"),
        mitm_append_unique=_expect_string_list_map(mitm, "append_unique"),
        rules_prepend=fragment_values["prepend"],
        rules_before_terminal=fragment_values["before_terminal"],
        insertion_anchor=anchors["insertion_anchor"],
        terminal_anchor=anchors["terminal_anchor"],
        budget=budget,
    )


def normalize_rule(line: str) -> tuple[str, ...] | None:
    stripped = line.strip()
    if not stripped or stripped.startswith(("#", ";")) or "," not in stripped:
        return None
    first_field = stripped.split(",", 1)[0]
    if "=" in first_field:
        return None
    fields = tuple(field.strip() for field in stripped.split(","))
    if len(fields) < 2 or not fields[0] or any(not field for field in fields):
        return None
    return fields


def _assignment_index(section: Section) -> dict[str, tuple[int, str]]:
    assignments: dict[str, tuple[int, str]] = {}
    for index, line in enumerate(section.body):
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";")):
            continue
        match = ASSIGNMENT.fullmatch(line)
        if not match:
            continue
        key = match.group(1).strip()
        value = match.group(2).strip()
        if key in assignments:
            raise RenderError(f"duplicate key {key!r} in [{section.name}]")
        assignments[key] = (index, value)
    return assignments


def _named_assignments(
    lines: Sequence[str], source: str, names: set[str] | None = None
) -> dict[str, str]:
    assignments: dict[str, str] = {}
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";")):
            continue
        match = ASSIGNMENT.fullmatch(line)
        if match is None:
            continue
        key = match.group(1).strip()
        if names is not None and key not in names:
            continue
        value = match.group(2).strip()
        if key in assignments:
            raise RenderError(f"duplicate named assignment {key!r} in {source}")
        assignments[key] = value
    return assignments


def _insert_before_trailing_blanks(body: list[str], lines: Sequence[str]) -> None:
    index = len(body)
    while index > 0 and not body[index - 1]:
        index -= 1
    body[index:index] = lines


def _apply_key_overlay(
    section: Section,
    ensure: Mapping[str, str],
    append_unique: Mapping[str, tuple[str, ...]],
    stats: RenderStats,
    count_general_values: bool = False,
) -> None:
    assignments = _assignment_index(section)
    additions: list[str] = []

    for key, expected in ensure.items():
        existing = assignments.get(key)
        if existing is None:
            additions.append(f"{key} = {expected}")
            if count_general_values:
                stats.general_values_added += 1
        elif existing[1] != expected:
            raise RenderError(
                f"conflicting [{section.name}] value for {key!r}: "
                f"expected {expected!r}, found {existing[1]!r}"
            )

    for key, required_values in append_unique.items():
        existing = assignments.get(key)
        if existing is None:
            additions.append(f"{key} = {', '.join(required_values)}")
            stats.list_values_appended += len(required_values)
            continue
        index, raw_value = existing
        values = [value.strip() for value in raw_value.split(",") if value.strip()]
        missing = [value for value in required_values if value not in values]
        if missing:
            section.body[index] = (
                f"{key} = {', '.join([*values, *missing])}"
            )
            stats.modified_lines += 1
            stats.list_values_appended += len(missing)

    if additions:
        _insert_before_trailing_blanks(section.body, additions)
        stats.added_lines += len(additions)


def _contains_fragment(body: Sequence[str], fragment: Sequence[str]) -> bool:
    if len(fragment) > len(body):
        return False
    return any(
        tuple(body[index : index + len(fragment)]) == tuple(fragment)
        for index in range(len(body) - len(fragment) + 1)
    )


def _apply_rule_overlay(
    section: Section, overlay: Overlay, stats: RenderStats
) -> None:
    terminal_indexes = [
        index
        for index, line in enumerate(section.body)
        if normalize_rule(line) == overlay.terminal_anchor
    ]
    if len(terminal_indexes) != 1:
        raise RenderError(
            "terminal anchor "
            f"{','.join(overlay.terminal_anchor)!r} must occur exactly once; "
            f"found {len(terminal_indexes)}"
        )
    terminal_index = terminal_indexes[0]

    insertion_indexes = [
        index
        for index, line in enumerate(section.body)
        if normalize_rule(line) == overlay.insertion_anchor
    ]
    if len(insertion_indexes) != 1:
        raise RenderError(
            "insertion anchor "
            f"{','.join(overlay.insertion_anchor)!r} must occur exactly once; "
            f"found {len(insertion_indexes)}"
        )
    insertion_index = insertion_indexes[0]
    if insertion_index >= terminal_index:
        raise RenderError("insertion anchor must occur before the terminal anchor")
    if any(normalize_rule(line) is not None for line in section.body[terminal_index + 1 :]):
        raise RenderError("terminal anchor is not the last active rule")

    prepend_block = (*overlay.rules_prepend, "")
    prepend_is_canonical = tuple(section.body[: len(prepend_block)]) == prepend_block
    if not prepend_is_canonical:
        if _contains_fragment(section.body, overlay.rules_prepend):
            raise RenderError("rules.prepend fragment is present outside its canonical prefix")
        section.body[0:0] = prepend_block
        stats.added_lines += len(prepend_block)
        stats.rule_fragments_added += 1
        insertion_index += len(prepend_block)

    before_block = (*overlay.rules_before_terminal, "")
    before_start = insertion_index - len(before_block)
    before_is_canonical = (
        before_start >= 0
        and tuple(section.body[before_start:insertion_index]) == before_block
    )
    fragment_assignments = _named_assignments(
        overlay.rules_before_terminal, "rules.before_terminal"
    )
    existing_assignments = _named_assignments(
        section.body, "[Rule]", set(fragment_assignments)
    )
    for key, expected in fragment_assignments.items():
        existing = existing_assignments.get(key)
        if existing is not None and existing != expected:
            raise RenderError(
                f"conflicting Rule assignment {key!r}: expected "
                f"{expected!r}, found {existing!r}"
            )
        if existing is not None and not before_is_canonical:
            raise RenderError(
                f"Rule assignment {key!r} is outside its canonical insertion position"
            )

    if not before_is_canonical:
        if _contains_fragment(section.body, overlay.rules_before_terminal):
            raise RenderError(
                "rules.before_terminal fragment is outside its canonical insertion position"
            )
        section.body[insertion_index:insertion_index] = before_block
        stats.added_lines += len(before_block)
        stats.rule_fragments_added += 1

    seen: set[tuple[str, ...]] = set()
    deduplicated: list[str] = []
    for line in section.body:
        key = normalize_rule(line)
        if key is not None and key in seen:
            stats.removed_lines += 1
            stats.duplicate_rules_removed += 1
            continue
        if key is not None:
            seen.add(key)
        deduplicated.append(line)
    section.body = deduplicated


def _ensure_host_section(document: Document, overlay: Overlay, stats: RenderStats) -> Section:
    matches = [section for section in document.sections if section.name == "Host"]
    if len(matches) > 1:
        raise RenderError(f"expected at most one [Host] section, found {len(matches)}")
    if matches:
        return matches[0]

    insert_indexes = [
        index
        for index, section in enumerate(document.sections)
        if section.name == overlay.host_insert_before
    ]
    if len(insert_indexes) != 1:
        raise RenderError(
            f"host insertion anchor [{overlay.host_insert_before}] must occur exactly once"
        )
    host = Section(name="Host", body=[""])
    document.sections.insert(insert_indexes[0], host)
    stats.sections_added += 1
    stats.added_lines += 2  # Section header and separating blank line.
    return host


def _check_budget(stats: RenderStats, overlay: Overlay) -> None:
    checks = {
        "added lines": (stats.added_lines, overlay.budget["max_added_lines"]),
        "removed lines": (stats.removed_lines, overlay.budget["max_removed_lines"]),
        "modified lines": (stats.modified_lines, overlay.budget["max_modified_lines"]),
        "output byte growth": (
            max(0, stats.output_growth_bytes),
            overlay.budget["max_output_growth_bytes"],
        ),
    }
    exceeded = [
        f"{name} {actual} exceeds {maximum}"
        for name, (actual, maximum) in checks.items()
        if actual > maximum
    ]
    if exceeded:
        raise RenderError("change budget exceeded: " + "; ".join(exceeded))


def render_bytes(base: bytes, overlay: Overlay) -> RenderResult:
    document = parse_document(base)
    section_names = {section.name for section in document.sections}
    missing = [name for name in overlay.core_sections if name not in section_names]
    if missing:
        raise RenderError("missing core sections: " + ", ".join(f"[{name}]" for name in missing))

    rule_section = document.section("Rule")
    stats = RenderStats(
        base_bytes=len(base),
        base_lines=base.count(b"\n"),
        base_rule_count=sum(
            normalize_rule(line) is not None for line in rule_section.body
        ),
    )
    _apply_key_overlay(
        document.section("General"),
        overlay.general_ensure,
        overlay.general_append_unique,
        stats,
        count_general_values=True,
    )
    host = _ensure_host_section(document, overlay, stats)
    _apply_key_overlay(host, overlay.host_ensure, {}, stats)
    _apply_key_overlay(
        document.section("MITM"),
        overlay.mitm_ensure,
        overlay.mitm_append_unique,
        stats,
    )
    _apply_rule_overlay(rule_section, overlay, stats)
    output_rule_keys = {
        key for line in rule_section.body if (key := normalize_rule(line)) is not None
    }
    stats.output_rule_count = len(
        [line for line in rule_section.body if normalize_rule(line) is not None]
    )
    stats.output_unique_rule_count = len(output_rule_keys)

    output = document.serialize()
    decode_strict_text(output, "rendered output")
    stats.output_bytes = len(output)
    stats.output_lines = output.count(b"\n")
    stats.output_growth_bytes = len(output) - len(base)
    if stats.output_rule_count != stats.output_unique_rule_count:
        raise RenderError("internal rule uniqueness accounting mismatch")
    if stats.output_lines != stats.base_lines + stats.added_lines - stats.removed_lines:
        raise RenderError("internal line accounting mismatch")
    _check_budget(stats, overlay)
    return RenderResult(
        output=output,
        overlay_sha256=overlay.digest,
        stats=stats.as_dict(),
    )


def build_state(result: RenderResult, base: bytes, upstream_commit: str) -> dict[str, Any]:
    if re.fullmatch(r"[0-9a-f]{40}", upstream_commit) is None:
        raise RenderError("upstream commit must be a lowercase 40-character commit ID")
    return {
        "schema_version": 1,
        "upstream_commit": upstream_commit,
        "base_sha256": sha256(base),
        "overlay_sha256": result.overlay_sha256,
        "output_sha256": sha256(result.output),
        "stats": dict(result.stats),
    }


def encode_state(state: Mapping[str, Any]) -> bytes:
    return (json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = (path.stat().st_mode & 0o777) if path.exists() else 0o644
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary_name, mode)
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def render_files(
    input_path: Path,
    output_path: Path,
    state_path: Path,
    overlay_path: Path,
    upstream_commit: str,
) -> dict[str, Any]:
    base = read_strict_file(input_path)
    overlay = load_overlay(overlay_path)
    result = render_bytes(base, overlay)
    state = build_state(result, base, upstream_commit)
    _atomic_write(output_path, result.output)
    _atomic_write(state_path, encode_state(state))
    return state


def check_files(input_path: Path, output_path: Path, overlay_path: Path) -> RenderResult:
    base = read_strict_file(input_path)
    actual = read_strict_file(output_path)
    result = render_bytes(base, load_overlay(overlay_path))
    if actual != result.output:
        raise RenderError(
            "rendered candidate differs from output: "
            f"expected sha256 {sha256(result.output)}, found {sha256(actual)}"
        )
    return result


def _load_state(path: Path) -> Mapping[str, Any]:
    data = read_strict_file(path)
    try:
        state = json.loads(data)
    except json.JSONDecodeError as error:
        raise RenderError(f"invalid state JSON {path}: {error}") from error
    if not isinstance(state, dict):
        raise RenderError("state must be a schema_version 1 JSON object")
    required = {
        "schema_version",
        "upstream_commit",
        "base_sha256",
        "overlay_sha256",
        "output_sha256",
        "stats",
    }
    if set(state) != required:
        raise RenderError("state has an invalid top-level key set")
    if type(state["schema_version"]) is not int or state["schema_version"] != 1:
        raise RenderError("state schema_version must be integer 1")
    if (
        not isinstance(state["upstream_commit"], str)
        or re.fullmatch(r"[0-9a-f]{40}", state["upstream_commit"]) is None
    ):
        raise RenderError("state upstream_commit must be a lowercase 40-character commit ID")
    for key in ("base_sha256", "overlay_sha256", "output_sha256"):
        value = state[key]
        if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise RenderError(f"state {key} must be a lowercase SHA-256 digest")

    stats = state["stats"]
    expected_stats = set(RenderStats().as_dict())
    if not isinstance(stats, dict) or set(stats) != expected_stats:
        raise RenderError("state stats has an invalid key set")
    for key, value in stats.items():
        if type(value) is not int:
            raise RenderError(f"state stats.{key} must be an integer")
        if key != "output_growth_bytes" and value < 0:
            raise RenderError(f"state stats.{key} must be non-negative")
    return state


def verify_state_files(
    output_path: Path,
    state_path: Path,
) -> Mapping[str, Any]:
    actual = read_strict_file(output_path)
    recorded = _load_state(state_path)
    actual_digest = sha256(actual)
    if actual_digest != recorded["output_sha256"]:
        raise RenderError(
            "output drift detected: "
            f"expected sha256 {recorded['output_sha256']}, found {actual_digest}"
        )
    return recorded


def validate_history_records(
    bootstrap_commit: str,
    tip_commit: str,
    commits: Sequence[HistoryCommit],
    expected_subject: str = EXPECTED_MERGE_SUBJECT,
) -> HistoryValidation:
    expected_first_parent = bootstrap_commit
    for commit in commits:
        if len(commit.parents) != 2:
            raise RenderError(
                f"first-parent commit {commit.oid} must be a two-parent merge; "
                f"found {len(commit.parents)} parents"
            )
        if commit.parents[0] != expected_first_parent:
            raise RenderError(
                f"broken first-parent chain at {commit.oid}: expected "
                f"{expected_first_parent}, found {commit.parents[0]}"
            )
        if commit.subject != expected_subject:
            raise RenderError(
                f"unexpected merge subject at {commit.oid}: expected "
                f"{expected_subject!r}, found {commit.subject!r}"
            )
        expected_first_parent = commit.oid
    if expected_first_parent != tip_commit:
        raise RenderError(
            f"first-parent history ended at {expected_first_parent}, expected {tip_commit}"
        )
    return HistoryValidation(bootstrap_commit, tip_commit, len(commits))


def _git(
    repository: Path, *arguments: str, check: bool = True
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["git", "-C", str(repository), *arguments],
            check=check,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        detail = ""
        if isinstance(error, subprocess.CalledProcessError):
            detail = error.stderr.strip()
        raise RenderError(
            f"git {' '.join(arguments)} failed" + (f": {detail}" if detail else "")
        ) from error


def validate_bootstrap_history(
    repository: Path,
    tip: str,
    bootstrap: str = BOOTSTRAP_COMMIT,
) -> HistoryValidation:
    repository = repository.resolve()
    bootstrap_oid = _git(
        repository, "rev-parse", "--verify", f"{bootstrap}^{{commit}}"
    ).stdout.strip()
    tip_oid = _git(
        repository, "rev-parse", "--verify", f"{tip}^{{commit}}"
    ).stdout.strip()
    ancestor = _git(
        repository,
        "merge-base",
        "--is-ancestor",
        bootstrap_oid,
        tip_oid,
        check=False,
    )
    if ancestor.returncode == 1:
        raise RenderError(f"bootstrap commit {bootstrap_oid} is not an ancestor of {tip_oid}")
    if ancestor.returncode != 0:
        raise RenderError(f"git merge-base --is-ancestor failed: {ancestor.stderr.strip()}")

    history_lines = _git(
        repository,
        "log",
        "--first-parent",
        "--reverse",
        "--format=%H%x00%P%x00%s",
        f"{bootstrap_oid}..{tip_oid}",
    ).stdout.splitlines()
    commits = []
    for line in history_lines:
        if not line:
            continue
        fields = line.split("\0", 2)
        if len(fields) != 3:
            raise RenderError(f"cannot parse first-parent history record: {line!r}")
        oid, raw_parents, subject = fields
        commits.append(HistoryCommit(oid, tuple(raw_parents.split()), subject))
    return validate_history_records(bootstrap_oid, tip_oid, commits)


def _add_candidate_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--input", type=Path, required=True, help="upstream config")
    parser.add_argument("--output", type=Path, required=True, help="rendered config")
    parser.add_argument("--overlay", type=Path, default=DEFAULT_OVERLAY)


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    render_parser = subparsers.add_parser("render", help="render an upstream config")
    _add_candidate_arguments(render_parser)
    render_parser.add_argument("--state", type=Path, required=True, help="render state JSON")
    render_parser.add_argument("--upstream-commit", required=True)

    check_parser = subparsers.add_parser("check", help="check committed output bytes")
    _add_candidate_arguments(check_parser)

    verify_parser = subparsers.add_parser("verify-state", help="verify output provenance")
    verify_parser.add_argument("--output", type=Path, required=True, help="rendered config")
    verify_parser.add_argument("--state", type=Path, required=True, help="render state JSON")

    history_parser = subparsers.add_parser(
        "validate-history", help="validate the my-rules bootstrap history"
    )
    history_parser.add_argument("--repository", type=Path, default=REPOSITORY_ROOT)
    history_parser.add_argument("--tip", required=True)
    history_parser.add_argument("--bootstrap", default=BOOTSTRAP_COMMIT)
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    parser = build_argument_parser()
    options = parser.parse_args(arguments)
    try:
        if options.command == "render":
            payload: Mapping[str, Any] = render_files(
                options.input,
                options.output,
                options.state,
                options.overlay,
                options.upstream_commit,
            )
        elif options.command == "check":
            result = check_files(options.input, options.output, options.overlay)
            payload = {
                "output_sha256": sha256(result.output),
                "overlay_sha256": result.overlay_sha256,
                "stats": dict(result.stats),
            }
        elif options.command == "verify-state":
            payload = verify_state_files(options.output, options.state)
        else:
            payload = validate_bootstrap_history(
                options.repository, options.tip, options.bootstrap
            ).as_dict()
    except RenderError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
