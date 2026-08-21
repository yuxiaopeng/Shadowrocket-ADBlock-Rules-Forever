#!/usr/bin/env python3
"""Render repository-owned Shadowrocket customizations onto an upstream config."""

from __future__ import annotations

import argparse
import difflib
import hashlib
import ipaddress
import json
import os
import re
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CUSTOM_CONFIG = (
    REPOSITORY_ROOT
    / "automation"
    / "my-rules"
    / "sr_top500_banlist_ad"
    / "custom.conf"
)
SECTION_HEADER = re.compile(r"^\[([^\[\]]+)\]$")
ASSIGNMENT = re.compile(r"^([^=]+?)\s*=\s*(.*)$")
DOMAIN_RULE_TYPES = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD"}
RULE_TYPES = {
    *DOMAIN_RULE_TYPES,
    "DOMAIN-SET",
    "IP-CIDR",
    "IP-CIDR6",
    "GEOIP",
    "USER-AGENT",
    "URL-REGEX",
    "PROCESS-NAME",
    "PROCESS-PATH",
    "DEST-PORT",
    "DST-PORT",
    "SRC-IP",
    "SRC-PORT",
    "IN-PORT",
    "PROTOCOL",
    "RULE-SET",
    "SCRIPT",
    "AND",
    "OR",
    "NOT",
}
COMPOUND_DOMAIN_MATCHER = re.compile(
    r"(?i)(?<![A-Z0-9-])(DOMAIN(?:-SUFFIX|-KEYWORD)?),([^,()]+)"
)
COMPOUND_PROTOCOL_MATCHER = re.compile(
    r"(?i)(?<![A-Z0-9-])PROTOCOL,([^,()]+)"
)
COMPOUND_RULE_TYPE = re.compile(
    r"(?i)(?<![A-Z0-9-])("
    + "|".join(sorted(RULE_TYPES, key=len, reverse=True))
    + r")(?=,)"
)
UNION_GENERAL_KEYS = {"skip-proxy", "always-real-ip"}
CASEFOLD_MATCHER_TYPES = {"GEOIP", "PROTOCOL"}
CASEFOLD_MODIFIERS = {"no-resolve", "extended-matching", "pre-matching"}
CUSTOM_SECTIONS = ("General", "Rule", "Host", "URL Rewrite", "MITM")
MAX_ADDED_LINES = 64
MAX_REMOVED_LINES = 512
MAX_MODIFIED_LINES = 32
MAX_OUTPUT_GROWTH_BYTES = 65536


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

    def optional_section(self, name: str) -> Section | None:
        matches = [section for section in self.sections if section.name == name]
        if len(matches) > 1:
            raise RenderError(f"expected at most one [{name}] section, found {len(matches)}")
        return matches[0] if matches else None

    def serialize(self) -> bytes:
        lines = list(self.preamble)
        for section in self.sections:
            lines.append(f"[{section.name}]")
            lines.extend(section.body)
        return ("\n".join(lines) + "\n").encode("utf-8")


@dataclass(frozen=True)
class CustomConfig:
    digest: str
    document: Document

    def section(self, name: str) -> Section:
        return self.document.section(name)


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
        return dict(self.__dict__)


@dataclass(frozen=True)
class RenderResult:
    output: bytes
    custom_sha256: str
    stats: Mapping[str, int]


@dataclass(frozen=True)
class RuleEntry:
    kind: str
    identity: tuple[str, ...] | str | None
    assignment_key: str | None = None


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
                raise RenderError(f"{source}:{line_number}: duplicate [{name}] section")
            seen.add(name)
            current = Section(name=name, body=[])
            sections.append(current)
        elif current is None:
            preamble.append(line)
        else:
            current.body.append(line)
    return Document(preamble=preamble, sections=sections)


def _is_comment_or_blank(line: str) -> bool:
    stripped = line.strip()
    return not stripped or stripped.startswith(("#", ";"))


def _assignment(line: str) -> tuple[str, str] | None:
    if _is_comment_or_blank(line):
        return None
    match = ASSIGNMENT.fullmatch(line)
    if match is None:
        return None
    return match.group(1).strip(), match.group(2).strip()


def _assignment_index(section: Section, source: str) -> dict[str, tuple[int, str]]:
    assignments: dict[str, tuple[int, str]] = {}
    for index, line in enumerate(section.body):
        parsed = _assignment(line)
        if parsed is None:
            continue
        key, value = parsed
        if key in assignments:
            raise RenderError(f"duplicate key {key!r} in {source} [{section.name}]")
        assignments[key] = (index, value)
    return assignments


def _require_assignment_section(section: Section, source: str) -> None:
    _assignment_index(section, source)
    for line_number, line in enumerate(section.body, start=1):
        if not _is_comment_or_blank(line) and _assignment(line) is None:
            raise RenderError(
                f"{source} [{section.name}] line {line_number} must be an assignment"
            )


def _trim_blank_edges(lines: Sequence[str]) -> list[str]:
    start = 0
    end = len(lines)
    while start < end and not lines[start]:
        start += 1
    while end > start and not lines[end - 1]:
        end -= 1
    return list(lines[start:end])


def _custom_comment_lines(section: Section) -> set[str]:
    return {
        line.strip()
        for line in section.body
        if line.strip().startswith(("#", ";"))
    }


def _compose_custom_first(
    custom_lines: Sequence[str], upstream_lines: Sequence[str], trailing_blank: bool
) -> list[str]:
    custom = _trim_blank_edges(custom_lines)
    upstream = _trim_blank_edges(upstream_lines)
    body = custom
    if custom and upstream:
        body.append("")
    body.extend(upstream)
    if trailing_blank:
        body.append("")
    return body


def _dedupe_values(values: Sequence[str], case_insensitive: bool = False) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        normalized = value.casefold() if case_insensitive else value
        if normalized not in seen:
            seen.add(normalized)
            result.append(value)
    return result


def _comma_values(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _render_assignment_section(
    upstream: Section,
    custom: Section,
    union_keys: set[str] = frozenset(),
    case_insensitive_union_keys: set[str] = frozenset(),
) -> tuple[list[str], int, int, list[str]]:
    upstream_assignments = _assignment_index(upstream, "upstream")
    custom_assignments = _assignment_index(custom, "custom config")
    custom_comments = _custom_comment_lines(custom)
    rendered_custom: list[str] = []
    values_added = 0
    list_values_added = 0

    for line in custom.body:
        parsed = _assignment(line)
        if parsed is None:
            rendered_custom.append(line)
            continue
        key, custom_value = parsed
        if key not in union_keys:
            rendered_custom.append(line)
            if key not in upstream_assignments:
                values_added += 1
            continue
        custom_values = _comma_values(custom_value)
        upstream_values = _comma_values(upstream_assignments.get(key, (-1, ""))[1])
        case_insensitive = key in case_insensitive_union_keys
        merged = _dedupe_values(
            [*custom_values, *upstream_values], case_insensitive=case_insensitive
        )
        upstream_keys = {
            value.casefold() if case_insensitive else value for value in upstream_values
        }
        list_values_added += sum(
            (value.casefold() if case_insensitive else value) not in upstream_keys
            for value in custom_values
        )
        rendered_custom.append(f"{key} = {', '.join(merged)}")
        if key not in upstream_assignments:
            values_added += 1

    residual: list[str] = []
    for line in upstream.body:
        parsed = _assignment(line)
        if parsed is not None and parsed[0] in custom_assignments:
            continue
        if line.strip() in custom_comments:
            continue
        residual.append(line)
    return rendered_custom, values_added, list_values_added, residual


def _top_level_comma_fields(line: str, source: str) -> tuple[str, ...]:
    fields: list[str] = []
    start = 0
    depth = 0
    for index, character in enumerate(line):
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth < 0:
                raise RenderError(f"{source}: unbalanced parentheses")
        elif character == "," and depth == 0:
            fields.append(line[start:index].strip())
            start = index + 1
    if depth != 0:
        raise RenderError(f"{source}: unbalanced parentheses")
    fields.append(line[start:].strip())
    if any(not field for field in fields):
        raise RenderError(f"{source}: empty top-level rule field")
    return tuple(fields)


def _normalize_compound_matcher(value: str) -> str:
    normalized = re.sub(r"\s*([(),])\s*", r"\1", value.strip())
    normalized = COMPOUND_DOMAIN_MATCHER.sub(
        lambda match: f"{match.group(1).upper()},{match.group(2).casefold()}",
        normalized,
    )
    normalized = COMPOUND_PROTOCOL_MATCHER.sub(
        lambda match: f"PROTOCOL,{match.group(1).casefold()}", normalized
    )
    return COMPOUND_RULE_TYPE.sub(lambda match: match.group(1).upper(), normalized)


def _normalize_rule_matcher(rule_type: str, matcher: str, source: str) -> str:
    if rule_type in DOMAIN_RULE_TYPES or rule_type in CASEFOLD_MATCHER_TYPES:
        return matcher.casefold()
    if rule_type in {"IP-CIDR", "IP-CIDR6"}:
        try:
            return str(ipaddress.ip_network(matcher, strict=False))
        except ValueError as error:
            raise RenderError(f"{source}: invalid {rule_type} matcher {matcher!r}") from error
    if rule_type in {"AND", "OR", "NOT"}:
        return _normalize_compound_matcher(matcher)
    return matcher


def parse_rule_entry(line: str, source: str, custom: bool = False) -> RuleEntry:
    stripped = line.strip()
    if not stripped or stripped.startswith(("#", ";")):
        return RuleEntry("trivia", None)
    assignment = _assignment(line)
    first_comma = stripped.find(",")
    equals = stripped.find("=")
    if assignment is not None and (first_comma < 0 or equals < first_comma):
        return RuleEntry("assignment", assignment[0], assignment[0])

    first = stripped.split(",", 1)[0].strip().upper()
    if first == "FINAL":
        fields = _top_level_comma_fields(stripped, source)
        if len(fields) != 2:
            raise RenderError(f"{source}: FINAL must contain exactly a policy/action")
        return RuleEntry("final", ("FINAL",))
    if first in RULE_TYPES:
        fields = _top_level_comma_fields(stripped, source)
        if len(fields) < 3:
            raise RenderError(
                f"{source}: {fields[0]} must contain a matcher and policy/action"
            )
        rule_type = fields[0].upper()
        matcher = _normalize_rule_matcher(rule_type, fields[1], source)
        modifiers = tuple(
            field.casefold() if field.casefold() in CASEFOLD_MODIFIERS else field
            for field in fields[3:]
        )
        identity = (rule_type, matcher, *modifiers)
        return RuleEntry("structured", identity)
    if custom:
        raise RenderError(f"{source}: unknown custom rule type {first!r}")
    return RuleEntry("opaque", stripped)


def _validate_custom_rules(section: Section) -> None:
    identities: set[tuple[str, ...]] = set()
    assignments: set[str] = set()
    final_count = 0
    for index, line in enumerate(section.body, start=1):
        entry = parse_rule_entry(line, f"custom [Rule] line {index}", custom=True)
        if entry.kind == "structured":
            assert isinstance(entry.identity, tuple)
            if entry.identity in identities:
                raise RenderError(
                    f"custom [Rule] contains duplicate matcher identity at line {index}"
                )
            identities.add(entry.identity)
        elif entry.kind == "assignment":
            assert entry.assignment_key is not None
            if entry.assignment_key in assignments:
                raise RenderError(
                    f"custom [Rule] contains duplicate named assignment {entry.assignment_key!r}"
                )
            assignments.add(entry.assignment_key)
        elif entry.kind == "final":
            final_count += 1
            if final_count > 1:
                raise RenderError("custom [Rule] contains more than one FINAL rule")


def _validate_custom_rewrites(section: Section) -> None:
    seen: set[str] = set()
    for index, line in enumerate(section.body, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";")):
            continue
        identity = stripped.split(None, 1)[0]
        if identity in seen:
            raise RenderError(
                f"custom [URL Rewrite] contains duplicate identity {identity!r} at line {index}"
            )
        seen.add(identity)


def load_custom_config(path: Path = DEFAULT_CUSTOM_CONFIG) -> CustomConfig:
    path = path.resolve()
    data = read_strict_file(path)
    document = parse_document(data, str(path))
    allowed = {"Overlay", *CUSTOM_SECTIONS}
    unexpected = [section.name for section in document.sections if section.name not in allowed]
    if unexpected:
        raise RenderError(
            "custom config contains unsupported sections: "
            + ", ".join(f"[{name}]" for name in unexpected)
        )
    missing = [name for name in ("Overlay", *CUSTOM_SECTIONS) if document.optional_section(name) is None]
    if missing:
        raise RenderError(
            "custom config is missing sections: "
            + ", ".join(f"[{name}]" for name in missing)
        )
    overlay = document.section("Overlay")
    _require_assignment_section(overlay, "custom config")
    overlay_assignments = _assignment_index(overlay, "custom config")
    if set(overlay_assignments) != {"schema-version"}:
        raise RenderError("[Overlay] must define exactly schema-version")
    if overlay_assignments["schema-version"][1] != "1":
        raise RenderError("custom config schema-version must be 1")
    for name in ("General", "Host", "MITM"):
        _require_assignment_section(document.section(name), "custom config")
    _validate_custom_rules(document.section("Rule"))
    _validate_custom_rewrites(document.section("URL Rewrite"))
    return CustomConfig(digest=sha256(data), document=document)


def _merge_general(document: Document, custom: CustomConfig, stats: RenderStats) -> None:
    section = document.section("General")
    trailing_blank = bool(section.body and not section.body[-1])
    custom_lines, added, list_added, residual = _render_assignment_section(
        section,
        custom.section("General"),
        union_keys=UNION_GENERAL_KEYS,
        case_insensitive_union_keys=UNION_GENERAL_KEYS,
    )
    section.body = _compose_custom_first(custom_lines, residual, trailing_blank)
    stats.general_values_added += added
    stats.list_values_appended += list_added


def _merge_host(document: Document, custom: CustomConfig, stats: RenderStats) -> None:
    section = document.optional_section("Host")
    if section is None:
        rewrite_index = next(
            (index for index, item in enumerate(document.sections) if item.name == "URL Rewrite"),
            None,
        )
        if rewrite_index is None:
            raise RenderError("cannot create [Host] without a [URL Rewrite] section")
        section = Section("Host", [""])
        document.sections.insert(rewrite_index, section)
        stats.sections_added += 1
    trailing_blank = bool(section.body and not section.body[-1])
    custom_lines, _, _, residual = _render_assignment_section(
        section, custom.section("Host")
    )
    section.body = _compose_custom_first(custom_lines, residual, trailing_blank)


def _merge_mitm(document: Document, custom: CustomConfig, stats: RenderStats) -> None:
    section = document.section("MITM")
    trailing_blank = bool(section.body and not section.body[-1])
    custom_lines, _, list_added, residual = _render_assignment_section(
        section,
        custom.section("MITM"),
        union_keys={"hostname"},
        case_insensitive_union_keys={"hostname"},
    )
    section.body = _compose_custom_first(custom_lines, residual, trailing_blank)
    stats.list_values_appended += list_added


def _rewrite_identity(line: str) -> str | None:
    stripped = line.strip()
    if not stripped or stripped.startswith(("#", ";")):
        return None
    return stripped.split(None, 1)[0]


def _merge_url_rewrite(document: Document, custom: CustomConfig) -> None:
    section = document.section("URL Rewrite")
    custom_section = custom.section("URL Rewrite")
    trailing_blank = bool(section.body and not section.body[-1])
    custom_ids = {
        identity
        for line in custom_section.body
        if (identity := _rewrite_identity(line)) is not None
    }
    custom_comments = _custom_comment_lines(custom_section)
    seen = set(custom_ids)
    residual: list[str] = []
    for line in section.body:
        identity = _rewrite_identity(line)
        if identity is not None:
            if identity in seen:
                continue
            seen.add(identity)
        if line.strip() in custom_comments:
            continue
        residual.append(line)
    section.body = _compose_custom_first(custom_section.body, residual, trailing_blank)


def _rule_metrics(
    lines: Sequence[str], source: str, custom: bool = False
) -> tuple[int, set[tuple[str, ...] | str]]:
    identities: set[tuple[str, ...] | str] = set()
    count = 0
    for index, line in enumerate(lines, start=1):
        entry = parse_rule_entry(line, f"{source} line {index}", custom=custom)
        if entry.kind in {"structured", "opaque", "final"}:
            assert entry.identity is not None
            count += 1
            identities.add(entry.identity)
    return count, identities


def _merge_rules(document: Document, custom: CustomConfig) -> None:
    section = document.section("Rule")
    custom_section = custom.section("Rule")
    trailing_blank = bool(section.body and not section.body[-1])
    custom_comments = _custom_comment_lines(custom_section)
    custom_identities: set[tuple[str, ...]] = set()
    custom_assignments: set[str] = set()
    custom_final: str | None = None
    rendered_custom: list[str] = []

    for index, line in enumerate(custom_section.body, start=1):
        entry = parse_rule_entry(line, f"custom [Rule] line {index}", custom=True)
        if entry.kind == "structured":
            assert isinstance(entry.identity, tuple)
            custom_identities.add(entry.identity)
            rendered_custom.append(line)
        elif entry.kind == "assignment":
            assert entry.assignment_key is not None
            custom_assignments.add(entry.assignment_key)
            rendered_custom.append(line)
        elif entry.kind == "final":
            custom_final = line
        else:
            rendered_custom.append(line)

    seen_identities = set(custom_identities)
    seen_opaque: set[str] = set()
    seen_assignments = set(custom_assignments)
    upstream_final: str | None = None
    residual: list[str] = []
    for index, line in enumerate(section.body, start=1):
        entry = parse_rule_entry(line, f"upstream [Rule] line {index}")
        if upstream_final is not None and entry.kind != "trivia":
            raise RenderError("active Rule entry appears after terminal FINAL")
        if entry.kind == "trivia":
            if line.strip() not in custom_comments:
                residual.append(line)
            continue
        if entry.kind == "assignment":
            assert entry.assignment_key is not None
            if entry.assignment_key in seen_assignments:
                continue
            seen_assignments.add(entry.assignment_key)
            residual.append(line)
            continue
        if entry.kind == "final":
            if upstream_final is None:
                upstream_final = line
            continue
        if entry.kind == "structured":
            assert isinstance(entry.identity, tuple)
            if entry.identity in seen_identities:
                continue
            seen_identities.add(entry.identity)
            residual.append(line)
            continue
        assert isinstance(entry.identity, str)
        if entry.identity in seen_opaque:
            continue
        seen_opaque.add(entry.identity)
        residual.append(line)

    final = custom_final or upstream_final
    if final is None:
        raise RenderError("[Rule] must contain a FINAL rule in custom or upstream config")
    body = _compose_custom_first(rendered_custom, residual, False)
    body = _trim_blank_edges(body)
    if body:
        body.append("")
    body.append(final)
    if trailing_blank:
        body.append("")
    section.body = body


def _line_change_stats(base: bytes, output: bytes) -> tuple[int, int, int]:
    base_lines = decode_strict_text(base, "input").splitlines()
    output_lines = decode_strict_text(output, "rendered output").splitlines()
    added = removed = modified = 0
    matcher = difflib.SequenceMatcher(a=base_lines, b=output_lines, autojunk=False)
    for tag, start_a, end_a, start_b, end_b in matcher.get_opcodes():
        old_count = end_a - start_a
        new_count = end_b - start_b
        if tag == "insert":
            added += new_count
        elif tag == "delete":
            removed += old_count
        elif tag == "replace":
            overlap = min(old_count, new_count)
            modified += overlap
            removed += old_count - overlap
            added += new_count - overlap
    return added, removed, modified


def _check_budget(stats: RenderStats) -> None:
    checks = {
        "added lines": (stats.added_lines, MAX_ADDED_LINES),
        "removed lines": (stats.removed_lines, MAX_REMOVED_LINES),
        "modified lines": (stats.modified_lines, MAX_MODIFIED_LINES),
        "output byte growth": (
            max(0, stats.output_growth_bytes),
            MAX_OUTPUT_GROWTH_BYTES,
        ),
    }
    exceeded = [
        f"{name} {actual} exceeds {maximum}"
        for name, (actual, maximum) in checks.items()
        if actual > maximum
    ]
    if exceeded:
        raise RenderError("change budget exceeded: " + "; ".join(exceeded))


def render_bytes(base: bytes, custom: CustomConfig) -> RenderResult:
    document = parse_document(base)
    missing = [
        name
        for name in ("General", "Rule", "URL Rewrite", "MITM")
        if document.optional_section(name) is None
    ]
    if missing:
        raise RenderError("missing core sections: " + ", ".join(f"[{name}]" for name in missing))
    rule_section = document.section("Rule")
    base_rule_count, base_rule_identities = _rule_metrics(
        rule_section.body, "upstream [Rule]"
    )
    _, custom_rule_identities = _rule_metrics(
        custom.section("Rule").body, "custom [Rule]", custom=True
    )
    stats = RenderStats(
        base_bytes=len(base),
        base_lines=base.count(b"\n"),
        base_rule_count=base_rule_count,
    )

    _merge_general(document, custom, stats)
    _merge_rules(document, custom)
    _merge_host(document, custom, stats)
    _merge_url_rewrite(document, custom)
    _merge_mitm(document, custom, stats)

    output_rule_count, output_rule_identities = _rule_metrics(
        document.section("Rule").body, "rendered [Rule]"
    )
    stats.output_rule_count = output_rule_count
    stats.output_unique_rule_count = len(output_rule_identities)
    stats.duplicate_rules_removed = max(
        0,
        base_rule_count
        + len(custom_rule_identities - base_rule_identities)
        - output_rule_count,
    )
    output = document.serialize()
    decode_strict_text(output, "rendered output")
    stats.output_bytes = len(output)
    stats.output_lines = output.count(b"\n")
    stats.output_growth_bytes = len(output) - len(base)
    stats.added_lines, stats.removed_lines, stats.modified_lines = _line_change_stats(
        base, output
    )
    if stats.output_rule_count != stats.output_unique_rule_count:
        raise RenderError("internal rule uniqueness accounting mismatch")
    _check_budget(stats)
    return RenderResult(output=output, custom_sha256=custom.digest, stats=stats.as_dict())


def build_state(result: RenderResult, base: bytes, upstream_commit: str) -> dict[str, Any]:
    if re.fullmatch(r"[0-9a-f]{40}", upstream_commit) is None:
        raise RenderError("upstream commit must be a lowercase 40-character commit ID")
    return {
        "schema_version": 2,
        "upstream_commit": upstream_commit,
        "base_sha256": sha256(base),
        "custom_sha256": result.custom_sha256,
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
    custom_path: Path,
    upstream_commit: str,
) -> dict[str, Any]:
    base = read_strict_file(input_path)
    custom = load_custom_config(custom_path)
    result = render_bytes(base, custom)
    state = build_state(result, base, upstream_commit)
    _atomic_write(output_path, result.output)
    _atomic_write(state_path, encode_state(state))
    return state


def check_files(input_path: Path, output_path: Path, custom_path: Path) -> RenderResult:
    base = read_strict_file(input_path)
    actual = read_strict_file(output_path)
    result = render_bytes(base, load_custom_config(custom_path))
    if actual != result.output:
        raise RenderError(
            "rendered candidate differs from output: "
            f"expected sha256 {sha256(result.output)}, found {sha256(actual)}"
        )
    return result


def _validate_state_stats(stats: object) -> None:
    expected_stats = set(RenderStats().as_dict())
    if not isinstance(stats, dict) or set(stats) != expected_stats:
        raise RenderError("state stats has an invalid key set")
    for key, value in stats.items():
        if type(value) is not int:
            raise RenderError(f"state stats.{key} must be an integer")
        if key != "output_growth_bytes" and value < 0:
            raise RenderError(f"state stats.{key} must be non-negative")


def _load_state(path: Path) -> Mapping[str, Any]:
    data = read_strict_file(path)
    try:
        state = json.loads(data)
    except json.JSONDecodeError as error:
        raise RenderError(f"invalid state JSON {path}: {error}") from error
    if not isinstance(state, dict):
        raise RenderError("state must be a schema_version 1 or 2 JSON object")
    schema = state.get("schema_version")
    if type(schema) is not int or schema not in {1, 2}:
        raise RenderError("state schema_version must be integer 1 or 2")
    config_hash_key = "overlay_sha256" if schema == 1 else "custom_sha256"
    required = {
        "schema_version",
        "upstream_commit",
        "base_sha256",
        config_hash_key,
        "output_sha256",
        "stats",
    }
    if set(state) != required:
        raise RenderError("state has an invalid top-level key set")
    if (
        not isinstance(state["upstream_commit"], str)
        or re.fullmatch(r"[0-9a-f]{40}", state["upstream_commit"]) is None
    ):
        raise RenderError("state upstream_commit must be a lowercase 40-character commit ID")
    for key in ("base_sha256", config_hash_key, "output_sha256"):
        value = state[key]
        if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise RenderError(f"state {key} must be a lowercase SHA-256 digest")
    _validate_state_stats(state["stats"])
    return state


def verify_state_files(output_path: Path, state_path: Path) -> Mapping[str, Any]:
    actual = read_strict_file(output_path)
    recorded = _load_state(state_path)
    actual_digest = sha256(actual)
    if actual_digest != recorded["output_sha256"]:
        raise RenderError(
            "output drift detected: "
            f"expected sha256 {recorded['output_sha256']}, found {actual_digest}"
        )
    return recorded


def _add_candidate_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--input", type=Path, required=True, help="upstream config")
    parser.add_argument("--output", type=Path, required=True, help="rendered config")
    parser.add_argument(
        "--custom-config", type=Path, default=DEFAULT_CUSTOM_CONFIG, help="custom config"
    )


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
                options.custom_config,
                options.upstream_commit,
            )
        elif options.command == "check":
            result = check_files(options.input, options.output, options.custom_config)
            payload = {
                "output_sha256": sha256(result.output),
                "custom_sha256": result.custom_sha256,
                "stats": dict(result.stats),
            }
        else:
            payload = verify_state_files(options.output, options.state)
    except RenderError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
