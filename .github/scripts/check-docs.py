#!/usr/bin/env python3
"""Documentation integrity gate.

The repository states its documentation rules in `docs/dev/standards/`
(taxonomy, style, adr, invariants). A rule that nothing checks is a comment,
so this script is the enforcement mechanism behind those documents:

    DOC-001  every relative link resolves
    DOC-002  every `#anchor` resolves to a heading in its target
    DOC-003  every reference-style link label is defined
    DOC-004  public quadrants never link into `docs/dev/**`
    DOC-005  nothing under `docs/` refers to a tool-owned root file
    DOC-006  the Markdown at the repository root is limited to the whitelist
    DOC-007  every fenced block declares a supported language
    DOC-008  exactly one H1, and it is the first content line
    DOC-009  each quadrant index lists every document in its directory
    DOC-010  the ADR registry lists every ADR, in number order
    DOC-011  every ADR frontmatter matches the schema in `adr.md`
    DOC-012  every `ADR-NNNN` reference points at a file that exists
    DOC-013  every `INV-*` tag is ratified in an ADR, and the invariant
             index is complete in both directions
    DOC-014  the workspace version is stated consistently
    DOC-015  every postmortem has the required frontmatter, sections and
             verifiable action item
    DOC-016  every runbook has the required operational sections

Usage:
    python3 .github/scripts/check-docs.py [--root DIR]

Exit status is 0 when clean and 1 when any violation is reported. The output
is one line per violation, `<rule> <path>:<line> <message>`, so an editor can
jump to it and CI failure text is readable without a log viewer.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

# --- policy tables ---------------------------------------------------------

# Root Markdown that belongs to the documentation system. Anything else at the
# root must be tool-owned configuration, not prose.
ROOT_DOC_WHITELIST = {
    "README.md",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "LICENSE",
    "LICENSE.md",
    "SECURITY.md",
}

# Tool-owned root files: consumed by tooling, owned by the maintainer, and
# deliberately outside the documentation system. `docs/` must never reference
# one, and the taxonomy neither lists nor governs them (DOC-005).
TOOL_OWNED_ROOT_FILES = {"AGENTS.md"}

PUBLIC_QUADRANTS = ("docs/tutorials", "docs/how-to", "docs/reference", "docs/explanation")

INDEXED_QUADRANTS = {
    "docs/tutorials": "docs/tutorials/index.md",
    "docs/how-to": "docs/how-to/index.md",
    "docs/reference": "docs/reference/index.md",
    "docs/explanation": "docs/explanation/index.md",
    "docs/dev/standards": "docs/dev/standards/README.md",
    "docs/dev/postmortems": "docs/dev/postmortems/index.md",
    "docs/dev/runbooks": "docs/dev/runbooks/index.md",
}

FENCE_LANGUAGES = {
    "rust",
    "rust,no_run",
    "toml",
    "bash",
    "text",
    "yaml",
    "markdown",
    "json",
}

ADR_STATUSES = {"draft", "accepted", "superseded", "rejected"}
ADR_REQUIRED_FRONTMATTER = ("id", "title", "status", "date", "scope", "superseded_by")
POSTMORTEM_REQUIRED_FRONTMATTER = (
    "id",
    "severity",
    "status",
    "detected_by",
    "affected_versions",
    "invariants",
    "adrs",
    "trace_ids",
)
POSTMORTEM_REQUIRED_HEADINGS = (
    "Executive Summary",
    "Timeline of Events (UTC)",
    "Evidence",
    "Detection Gaps",
    "Trigger & Underlying Root Cause",
    "Action Items & Defense-in-Depth",
)
RUNBOOK_REQUIRED_HEADINGS = (
    "Target Subsystem & Reference Environment",
    "Core Protocol Rules & Invariants",
    "Diagnostic Playbook",
    "Do-Not-Regress Checklist",
)

INLINE_LINK = re.compile(r"(?<!\!)\[(?P<text>[^\]]*)\]\((?P<target>[^)\s]+)(?:\s+\"[^\"]*\")?\)")
IMAGE_LINK = re.compile(r"!\[(?P<text>[^\]]*)\]\((?P<target>[^)\s]+)\)")
REF_DEF = re.compile(r"^\[(?P<label>[^\]]+)\]:\s*(?P<target>\S+)\s*$")
# Explicit reference forms only: `[text][label]` and `[label][]`. A shortcut
# `[label]` with no definition is plain literal text in CommonMark (the way
# `[INV-WS-01]` is used in this repository), so it is not a broken link.
REF_USE = re.compile(r"(?<!!)\[[^\]]*\]\[(?P<label>[^\]]*)\]|(?<!!)\[(?P<self>[^\]]+)\]\[\]")
HEADING = re.compile(r"^(?P<hashes>#{1,6})\s+(?P<text>.+?)\s*$")
# A fence may be indented inside a list item (up to three spaces is also a
# valid top-level fence, and CommonMark allows the body to be indented to the
# list marker). Matching leading whitespace is what makes a fenced example in
# a numbered list visible to the language check instead of silently skipped.
FENCE = re.compile(r"^\s*(?P<fence>`{3,}|~{3,})(?P<info>.*)$")
ADR_ID = re.compile(r"ADR-(\d{4})")
ADR_FILE = re.compile(r"^(\d{4})-.+\.md$")
INV_TAG = re.compile(r"INV-[A-Z0-9]+-\d{2}")
INV_RANGE = re.compile(r"(INV-([A-Z0-9]+)-)(\d{2})\.\.(\d{2})")
INV_FAMILY = re.compile(r"INV-([A-Z0-9]+)-\d{2}")


def invariant_tags(text: str) -> set[str]:
    """Every `INV-*` tag in `text`, with range notation expanded.

    The invariant index writes a family compactly as `INV-TRANSPORT-00..04`;
    that is four tags, and a checker that cannot see the middle three would
    either miss a real gap or report a phantom one.
    """
    tags: set[str] = set()
    for match in INV_RANGE.finditer(text):
        prefix, _, low, high = match.group(1), match.group(2), match.group(3), match.group(4)
        for number in range(int(low), int(high) + 1):
            tags.add(f"{prefix}{number:02d}")
    tags |= set(INV_TAG.findall(text))
    return tags


@dataclass(frozen=True, order=True)
class Violation:
    rule: str
    path: str
    line: int
    message: str

    def render(self) -> str:
        return f"{self.rule} {self.path}:{self.line} {self.message}"


# --- parsing helpers -------------------------------------------------------


@dataclass
class Markdown:
    path: str
    lines: list[str]
    fences: list[tuple[int, str]]  # (line_no, info) for each opening fence
    headings: list[tuple[int, int, str]]  # (line_no, level, text)
    frontmatter_end: int  # 0 when the file has no YAML frontmatter

    def text(self) -> str:
        return "\n".join(self.lines)


def split_frontmatter(lines: list[str]) -> tuple[dict[str, str], int]:
    """Return `(frontmatter, lines_consumed)`; `({}, 0)` when there is none."""
    if not lines or lines[0].strip() != "---":
        return {}, 0
    for index in range(1, len(lines)):
        if lines[index].strip() == "---":
            fields: dict[str, str] = {}
            for raw in lines[1:index]:
                if ":" not in raw:
                    continue
                key, _, value = raw.partition(":")
                fields[key.strip()] = value.strip()
            return fields, index + 1
    return {}, 0


def parse_markdown(path: str, lines: list[str]) -> Markdown:
    _, consumed = split_frontmatter(lines)
    fences: list[tuple[int, str]] = []
    active: tuple[str, int] | None = None
    in_fence = [False] * len(lines)
    for index, raw in enumerate(lines):
        match = FENCE.match(raw)
        if active is None:
            if match:
                active = (match.group("fence")[0], len(match.group("fence")))
                fences.append((index + 1, match.group("info").strip()))
        else:
            char, length = active
            if match and match.group("fence")[0] == char and len(match.group("fence")) >= length:
                active = None
            in_fence[index] = True
    headings: list[tuple[int, int, str]] = []
    for index, raw in enumerate(lines):
        if in_fence[index] or index < consumed:
            continue
        match = HEADING.match(raw)
        if match:
            headings.append((index + 1, len(match.group("hashes")), match.group("text")))
    return Markdown(path, lines, fences, headings, consumed)


def slugify(text: str) -> str:
    text = text.strip().lower()
    text = re.sub(r"`", "", text)
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


def heading_slugs(doc: Markdown) -> set[str]:
    slugs: set[str] = set()
    seen: dict[str, int] = {}
    for _, _, text in doc.headings:
        base = slugify(text)
        if base in seen:
            seen[base] += 1
            slugs.add(f"{base}-{seen[base]}")
        else:
            seen[base] = 0
            slugs.add(base)
    return slugs


def is_external(target: str) -> bool:
    return bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", target)) or target.startswith("//")


# --- the checker -----------------------------------------------------------


class Checker:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.violations: list[Violation] = []
        self.markdown: dict[str, Markdown] = {}
        paths = sorted(root.glob("*.md")) + sorted(root.glob("docs/**/*.md"))
        for path in paths:
            rel = path.relative_to(root).as_posix()
            self.markdown[rel] = parse_markdown(rel, path.read_text(encoding="utf-8").split("\n"))
        self.workspace_version = self._workspace_version()

    # -- helpers ----------------------------------------------------------

    def report(self, rule: str, path: str, line: int, message: str) -> None:
        self.violations.append(Violation(rule, path, line, message))

    def _workspace_version(self) -> str:
        manifest = (self.root / "Cargo.toml").read_text(encoding="utf-8")
        section = manifest.split("[workspace.package]", 1)
        if len(section) != 2:
            return ""
        match = re.search(r'^version\s*=\s*"([^"]+)"', section[1], re.MULTILINE)
        return match.group(1) if match else ""

    def _is_public(self, path: str) -> bool:
        return any(path.startswith(prefix + "/") for prefix in PUBLIC_QUADRANTS)

    # -- DOC-001/002/003: links -------------------------------------------

    def check_links(self) -> None:
        for path, doc in self.markdown.items():
            labels = self._reference_labels(doc)
            fenced = self._fenced_lines(doc)
            for line_no, raw in enumerate(doc.lines, start=1):
                if line_no <= doc.frontmatter_end or line_no in fenced:
                    continue
                for pattern in (INLINE_LINK, IMAGE_LINK):
                    for match in pattern.finditer(raw):
                        self._check_link(path, line_no, match.group("target"))
                for match in REF_USE.finditer(raw):
                    label = (match.group("label") or match.group("self") or "").lower()
                    if label not in labels:
                        self.report(
                            "DOC-003",
                            path,
                            line_no,
                            f"reference link [{label}] has no definition",
                        )

    def _fenced_lines(self, doc: Markdown) -> set[int]:
        """Line numbers inside a fence: illustrative, never a real link."""
        fenced: set[int] = set()
        active: tuple[str, int] | None = None
        for index, raw in enumerate(doc.lines, start=1):
            match = FENCE.match(raw)
            if active is None:
                if match:
                    active = (match.group("fence")[0], len(match.group("fence")))
                    fenced.add(index)
                continue
            fenced.add(index)
            char, length = active
            if match and match.group("fence")[0] == char and len(match.group("fence")) >= length:
                active = None
        return fenced

    def _reference_labels(self, doc: Markdown) -> set[str]:
        labels: set[str] = set()
        for raw in doc.lines:
            match = REF_DEF.match(raw.strip())
            if match:
                labels.add(match.group("label").lower())
        return labels

    def _check_link(self, path: str, line_no: int, target: str) -> None:
        if not target or target.startswith("#") and len(target) == 1:
            return
        if is_external(target):
            return
        target_path, _, anchor = target.partition("#")
        target_path = target_path.split("?", 1)[0]
        if not target_path:
            self._check_anchor(path, line_no, path, anchor)
            return
        resolved = (Path(path).parent / target_path)
        resolved_str = self._normalise(resolved)
        absolute = self.root / resolved_str
        if target_path.endswith("/"):
            if not absolute.is_dir():
                self.report("DOC-001", path, line_no, f"link target is not a directory: {target}")
                return
        elif not absolute.exists():
            self.report("DOC-001", path, line_no, f"link target does not exist: {target}")
            return
        if anchor and resolved_str.endswith(".md"):
            self._check_anchor(path, line_no, resolved_str, anchor)
        if self._is_public(path) and (resolved_str.startswith("docs/dev/")):
            self.report(
                "DOC-004",
                path,
                line_no,
                f"public document links into the internal surface: {target}",
            )

    def _check_anchor(self, path: str, line_no: int, target: str, anchor: str) -> None:
        doc = self.markdown.get(target)
        if doc is None:
            return
        if anchor.lower() not in heading_slugs(doc):
            self.report("DOC-002", path, line_no, f"anchor #{anchor} is not a heading in {target}")

    def _normalise(self, path: Path) -> str:
        parts: list[str] = []
        for part in path.as_posix().split("/"):
            if part in ("", "."):
                continue
            if part == "..":
                if parts:
                    parts.pop()
                continue
            parts.append(part)
        return "/".join(parts)

    # -- DOC-005: tool-owned root files stay out of the documentation ------

    def check_tool_owned_isolation(self) -> None:
        for path, doc in self.markdown.items():
            if not path.startswith("docs/"):
                continue
            for line_no, raw in enumerate(doc.lines, start=1):
                for name in TOOL_OWNED_ROOT_FILES:
                    if name in raw:
                        self.report(
                            "DOC-005",
                            path,
                            line_no,
                            f"the documentation system must not reference the tool-owned {name}",
                        )

    # -- DOC-006: root whitelist ------------------------------------------

    def check_root_whitelist(self) -> None:
        for path in self.markdown:
            if "/" in path:
                continue
            if path in ROOT_DOC_WHITELIST or path in TOOL_OWNED_ROOT_FILES:
                continue
            self.report("DOC-006", path, 1, "Markdown at the repository root is not whitelisted")

    # -- DOC-007/008: fence and heading hygiene ---------------------------

    def check_fences_and_headings(self) -> None:
        for path, doc in self.markdown.items():
            if path in TOOL_OWNED_ROOT_FILES:
                continue
            for line_no, info in doc.fences:
                if not info:
                    self.report("DOC-007", path, line_no, "fenced block declares no language")
                elif info not in FENCE_LANGUAGES:
                    self.report(
                        "DOC-007",
                        path,
                        line_no,
                        f"unsupported fence language {info!r}; "
                        f"expected one of {sorted(FENCE_LANGUAGES)}",
                    )
            h1 = [(line, text) for line, level, text in doc.headings if level == 1]
            if not h1:
                self.report("DOC-008", path, 1, "document has no H1")
                continue
            if len(h1) > 1:
                for line, _ in h1[1:]:
                    self.report("DOC-008", path, line, "document has more than one H1")
            first_line = h1[0][0]
            expected = doc.frontmatter_end + 1
            content = [i for i in range(expected, first_line) if doc.lines[i - 1].strip()]
            if content:
                self.report(
                    "DOC-008",
                    path,
                    first_line,
                    f"H1 must be the first content line (line {expected})",
                )

    # -- DOC-009: index completeness --------------------------------------

    def check_indexes(self) -> None:
        for directory, index in INDEXED_QUADRANTS.items():
            index_doc = self.markdown.get(index)
            if index_doc is None:
                self.report("DOC-009", index, 1, "quadrant index is missing")
                continue
            linked = {
                self._normalise(Path(index).parent / match.group("target").split("#")[0])
                for match in INLINE_LINK.finditer(index_doc.text())
                if not is_external(match.group("target"))
            }
            members = sorted(
                path
                for path in self.markdown
                if Path(path).parent.as_posix() == directory and path != index
            )
            for member in members:
                if member not in linked:
                    self.report("DOC-009", index, 1, f"{member} is not listed in this index")
            for target in sorted(linked):
                if (
                    target not in self.markdown
                    and not (self.root / target).is_dir()
                    and not target.startswith(directory)
                ):
                    continue

    # -- DOC-010/011/012: ADR registry ------------------------------------

    def _adr_files(self) -> dict[int, str]:
        adrs: dict[int, str] = {}
        for path in self.markdown:
            match = ADR_FILE.match(Path(path).name)
            if match and Path(path).parent.as_posix() == "docs/adr":
                adrs[int(match.group(1))] = path
        return adrs

    def check_adr_registry(self) -> None:
        adrs = self._adr_files()
        index = "docs/adr/index.md"
        index_doc = self.markdown.get(index)
        if index_doc is None:
            self.report("DOC-010", index, 1, "ADR registry is missing")
            return
        rows: list[tuple[int, int, str]] = []
        for line_no, raw in enumerate(index_doc.lines, start=1):
            cells = [cell.strip() for cell in raw.strip().strip("|").split("|")]
            if len(cells) < 6 or not cells[0].startswith("["):
                continue
            match = re.search(r"\[(\d{4})\]", cells[0])
            if not match:
                continue
            rows.append((int(match.group(1)), line_no, cells[-1]))
        listed = {number for number, _, _ in rows}
        for number, path in sorted(adrs.items()):
            if number not in listed:
                self.report("DOC-010", index, 1, f"ADR-{number:04d} ({path}) is not in the registry")
        for number, line_no, date in rows:
            if number not in adrs:
                self.report("DOC-010", index, line_no, f"registry lists ADR-{number:04d}, which does not exist")
            if not re.match(r"^\d{4}-\d{2}-\d{2}$", date):
                self.report("DOC-010", index, line_no, f"ADR-{number:04d} has no ISO date in the last column")
        ordered = [number for number, _, _ in rows]
        if ordered != sorted(ordered):
            self.report("DOC-010", index, 1, "registry rows are not in ADR number order")
        dates = [(number, date) for number, _, date in rows]
        for (prev_no, prev_date), (next_no, next_date) in zip(dates, dates[1:]):
            if next_date < prev_date:
                self.report(
                    "DOC-010",
                    index,
                    1,
                    f"ADR-{next_no:04d} is dated {next_date}, before ADR-{prev_no:04d} ({prev_date})",
                )

        for number, path in sorted(adrs.items()):
            doc = self.markdown[path]
            fields, consumed = split_frontmatter(doc.lines)
            if consumed == 0:
                self.report("DOC-011", path, 1, "ADR has no YAML frontmatter")
                continue
            for key in ADR_REQUIRED_FRONTMATTER:
                if key not in fields:
                    self.report("DOC-011", path, 1, f"frontmatter is missing `{key}`")
            expected_id = f"ADR-{number:04d}"
            if fields.get("id") and fields["id"] != expected_id:
                self.report("DOC-011", path, 1, f"id is {fields['id']}, expected {expected_id}")
            status = fields.get("status", "")
            if status and status not in ADR_STATUSES:
                self.report("DOC-011", path, 1, f"status {status!r} is not one of {sorted(ADR_STATUSES)}")
            if status == "superseded" and fields.get("superseded_by", "null") in ("", "null"):
                self.report("DOC-011", path, 1, "a superseded ADR must name `superseded_by`")
            for key in ("date",):
                if fields.get(key) and not re.match(r"^\d{4}-\d{2}-\d{2}$", fields[key]):
                    self.report("DOC-011", path, 1, f"{key} is not ISO 8601")
            heading = next((text for _, level, text in doc.headings if level == 1), "")
            if heading and not heading.startswith(f"{number:04d}. "):
                self.report("DOC-011", path, 1, f"H1 must read '{number:04d}. <title>'")

    def check_adr_references(self) -> None:
        adrs = self._adr_files()
        for path, doc in self.markdown.items():
            if path.startswith("docs/adr/") and ADR_FILE.match(Path(path).name):
                continue
            for line_no, raw in enumerate(doc.lines, start=1):
                for match in ADR_ID.finditer(raw):
                    number = int(match.group(1))
                    if number not in adrs:
                        self.report(
                            "DOC-012",
                            path,
                            line_no,
                            f"{match.group(0)} does not exist in docs/adr/",
                        )

    # -- DOC-013: invariant governance ------------------------------------

    def check_invariants(self) -> None:
        """Every tag has an ADR behind it, and the index is complete both ways."""
        adrs = self._adr_files()
        ratified: dict[str, set[int]] = {}
        for number, path in adrs.items():
            for tag in invariant_tags(self.markdown[path].text()):
                ratified.setdefault(tag, set()).add(number)

        index = "docs/dev/invariants.md"
        index_doc = self.markdown.get(index)
        indexed: set[str] = set()
        if index_doc is not None:
            indexed = invariant_tags(index_doc.text())

        for path, doc in self.markdown.items():
            for line_no, raw in enumerate(doc.lines, start=1):
                for tag in invariant_tags(raw):
                    if tag not in ratified:
                        self.report(
                            "DOC-013",
                            path,
                            line_no,
                            f"{tag} is not ratified by any ADR (add it to the ADR that owns it)",
                        )
        for tag in sorted(indexed - ratified.keys()):
            self.report("DOC-013", index, 1, f"{tag} is indexed but no ADR ratifies it")
        for tag in sorted(ratified.keys() - indexed):
            self.report("DOC-013", index, 1, f"{tag} is ratified in an ADR but missing from the index")

    # -- DOC-014: version consistency -------------------------------------

    def check_versions(self) -> None:
        version = self.workspace_version
        if not version:
            self.report("DOC-014", "Cargo.toml", 1, "[workspace.package] version not found")
            return
        for manifest in sorted(self.root.glob("crates/*/Cargo.toml")):
            rel = manifest.relative_to(self.root).as_posix()
            text = manifest.read_text(encoding="utf-8")
            if "version.workspace = true" not in text:
                self.report("DOC-014", rel, 1, "crate does not inherit `version.workspace = true`")
            for match in re.finditer(
                r'^([A-Za-z][\w-]*)\s*=\s*\{[^}]*\bpath\s*=\s*"[^"]*"[^}]*\bversion\s*=\s*"([^"]+)"',
                text,
                re.MULTILINE,
            ):
                if match.group(2) != version:
                    self.report(
                        "DOC-014",
                        rel,
                        1,
                        f"workspace path dependency {match.group(1)} is pinned to "
                        f"{match.group(2)}, workspace is {version}",
                    )

        crates = self.markdown.get("docs/reference/crates.md")
        if crates is not None:
            for line_no, raw in enumerate(crates.lines, start=1):
                cells = [cell.strip() for cell in raw.strip().strip("|").split("|")]
                if len(cells) < 4 or not cells[0].startswith("`"):
                    continue
                stated = cells[2].strip("` ")
                if re.match(r"^\d+\.\d+\.\d+$", stated) and stated != version:
                    self.report(
                        "DOC-014",
                        "docs/reference/crates.md",
                        line_no,
                        f"{cells[0].strip('`')} is documented at {stated}, workspace is {version}",
                    )

        readme = self.markdown.get("README.md")
        if readme is not None:
            for line_no, raw in enumerate(readme.lines, start=1):
                for stated in re.findall(r"lockstep-versioned at `([^`]+)`", raw):
                    if stated != version:
                        self.report(
                            "DOC-014",
                            "README.md",
                            line_no,
                            f"README states {stated}, workspace is {version}",
                        )
                # A README snippet that shows a consumer pin must name the
                # current tag, or every reader copies a stale one.
                for stated in re.findall(r'tag\s*=\s*"v([0-9][^"]*)"', raw):
                    if stated != version:
                        self.report(
                            "DOC-014",
                            "README.md",
                            line_no,
                            f"README shows tag v{stated}, workspace is {version}",
                        )

    # -- DOC-015: postmortem structure ------------------------------------

    def check_postmortems(self) -> None:
        for path, doc in self.markdown.items():
            if Path(path).parent.as_posix() != "docs/dev/postmortems":
                continue
            if Path(path).name in {"index.md", "TEMPLATE.md"}:
                continue
            fields, consumed = split_frontmatter(doc.lines)
            if consumed == 0:
                self.report("DOC-015", path, 1, "postmortem has no YAML frontmatter")
                continue
            for key in POSTMORTEM_REQUIRED_FRONTMATTER:
                if key not in fields:
                    self.report("DOC-015", path, 1, f"frontmatter is missing `{key}`")
            headings = {text for _, level, text in doc.headings if level == 2}
            for required in POSTMORTEM_REQUIRED_HEADINGS:
                if required not in headings:
                    self.report("DOC-015", path, 1, f"missing H2 section: {required}")
            status = fields.get("status", "").lower()
            if status not in {"open", "closed"}:
                self.report("DOC-015", path, 1, "status must be `open` or `closed`")
            if status == "closed":
                text = doc.text().lower()
                if not any(token in text for token in ("test:", "gate:", "invariant:")):
                    self.report(
                        "DOC-015",
                        path,
                        1,
                        "a closed postmortem needs an action item verified by test:, gate:, or invariant:",
                    )

    # -- DOC-016: runbook structure ---------------------------------------

    def check_runbooks(self) -> None:
        for path, doc in self.markdown.items():
            if Path(path).parent.as_posix() != "docs/dev/runbooks":
                continue
            if Path(path).name == "index.md":
                continue
            headings = {text for _, level, text in doc.headings if level == 2}
            for required in RUNBOOK_REQUIRED_HEADINGS:
                if required not in headings:
                    self.report("DOC-016", path, 1, f"missing H2 section: {required}")

    # -- driver -----------------------------------------------------------

    def run(self) -> list[Violation]:
        self.check_links()
        self.check_tool_owned_isolation()
        self.check_root_whitelist()
        self.check_fences_and_headings()
        self.check_indexes()
        self.check_adr_registry()
        self.check_adr_references()
        self.check_invariants()
        self.check_versions()
        self.check_postmortems()
        self.check_runbooks()
        return sorted(set(self.violations))


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Documentation integrity gate.")
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[2],
        help="repository root (default: two levels above this script)",
    )
    args = parser.parse_args(argv)
    checker = Checker(args.root)
    violations = checker.run()
    for violation in violations:
        print(violation.render())
    if violations:
        print(f"\n{len(violations)} documentation violation(s).", file=sys.stderr)
        return 1
    print(f"documentation clean ({len(checker.markdown)} files checked)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
