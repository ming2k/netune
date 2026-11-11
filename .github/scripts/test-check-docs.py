#!/usr/bin/env python3
"""Self-test for `.github/scripts/check-docs.py`.

A gate nobody tests is a gate that quietly stops failing. Every rule the
checker enforces has a fixture here that must be *reported* and, where the
rule has a legitimate near-miss, a fixture that must stay *clean* — otherwise
the obvious fix for a red build is to weaken the checker instead of fixing
the document.

Run: python3 .github/scripts/test-check-docs.py
"""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import textwrap
from pathlib import Path

SCRIPT = Path(__file__).with_name("check-docs.py")
spec = importlib.util.spec_from_file_location("check_docs", SCRIPT)
if spec is None or spec.loader is None:  # pragma: no cover
    raise SystemExit(f"cannot import {SCRIPT}")
check_docs = importlib.util.module_from_spec(spec)
# `dataclasses` resolves annotations through `sys.modules`, so the module must
# be registered before execution, not after.
sys.modules["check_docs"] = check_docs
spec.loader.exec_module(check_docs)

FAILURES: list[str] = []


def build(tmp: Path, files: dict[str, str]) -> Path:
    for relative, content in files.items():
        path = tmp / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(content).lstrip("\n"), encoding="utf-8")
    return tmp


def check(files: dict[str, str]) -> list[check_docs.Violation]:
    with tempfile.TemporaryDirectory() as raw:
        root = build(Path(raw), files)
        return check_docs.Checker(root).run()


def expect(rule: str, files: dict[str, str], *, message: str) -> None:
    """Assert that `rule` fires."""
    violations = check(files)
    if not any(v.rule == rule for v in violations):
        FAILURES.append(f"{message}: expected {rule}, got {[v.render() for v in violations]}")


def expect_clean(rule: str, files: dict[str, str], *, message: str) -> None:
    """Assert that `rule` does not fire (the legitimate near-miss)."""
    violations = [v for v in check(files) if v.rule == rule]
    if violations:
        FAILURES.append(f"{message}: unexpected {rule}: {[v.render() for v in violations]}")


BASE = {
    "Cargo.toml": """
        [workspace.package]
        version = "1.2.3"
    """,
    "README.md": """
        # Project

        Every workspace crate is lockstep-versioned at `1.2.3`.
    """,
    "docs/tutorials/index.md": """
        # Tutorials

        | [Lesson](lesson.md) |
        | :--- |
    """,
    "docs/tutorials/lesson.md": """
        # Lesson

        Body.
    """,
    "docs/how-to/index.md": "# How-To\n",
    "docs/reference/index.md": "# Reference\n",
    "docs/explanation/index.md": "# Explanation\n",
    "docs/dev/standards/README.md": """
        # Standards

        | [Style](style.md) · [Taxonomy](taxonomy.md) |
        | :--- |
    """,
    "docs/dev/standards/taxonomy.md": "# Taxonomy\n",
    "docs/dev/standards/style.md": "# Style\n",
    "docs/dev/postmortems/index.md": """
        # Postmortems

        | [Template](TEMPLATE.md) |
        | :--- |
    """,
    "docs/dev/postmortems/TEMPLATE.md": "# Template\n",
    "docs/dev/runbooks/index.md": """
        # Runbooks

        | [First](first-response.md) |
        | :--- |
    """,
    "docs/dev/runbooks/first-response.md": """
        # First Response

        ## Target Subsystem & Reference Environment

        ## Core Protocol Rules & Invariants

        ## Diagnostic Playbook

        ## Do-Not-Regress Checklist
    """,
    "docs/adr/index.md": """
        # ADRs

        | ID | Title | Status | Scope | Summary | Date |
        | :--- | :--- | :--- | :--- | :--- | :--- |
        | [0001](0001-first.md) | First | accepted | trace/model | Decision | 2026-01-01 |
    """,
    "docs/adr/0001-first.md": """
        ---
        id: ADR-0001
        title: "First"
        status: accepted
        date: 2026-01-01
        scope: [trace/model]
        superseded_by: null
        ---

        # 0001. First

        Ratifies `[INV-TRACE-01]`.
    """,
    "docs/dev/invariants.md": """
        # Invariants

        | `[INV-TRACE-01]` | A thing holds. |
    """,
}


def merged(**overrides: str) -> dict[str, str]:
    files = dict(BASE)
    files.update(overrides)
    return files


# --- the baseline must be clean --------------------------------------------


def test_baseline_is_clean() -> None:
    violations = check(BASE)
    if violations:
        FAILURES.append(f"baseline fixture is not clean: {[v.render() for v in violations]}")


# --- DOC-001: dead relative links ------------------------------------------


def test_dead_link_is_reported() -> None:
    expect(
        "DOC-001",
        merged(**{"README.md": "# Project\n\nSee [gone](docs/missing.md).\n"}),
        message="dead relative link",
    )


def test_relative_link_upwards_resolves() -> None:
    expect_clean(
        "DOC-001",
        merged(
            **{
                "docs/how-to/index.md": "# How-To\n\n[up](../../README.md)\n",
                "README.md": "# Project\n\nEvery workspace crate is lockstep-versioned at `1.2.3`.\n",
            }
        ),
        message="`../` link from a nested quadrant",
    )


def test_external_and_mailto_links_are_ignored() -> None:
    expect_clean(
        "DOC-001",
        merged(
            **{
                "README.md": (
                    "# Project\n\nEvery workspace crate is lockstep-versioned at `1.2.3`.\n\n"
                    "[a](https://example.com/x) [b](mailto:x@example.com)\n"
                )
            }
        ),
        message="external URL is not a filesystem path",
    )


def test_link_inside_a_fence_is_illustrative() -> None:
    expect_clean(
        "DOC-001",
        merged(
            **{
                "docs/dev/standards/style.md": (
                    "# Style\n\n```markdown\n[adr](../adr/0009-nope.md)\n```\n"
                )
            }
        ),
        message="a link shown inside a fence is an example",
    )


# --- DOC-002: anchors ------------------------------------------------------


def test_broken_anchor_is_reported() -> None:
    expect(
        "DOC-002",
        merged(
            **{
                "docs/tutorials/index.md": (
                    "# Tutorials\n\n[Lesson](lesson.md#no-such-heading)\n"
                )
            }
        ),
        message="anchor that is not a heading",
    )


def test_valid_anchor_resolves() -> None:
    expect_clean(
        "DOC-002",
        merged(
            **{
                "docs/tutorials/index.md": "# Tutorials\n\n[Lesson](lesson.md#lesson)\n",
            }
        ),
        message="anchor that is a heading",
    )


def test_same_page_anchor() -> None:
    expect_clean(
        "DOC-002",
        merged(**{"docs/tutorials/lesson.md": "# Lesson\n\n[top](#lesson)\n"}),
        message="same-page anchor",
    )


# --- DOC-003: reference-style links ---------------------------------------


def test_undefined_reference_is_reported() -> None:
    expect(
        "DOC-003",
        merged(**{"README.md": "# Project\n\nEvery workspace crate is lockstep-versioned at `1.2.3`. See [x][nowhere].\n"}),
        message="explicit reference with no definition",
    )


def test_shortcut_brackets_are_not_links() -> None:
    # `[INV-WS-01]` is how this repository writes an invariant tag. CommonMark
    # treats an undefined shortcut reference as literal text, so it is not a
    # broken link and must not be reported as one.
    expect_clean(
        "DOC-003",
        merged(**{"README.md": "# Project\n\nEvery workspace crate is lockstep-versioned at `1.2.3`. See [INV-WS-01].\n"}),
        message="undefined shortcut bracket",
    )


# --- DOC-004: the public/internal firewall ---------------------------------


def test_public_link_into_dev_is_reported() -> None:
    expect(
        "DOC-004",
        merged(
            **{
                "docs/reference/index.md": (
                    "# Reference\n\n[rule](../dev/standards/style.md)\n"
                )
            }
        ),
        message="public quadrant linking into docs/dev",
    )


def test_internal_link_outward_is_allowed() -> None:
    expect_clean(
        "DOC-004",
        merged(
            **{
                "docs/dev/standards/style.md": "# Style\n\n[guide](../../how-to/index.md)\n"
            }
        ),
        message="internal document linking outward",
    )


# --- DOC-005: tool-owned root files ---------------------------------------


def test_docs_referencing_agents_is_reported() -> None:
    expect(
        "DOC-005",
        merged(
            **{
                "docs/dev/standards/taxonomy.md": (
                    "# Taxonomy\n\n`AGENTS.md` is an entry point.\n"
                )
            }
        ),
        message="documentation governing a tool-owned file",
    )


def test_root_may_reference_agents() -> None:
    expect_clean(
        "DOC-005",
        merged(**{"README.md": "# Project\n\nEvery workspace crate is lockstep-versioned at `1.2.3`. See AGENTS.md.\n"}),
        message="README may mention the agent directive file",
    )


# --- DOC-006: root whitelist ----------------------------------------------


def test_unlisted_root_markdown_is_reported() -> None:
    expect(
        "DOC-006",
        merged(**{"NOTES.md": "# Notes\n"}),
        message="Markdown at the root outside the whitelist",
    )


def test_agents_is_exempt_from_the_whitelist() -> None:
    # AGENTS.md is tool-owned, not documentation: the whitelist neither lists
    # it (DOC-005 forbids that) nor rejects it (DOC-006).
    expect_clean(
        "DOC-006",
        merged(**{"AGENTS.md": "# Agent Directives\n\nRules.\n"}),
        message="tool-owned root file is neither listed nor rejected",
    )


# --- DOC-007: fence languages ---------------------------------------------


def test_untyped_fence_is_reported() -> None:
    expect(
        "DOC-007",
        merged(**{"docs/tutorials/lesson.md": "# Lesson\n\n```\nplain\n```\n"}),
        message="fence with no language",
    )


def test_typed_fence_passes() -> None:
    expect_clean(
        "DOC-007",
        merged(**{"docs/tutorials/lesson.md": "# Lesson\n\n```text\nplain\n```\n"}),
        message="typed fence",
    )


def test_unknown_fence_language_is_reported() -> None:
    expect(
        "DOC-007",
        merged(**{"docs/tutorials/lesson.md": "# Lesson\n\n```cobol\nx\n```\n"}),
        message="unsupported fence language",
    )


# --- DOC-008: headings ----------------------------------------------------


def test_missing_h1_is_reported() -> None:
    expect(
        "DOC-008",
        merged(**{"docs/tutorials/lesson.md": "## Secondary\n\nBody.\n"}),
        message="document with no H1",
    )


def test_h1_after_prose_is_reported() -> None:
    expect(
        "DOC-008",
        merged(**{"docs/tutorials/lesson.md": "Intro prose.\n\n# Lesson\n"}),
        message="H1 that is not the first content line",
    )


def test_h1_after_frontmatter_is_first_line() -> None:
    expect_clean(
        "DOC-008",
        merged(
            **{
                "docs/adr/0001-first.md": (
                    "---\nid: ADR-0001\ntitle: \"First\"\nstatus: accepted\n"
                    "date: 2026-01-01\nscope: [trace/model]\nsuperseded_by: null\n---\n\n"
                    "# 0001. First\n\nRatifies `[INV-TRACE-01]`.\n"
                )
            }
        ),
        message="frontmatter is not content",
    )


# --- DOC-009: index completeness ------------------------------------------


def test_unlisted_document_is_reported() -> None:
    expect(
        "DOC-009",
        merged(**{"docs/tutorials/hidden.md": "# Hidden\n"}),
        message="document missing from its quadrant index",
    )


def test_listed_document_passes() -> None:
    expect_clean("DOC-009", BASE, message="every document is indexed")


# --- DOC-010: ADR registry ------------------------------------------------


def test_adr_missing_from_registry_is_reported() -> None:
    expect(
        "DOC-010",
        merged(
            **{
                "docs/adr/0002-second.md": (
                    "---\nid: ADR-0002\ntitle: \"Second\"\nstatus: accepted\n"
                    "date: 2026-01-02\nscope: [trace/model]\nsuperseded_by: null\n---\n\n"
                    "# 0002. Second\n\nBody.\n"
                )
            }
        ),
        message="ADR absent from the registry",
    )


def test_registry_entry_without_file_is_reported() -> None:
    expect(
        "DOC-010",
        merged(
            **{
                "docs/adr/index.md": (
                    "# ADRs\n\n| ID | Title | Status | Scope | Summary | Date |\n"
                    "| :--- | :--- | :--- | :--- | :--- | :--- |\n"
                    "| [0001](0001-first.md) | First | accepted | trace/model | D | 2026-01-01 |\n"
                    "| [0007](0007-absent.md) | Absent | accepted | trace/model | D | 2026-01-02 |\n"
                )
            }
        ),
        message="registry row with no file",
    )


def test_out_of_order_dates_are_reported() -> None:
    expect(
        "DOC-010",
        merged(
            **{
                "docs/adr/index.md": (
                    "# ADRs\n\n| ID | Title | Status | Scope | Summary | Date |\n"
                    "| :--- | :--- | :--- | :--- | :--- | :--- |\n"
                    "| [0001](0001-first.md) | First | accepted | trace/model | D | 2026-05-01 |\n"
                    "| [0002](0002-second.md) | Second | accepted | trace/model | D | 2026-01-01 |\n"
                ),
                "docs/adr/0002-second.md": (
                    "---\nid: ADR-0002\ntitle: \"Second\"\nstatus: accepted\n"
                    "date: 2026-01-01\nscope: [trace/model]\nsuperseded_by: null\n---\n\n"
                    "# 0002. Second\n\nBody.\n"
                ),
            }
        ),
        message="registry ordered by number but dated backwards",
    )


# --- DOC-011: ADR frontmatter schema --------------------------------------


def test_frontmatter_missing_a_field_is_reported() -> None:
    expect(
        "DOC-011",
        merged(
            **{
                "docs/adr/0001-first.md": (
                    "---\nid: ADR-0001\ntitle: \"First\"\nstatus: accepted\n"
                    "date: 2026-01-01\nscope: [trace/model]\n---\n\n"
                    "# 0001. First\n\nRatifies `[INV-TRACE-01]`.\n"
                )
            }
        ),
        message="frontmatter without superseded_by",
    )


def test_superseded_without_target_is_reported() -> None:
    expect(
        "DOC-011",
        merged(
            **{
                "docs/adr/0001-first.md": (
                    "---\nid: ADR-0001\ntitle: \"First\"\nstatus: superseded\n"
                    "date: 2026-01-01\nscope: [trace/model]\nsuperseded_by: null\n---\n\n"
                    "# 0001. First\n\nRatifies `[INV-TRACE-01]`.\n"
                )
            }
        ),
        message="superseded ADR naming no successor",
    )


def test_h1_number_mismatch_is_reported() -> None:
    expect(
        "DOC-011",
        merged(
            **{
                "docs/adr/0001-first.md": (
                    "---\nid: ADR-0001\ntitle: \"First\"\nstatus: accepted\n"
                    "date: 2026-01-01\nscope: [trace/model]\nsuperseded_by: null\n---\n\n"
                    "# First\n\nRatifies `[INV-TRACE-01]`.\n"
                )
            }
        ),
        message="H1 without the ADR number",
    )


# --- DOC-012: ghost ADR references ---------------------------------------


def test_ghost_adr_reference_is_reported() -> None:
    expect(
        "DOC-012",
        merged(**{"docs/tutorials/lesson.md": "# Lesson\n\nSee ADR-0042.\n"}),
        message="reference to an ADR that does not exist",
    )


# --- DOC-013: invariant governance ---------------------------------------


def test_unratified_invariant_tag_is_reported() -> None:
    expect(
        "DOC-013",
        merged(**{"docs/tutorials/lesson.md": "# Lesson\n\nHolds `[INV-GHOST-01]`.\n"}),
        message="tag with no ADR behind it",
    )


def test_index_missing_a_ratified_tag_is_reported() -> None:
    expect(
        "DOC-013",
        merged(
            **{
                "docs/adr/0001-first.md": (
                    "---\nid: ADR-0001\ntitle: \"First\"\nstatus: accepted\n"
                    "date: 2026-01-01\nscope: [trace/model]\nsuperseded_by: null\n---\n\n"
                    "# 0001. First\n\nRatifies `[INV-TRACE-01]` and `[INV-TRACE-02]`.\n"
                )
            }
        ),
        message="ratified tag absent from the invariant index",
    )


def test_range_notation_is_expanded() -> None:
    # `INV-TRACE-01..02` is two tags. A checker that reads it as one would
    # demand a second ADR line that the standard does not require.
    expect_clean(
        "DOC-013",
        merged(
            **{
                "docs/adr/0001-first.md": (
                    "---\nid: ADR-0001\ntitle: \"First\"\nstatus: accepted\n"
                    "date: 2026-01-01\nscope: [trace/model]\nsuperseded_by: null\n---\n\n"
                    "# 0001. First\n\nRatifies `[INV-TRACE-01..02]`.\n"
                ),
                "docs/dev/invariants.md": (
                    "# Invariants\n\n| `[INV-TRACE-01..02]` | Two things hold. |\n"
                ),
            }
        ),
        message="range notation covers both tags",
    )


# --- DOC-014: version consistency ----------------------------------------


def test_readme_version_drift_is_reported() -> None:
    expect(
        "DOC-014",
        merged(**{"README.md": "# Project\n\nEvery workspace crate is lockstep-versioned at `0.0.2`.\n"}),
        message="README states a stale version",
    )


def test_readme_without_a_version_claim_is_clean() -> None:
    # Silence is not drift: a README that states no version cannot state a
    # stale one. Requiring a sentence, not a match, keeps the rule honest.
    expect_clean(
        "DOC-014",
        merged(**{"README.md": "# Project\n\nNo version claim here.\n"}),
        message="README with no version statement",
    )


def test_non_workspace_dependency_pin_is_ignored() -> None:
    # `hyper = { version = "1.10" }` is an external dev-dependency, not a
    # workspace path dependency. Only the latter follows the workspace version.
    expect_clean(
        "DOC-014",
        merged(
            **{
                "crates/netune-http1/Cargo.toml": (
                    "[package]\nversion.workspace = true\n\n"
                    "[dev-dependencies]\nhyper = { version = \"1.10\" }\n"
                )
            }
        ),
        message="external dependency pin is not a workspace version",
    )


def test_workspace_pin_drift_is_reported() -> None:
    expect(
        "DOC-014",
        merged(
            **{
                "crates/netune/Cargo.toml": (
                    "[package]\nversion.workspace = true\n\n"
                    "[dependencies]\nnetune-trace = { path = \"../netune-trace\", version = \"9.9.9\" }\n"
                )
            }
        ),
        message="internal path dependency pinned off the workspace version",
    )


# --- DOC-015: postmortem structure ---------------------------------------


VALID_POSTMORTEM = """
---
id: PM-0001
severity: 2
status: closed
detected_by: user-report
affected_versions: [0.0.25]
invariants: [INV-DIAG-01]
adrs: [ADR-0041]
trace_ids: [01924f4e-0000-7000-8000-000000000001]
---

# PM-0001: Example

## Executive Summary

## Timeline of Events (UTC)

## Evidence

## Detection Gaps

## Trigger & Underlying Root Cause

## Action Items & Defense-in-Depth

| A1 | Add a test | test: diag_example |
"""


def test_closed_postmortem_with_verified_action_is_clean() -> None:
    expect_clean(
        "DOC-015",
        merged(
            **{
                "docs/dev/postmortems/index.md": (
                    "# Postmortems\n\n| [Template](TEMPLATE.md) | [PM-0001](0001-example.md) |\n| :--- |\n"
                ),
                "docs/dev/postmortems/0001-example.md": VALID_POSTMORTEM,
            }
        ),
        message="complete postmortem",
    )


def test_postmortem_without_evidence_and_verification_is_reported() -> None:
    broken = VALID_POSTMORTEM.replace("## Evidence\n", "").replace(
        "| A1 | Add a test | test: diag_example |", "| A1 | Add a test | later |"
    )
    expect(
        "DOC-015",
        merged(
            **{
                "docs/dev/postmortems/index.md": (
                    "# Postmortems\n\n| [Template](TEMPLATE.md) | [PM-0001](0001-example.md) |\n| :--- |\n"
                ),
                "docs/dev/postmortems/0001-example.md": broken,
            }
        ),
        message="postmortem missing evidence and verified action item",
    )


# --- DOC-016: runbook structure ------------------------------------------


def test_runbook_without_a_diagnostic_playbook_is_reported() -> None:
    expect(
        "DOC-016",
        merged(
            **{
                "docs/dev/runbooks/first-response.md": (
                    "# First Response\n\n"
                    "## Target Subsystem & Reference Environment\n\n"
                    "## Core Protocol Rules & Invariants\n\n"
                    "## Do-Not-Regress Checklist\n"
                )
            }
        ),
        message="runbook missing the diagnostic playbook",
    )


def test_complete_runbook_is_clean() -> None:
    expect_clean(
        "DOC-016",
        merged(),
        message="complete runbook",
    )


# --- driver ---------------------------------------------------------------


def main() -> int:
    tests = [
        (name, value)
        for name, value in sorted(globals().items())
        if name.startswith("test_") and callable(value)
    ]
    for name, test in tests:
        try:
            test()
        except Exception as error:  # noqa: BLE001 - report, never abort the suite
            FAILURES.append(f"{name} raised {type(error).__name__}: {error}")
    if FAILURES:
        for failure in FAILURES:
            print(f"FAIL {failure}")
        print(f"\n{len(FAILURES)} self-test failure(s) over {len(tests)} tests.", file=sys.stderr)
        return 1
    print(f"documentation gate self-test clean ({len(tests)} tests)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
