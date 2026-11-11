#!/usr/bin/env python3
"""Workspace architecture gate.

`docs/dev/architecture.md` states the topology and the structural
red-lines; `AGENTS.md` states the guardrails an agent must not cross. Both were,
until this script existed, review conventions: nothing failed when a crate grew
an edge it was not allowed to have. This is the mechanism.

Rules, each mapped to the standard that states it:

    ARCH-001  a crate may only depend on the crates its layer allows
    ARCH-002  no orchestrator depends on the other orchestrator
    ARCH-003  no leaf depends on an orchestrator
    ARCH-004  netune-probe depends on no workspace crate
    ARCH-005  no third-party HTTP/2 or WebSocket runtime in a production graph
    ARCH-006  no third-party HTTP client in a production graph
    ARCH-007  every crate inherits the workspace version line
    ARCH-008  the transmit path is not reachable without `inject`
    ARCH-009  production dependencies carry an explicit `version` with their `path`
    ARCH-010  H3/QPACK is owned; no vendored protocol runtime tree
    ARCH-011  production code never emits a contentless diagnostic event

The distinction that matters is production vs. dev: an oracle (`hyper`,
`tungstenite`, `h3`) is allowed as a `dev-dependency`, because a differential
test compares owned bytes against it and never links it into the artifact that
ships. `ARCH-005`/`ARCH-006` therefore read `[dependencies]` only, which is the
question "what ships", not "what the test suite resolves".

Usage:
    python3 .github/scripts/check-architecture.py [--root DIR]

Exit status is 0 when clean and 1 when any violation is reported.
"""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

# --- the topology ----------------------------------------------------------

# The one place the allowed shape of the workspace is written down. An edge
# not listed here is an architectural inversion (ARCH-001).
#
# The leaves are not a flat ring: `netune-io` sits above `netune-trace`,
# because `TimedIo` writes into a `Recorder` and there is no version of that
# type that does not. Encoding the real DAG is the point — a rule that says
# "leaves never depend on each other" would be false, and a false rule
# trains people to ignore the checker.
ALLOWED_EDGES: dict[str, set[str]] = {
    # trace model: no workspace dependencies at all, so both orchestrators and
    # netune-io can depend on it without a cycle.
    "netune-trace": set(),
    # byte-path wrappers: record into the trace model, nothing else.
    "netune-io": {"netune-trace"},
    # native diagnostic sinks and review bundles: presentation/file I/O only,
    # never a socket or an orchestrator.
    "netune-diagnostics": {"netune-trace"},
    # pure egress address policy: no dependencies at all, so every outbound
    # transport (netune TCP/UDP, netune-quic) shares one definition of
    # `is_public_ip` rather than maintaining copies that drift.
    "netune-egress": set(),
    # pure codecs: caller-provided buffers, no sibling, no orchestrator.
    "netune-http1": set(),
    "netune-http2": set(),
    "netune-ws": set(),
    # probe: parses and builds L2 frames; links none of the stack.
    "netune-probe": set(),
    # QUIC and HTTP/3 client transport (ADR-0016).
    "netune-quic": {"netune-egress", "netune-io", "netune-trace"},
    "netune-http3": {"netune-quic", "netune-trace"},
    "netune-webtransport": {"netune-http3", "netune-quic"},
    # egress orchestrator.
    "netune": {
        "netune-egress",
        "netune-http1",
        "netune-http2",
        "netune-http3",
        "netune-quic",
        "netune-trace",
        "netune-ws",
        "netune-io",
        "netune-diagnostics",
    },
    # ingress orchestrator: the peer of `netune`, never its dependency.
    "netune-server": {
        "netune-http1",
        "netune-http2",
        "netune-http3",
        "netune-io",
        "netune-quic",
        "netune-trace",
        "netune-diagnostics",
    },
}

ORCHESTRATORS = {"netune", "netune-server"}
LEAVES = set(ALLOWED_EDGES) - ORCHESTRATORS

# A production dependency on any of these is the red-line ADR-0001 exists for.
FORBIDDEN_HTTP2_RUNTIME = {
    "h2",
    "quiche",
    "s2n-quic",
    "neon-http",
}
FORBIDDEN_QUIC_RUNTIME = {
    "quinn",
    "quinn-proto",
    "h3",
    "h3-quinn",
}
ALLOWED_RUNTIME_DEPS: dict[str, set[str]] = {}
FORBIDDEN_WS_RUNTIME = {
    "tungstenite",
    "tokio-tungstenite",
    "async-tungstenite",
    "fastwebsockets",
    "ws-rs",
}
FORBIDDEN_HTTP_CLIENT = {
    "hyper",
    "hyper-util",
    "reqwest",
    "ureq",
    "isahc",
    "surf",
    "attohttpc",
    "minreq",
    "awc",
    "tame-oauth",
}


@dataclass(frozen=True, order=True)
class Violation:
    rule: str
    path: str
    message: str

    def render(self) -> str:
        return f"{self.rule} {self.path} {self.message}"


def normalise(name: str) -> str:
    return name.replace("_", "-").lower()


class Workspace:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.violations: list[Violation] = []
        self.manifests: dict[str, dict] = {}
        self.paths: dict[str, str] = {}
        for manifest in sorted(root.glob("crates/*/Cargo.toml")):
            relative = manifest.relative_to(root).as_posix()
            data = tomllib.loads(manifest.read_text(encoding="utf-8"))
            name = data.get("package", {}).get("name")
            if not name:
                continue
            self.manifests[name] = data
            self.paths[name] = relative
        self.workspace_version = self._workspace_version()

    def _workspace_version(self) -> str:
        data = tomllib.loads((self.root / "Cargo.toml").read_text(encoding="utf-8"))
        return data.get("workspace", {}).get("package", {}).get("version", "")

    def report(self, rule: str, crate: str, message: str) -> None:
        self.violations.append(Violation(rule, self.paths.get(crate, crate), message))

    # -- helpers ----------------------------------------------------------

    @staticmethod
    def _section(data: dict, key: str) -> dict:
        return data.get(key, {}) or {}

    def production_deps(self, crate: str) -> set[str]:
        """Workspace crates this crate depends on in a *shipping* build."""
        deps = self._section(self.manifests[crate], "dependencies")
        return {normalise(name) for name in deps} & set(ALLOWED_EDGES)

    def dev_deps(self, crate: str) -> set[str]:
        deps = self._section(self.manifests[crate], "dev-dependencies")
        return {normalise(name) for name in deps} & set(ALLOWED_EDGES)

    def third_party_production(self, crate: str) -> dict[str, str]:
        """Every non-workspace production dependency, `name -> version spec`."""
        deps = self._section(self.manifests[crate], "dependencies")
        out: dict[str, str] = {}
        for name, spec in deps.items():
            if normalise(name) in ALLOWED_EDGES:
                continue
            out[normalise(name)] = spec.get("version", "") if isinstance(spec, dict) else str(spec)
        return out

    # -- ARCH-001..004: topology ------------------------------------------

    def check_edges(self) -> None:
        for crate in ALLOWED_EDGES:
            if crate not in self.manifests:
                self.report("ARCH-001", crate, "crate declared in the topology but not present on disk")
                continue
            allowed = ALLOWED_EDGES[crate]
            for dep in sorted(self.production_deps(crate)):
                if dep == crate:
                    self.report("ARCH-001", crate, f"depends on itself")
                    continue
                if dep not in allowed:
                    self.report(
                        "ARCH-001",
                        crate,
                        f"production dependency on {dep} is not an allowed edge "
                        f"(allowed: {sorted(allowed) or 'none'})",
                    )
                if crate in ORCHESTRATORS and dep in ORCHESTRATORS:
                    self.report(
                        "ARCH-002",
                        crate,
                        f"orchestrator depends on the other orchestrator ({dep})",
                    )
                if crate in LEAVES and dep in ORCHESTRATORS:
                    self.report(
                        "ARCH-003",
                        crate,
                        f"leaf depends on an orchestrator ({dep})",
                    )
                if crate == "netune-probe":
                    self.report("ARCH-004", crate, f"probe depends on a workspace crate ({dep})")

        # ARCH-002 also covers the direction that a stray edge would express:
        # one orchestrator reached from the other through a shared leaf is fine,
        # one reaching the other directly is the inversion ADR-0011 forbids.
        for orchestrator in sorted(ORCHESTRATORS):
            for other in sorted(ORCHESTRATORS - {orchestrator}):
                if other in self.dev_deps(orchestrator):
                    # Allowed and deliberate: the interop suite drives ingress
                    # from the egress client. It must never ship.
                    continue

        unknown = set(self.manifests) - set(ALLOWED_EDGES)
        for crate in sorted(unknown):
            self.report(
                "ARCH-001",
                crate,
                "crate is not declared in the topology table in check-architecture.py",
            )

    # -- ARCH-005/006: no third-party protocol runtime --------------------

    def check_protocol_runtimes(self) -> None:
        for crate in self.manifests:
            deps = self.third_party_production(crate)
            for name in sorted(deps):
                if name in FORBIDDEN_HTTP2_RUNTIME:
                    self.report(
                        "ARCH-005",
                        crate,
                        f"production dependency on {name} (HTTP/2 or QUIC runtime, ADR-0001/ADR-0010)",
                    )
                if name in FORBIDDEN_QUIC_RUNTIME:
                    allowed = ALLOWED_RUNTIME_DEPS.get(crate, set())
                    if name not in allowed:
                        self.report(
                            "ARCH-005",
                            crate,
                            f"production dependency on {name} (third-party protocol runtime, ADR-0001/ADR-0027)",
                        )
                if name in FORBIDDEN_WS_RUNTIME:
                    self.report(
                        "ARCH-005",
                        crate,
                        f"production dependency on {name} (WebSocket runtime, ADR-0007)",
                    )
                if name in FORBIDDEN_HTTP_CLIENT:
                    self.report(
                        "ARCH-006",
                        crate,
                        f"production dependency on {name} (third-party HTTP client, ADR-0001)",
                    )

    # -- ARCH-007: one version line ---------------------------------------

    def check_versions(self) -> None:
        for crate, data in sorted(self.manifests.items()):
            package = data.get("package", {})
            if package.get("version") != {"workspace": True}:
                self.report("ARCH-007", crate, "crate does not inherit `version.workspace = true`")
            for dep, spec in self._section(data, "dependencies").items():
                if normalise(dep) not in ALLOWED_EDGES or not isinstance(spec, dict):
                    continue
                stated = spec.get("version")
                if stated is None:
                    self.report("ARCH-009", crate, f"workspace dependency {dep} carries no `version`")
                elif stated != self.workspace_version:
                    self.report(
                        "ARCH-009",
                        crate,
                        f"workspace dependency {dep} pinned to {stated}, workspace is {self.workspace_version}",
                    )

    # -- ARCH-011: one diagnostic producer path ---------------------------

    def check_diagnostic_producers(self) -> None:
        """`EventKind::Error` may only be emitted through the trace recorder.

        A crate that writes the event directly can bypass the side table and
        recreate the `Error(0, 0)` failure this ADR exists to remove. The trace
        crate owns the one producer; every other crate uses `record_error` /
        `record_error_stream`.
        """
        for source in sorted(self.root.glob("crates/*/src/**/*.rs")):
            relative = source.relative_to(self.root).as_posix()
            if relative.startswith(("crates/netune-trace/", "crates/netune-diagnostics/")):
                continue
            text = source.read_text(encoding="utf-8", errors="replace")
            for index, line in enumerate(text.split("\n"), start=1):
                if "EventKind::Error" in line:
                    self.report(
                        "ARCH-011",
                        relative,
                        f"line {index} emits EventKind::Error directly; use "
                        "TraceCollector::record_error or record_error_stream",
                    )

    # -- ARCH-008: the transmit path --------------------------------------

    def check_transmit_path(self) -> None:
        """`send_frame` must not compile without the `inject` feature.

        The gate may sit on the function or on the `impl` block that contains
        it — both remove the symbol from a default build, and pinning the rule
        to one spelling would fail a correct file.
        """
        probe = self.root / "crates/netune-probe"
        if not probe.is_dir():
            return
        features = self._section(self.manifests.get("netune-probe", {}), "features")
        if "inject" not in features:
            self.report("ARCH-008", "netune-probe", "declares no `inject` feature")
        for source in sorted(probe.rglob("*.rs")):
            text = source.read_text(encoding="utf-8", errors="replace")
            lines = text.split("\n")
            for index, line in enumerate(lines):
                match = re.match(r"^\s*pub (?:async )?fn (send_frame|send_raw)\b", line)
                if not match:
                    continue
                if self._gated_on_inject(lines, index):
                    continue
                self.report(
                    "ARCH-008",
                    source.relative_to(self.root).as_posix(),
                    f"`{match.group(1)}` at line {index + 1} is not gated on "
                    f"`feature = \"inject\"`, directly or via its `impl` block",
                )

    @staticmethod
    def _gated_on_inject(lines: list[str], item: int) -> bool:
        """`True` when the item, or the `impl` block enclosing it, is gated."""
        def attributes_above(start: int) -> list[str]:
            found: list[str] = []
            cursor = start - 1
            while cursor >= 0:
                stripped = lines[cursor].strip()
                if stripped.startswith("#[") or stripped.startswith("///") or stripped.startswith("//"):
                    found.append(stripped)
                    cursor -= 1
                    continue
                if stripped == "":
                    cursor -= 1
                    continue
                break
            return found

        if any('feature = "inject"' in attr for attr in attributes_above(item)):
            return True
        # Walk outward to the enclosing `impl` and check its attributes.
        depth = 0
        cursor = item - 1
        while cursor >= 0:
            stripped = lines[cursor].strip()
            depth += stripped.count("}") - stripped.count("{")
            if depth < 0 and stripped.startswith("impl"):
                return any('feature = "inject"' in attr for attr in attributes_above(cursor))
            if depth < 0:
                # A different enclosing item (e.g. a bare `mod`): keep walking.
                depth = 0
            cursor -= 1
        return False

    # -- driver -----------------------------------------------------------

    def check_vendor_tree(self) -> None:
        """ADR-0027 owns H3/QPACK; a vendored runtime tree is a regression."""
        for name in ("vendor/h3", "vendor/h3-quinn"):
            if (self.root / name).exists():
                self.report(
                    "ARCH-010",
                    "vendor",
                    f"{name} exists; H3/QPACK is owned by netune-http3 (ADR-0027)",
                )

    def run(self) -> list[Violation]:
        self.check_edges()
        self.check_protocol_runtimes()
        self.check_versions()
        self.check_transmit_path()
        self.check_vendor_tree()
        self.check_diagnostic_producers()
        return sorted(set(self.violations))


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Workspace architecture gate.")
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[2],
        help="repository root (default: two levels above this script)",
    )
    args = parser.parse_args(argv)
    workspace = Workspace(args.root)
    violations = workspace.run()
    for violation in violations:
        print(violation.render())
    if violations:
        print(f"\n{len(violations)} architecture violation(s).", file=sys.stderr)
        return 1
    print(f"architecture clean ({len(workspace.manifests)} crates checked)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
