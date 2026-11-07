#!/usr/bin/env python3
"""Self-test for `.github/scripts/check-architecture.py`.

Each rule gets a minimal workspace that violates it and one that is the
legitimate near-miss. The near-miss cases matter more than the violations: an
architecture gate that fails a correct crate gets deleted within a week, and
then nothing checks anything.

Run: python3 .github/scripts/test-check-architecture.py
"""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import textwrap
from pathlib import Path

SCRIPT = Path(__file__).with_name("check-architecture.py")
spec = importlib.util.spec_from_file_location("check_architecture", SCRIPT)
if spec is None or spec.loader is None:  # pragma: no cover
    raise SystemExit(f"cannot import {SCRIPT}")
check_architecture = importlib.util.module_from_spec(spec)
sys.modules["check_architecture"] = check_architecture
spec.loader.exec_module(check_architecture)

FAILURES: list[str] = []


def manifest(
    *,
    name: str,
    dependencies: str = "",
    dev_dependencies: str = "",
    version_inherited: bool = True,
    features: str = "",
) -> str:
    version = "version.workspace = true" if version_inherited else 'version = "9.9.9"'
    text = f"""
        [package]
        name = "{name}"
        {version}

        [dependencies]
    """
    text += textwrap.indent(textwrap.dedent(dependencies), " " * 8) if dependencies else ""
    if dev_dependencies:
        text += "\n[dev-dependencies]\n"
        text += textwrap.indent(textwrap.dedent(dev_dependencies), " " * 8)
    if features:
        text += "\n[features]\n"
        text += textwrap.indent(textwrap.dedent(features), " " * 8)
    return textwrap.dedent(text)


BASE_FILES: dict[str, str] = {
    "Cargo.toml": """
        [workspace]
        members = ["crates/*"]

        [workspace.package]
        version = "1.2.3"
    """,
    "crates/netune-trace/Cargo.toml": manifest(name="netune-trace"),
    "crates/netune-io/Cargo.toml": manifest(
        name="netune-io",
        dependencies="""
            netune-trace = { path = "../netune-trace", version = "1.2.3" }
        """,
    ),
    "crates/netune-egress/Cargo.toml": manifest(name="netune-egress"),
    "crates/netune-http1/Cargo.toml": manifest(
        name="netune-http1",
        dev_dependencies="""
            hyper = { version = "1.10", features = ["client", "http1"] }
        """,
    ),
    "crates/netune-http2/Cargo.toml": manifest(name="netune-http2"),
    "crates/netune-ws/Cargo.toml": manifest(
        name="netune-ws",
        dev_dependencies="""
            tokio-tungstenite = "0.28"
        """,
    ),
    "crates/netune/Cargo.toml": manifest(
        name="netune",
        dependencies="""
            netune-http1 = { path = "../netune-http1", version = "1.2.3" }
            netune-trace = { path = "../netune-trace", version = "1.2.3" }
            netune-io = { path = "../netune-io", version = "1.2.3" }
        """,
    ),
    "crates/netune-server/Cargo.toml": manifest(
        name="netune-server",
        dependencies="""
            netune-http1 = { path = "../netune-http1", version = "1.2.3" }
            netune-http2 = { path = "../netune-http2", version = "1.2.3" }
            netune-trace = { path = "../netune-trace", version = "1.2.3" }
            netune-io = { path = "../netune-io", version = "1.2.3" }
        """,
        dev_dependencies="""
            netune = { path = "../netune", version = "1.2.3" }
        """,
    ),
    "crates/netune-probe/Cargo.toml": manifest(
        name="netune-probe",
        features="""
            inject = []
        """,
    ),
    "crates/netune-quic/Cargo.toml": manifest(
        name="netune-quic",
        dependencies="""
            netune-egress = { path = "../netune-egress", version = "1.2.3" }
            netune-io = { path = "../netune-io", version = "1.2.3" }
            netune-trace = { path = "../netune-trace", version = "1.2.3" }
        """,
    ),
    "crates/netune-http3/Cargo.toml": manifest(
        name="netune-http3",
        dependencies="""
            netune-quic = { path = "../netune-quic", version = "1.2.3" }
            netune-trace = { path = "../netune-trace", version = "1.2.3" }
        """,
    ),
    "crates/netune-probe/src/capture.rs": """
        pub struct Capture;

        #[cfg(all(target_os = "linux", feature = "inject"))]
        impl Capture {
            pub fn send_frame(&self, _frame: &[u8]) -> std::io::Result<usize> {
                Ok(0)
            }
        }
    """,
}


def build(root: Path, files: dict[str, str]) -> Path:
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(content).lstrip("\n"), encoding="utf-8")
    return root


def check(files: dict[str, str]) -> list:
    with tempfile.TemporaryDirectory() as raw:
        return check_architecture.Workspace(build(Path(raw), files)).run()


def merged(**overrides: str) -> dict[str, str]:
    files = dict(BASE_FILES)
    files.update(overrides)
    return files


def expect(rule: str, files: dict[str, str], *, message: str) -> None:
    if not any(v.rule == rule for v in check(files)):
        FAILURES.append(f"{message}: expected {rule}, got {[v.render() for v in check(files)]}")


def expect_clean(rule: str, files: dict[str, str], *, message: str) -> None:
    violations = [v for v in check(files) if v.rule == rule]
    if violations:
        FAILURES.append(f"{message}: unexpected {rule}: {[v.render() for v in violations]}")


# --- baseline -------------------------------------------------------------


def test_baseline_is_clean() -> None:
    violations = check(BASE_FILES)
    if violations:
        FAILURES.append(f"baseline is not clean: {[v.render() for v in violations]}")


def test_gate_runs_on_the_real_workspace() -> None:
    root = Path(__file__).resolve().parents[2]
    violations = check_architecture.Workspace(root).run()
    if violations:
        FAILURES.append(f"the real workspace violates its own topology: {[v.render() for v in violations]}")


# --- ARCH-001: the allowed-edge table -------------------------------------


def test_leaf_depending_on_an_unlisted_sibling_is_reported() -> None:
    expect(
        "ARCH-001",
        merged(
            **{
                "crates/netune-http2/Cargo.toml": manifest(
                    name="netune-http2",
                    dependencies="""
                        netune-ws = { path = "../netune-ws", version = "1.2.3" }
                    """,
                )
            }
        ),
        message="codec depending on a sibling codec",
    )


def test_declared_leaf_edge_is_allowed() -> None:
    # `netune-io -> netune-trace` is a real edge: `TimedIo` writes a `Recorder`.
    expect_clean("ARCH-001", BASE_FILES, message="the declared io -> trace edge")


def test_ingress_drawing_on_the_http2_leaf_is_allowed() -> None:
    # ADR-0012: one handler serves both protocols, so the ingress orchestrator depends on
    # both codecs. This test exists so that edge cannot be "fixed" back out by a future
    # reader who sees a second codec in the manifest and assumes it is scope creep.
    expect_clean("ARCH-001", BASE_FILES, message="ingress -> http2 leaf")


def test_ingress_drawing_on_the_websocket_leaf_is_still_an_error() -> None:
    # WebSocket ingress is a separate, later decision (ADR-0011). The HTTP/2 edge opened a
    # door; this pins that the WebSocket one is still closed.
    expect(
        "ARCH-001",
        merged(
            **{
                "crates/netune-server/Cargo.toml": manifest(
                    name="netune-server",
                    dependencies="""
                        netune-http1 = { path = "../netune-http1", version = "1.2.3" }
                        netune-http2 = { path = "../netune-http2", version = "1.2.3" }
                        netune-ws = { path = "../netune-ws", version = "1.2.3" }
                        netune-trace = { path = "../netune-trace", version = "1.2.3" }
                        netune-io = { path = "../netune-io", version = "1.2.3" }
                    """,
                )
            }
        ),
        message="ingress -> ws leaf before its decision",
    )


def test_undeclared_crate_is_reported() -> None:
    expect(
        "ARCH-001",
        merged(**{"crates/netune-extra/Cargo.toml": manifest(name="netune-extra")}),
        message="a crate that exists but is not in the topology table",
    )


# --- ARCH-002: orchestrators never depend on each other -------------------


def test_orchestrator_depending_on_the_other_is_reported() -> None:
    expect(
        "ARCH-002",
        merged(
            **{
                "crates/netune/Cargo.toml": manifest(
                    name="netune",
                    dependencies="""
                        netune-server = { path = "../netune-server", version = "1.2.3" }
                    """,
                )
            }
        ),
        message="egress depending on ingress",
    )


def test_interop_dev_dependency_between_orchestrators_is_allowed() -> None:
    # `netune-server`'s interop suite drives ingress from the egress client.
    expect_clean(
        "ARCH-002",
        BASE_FILES,
        message="a dev-only edge between orchestrators",
    )


# --- ARCH-003: leaves never depend on an orchestrator --------------------


def test_leaf_depending_on_an_orchestrator_is_reported() -> None:
    expect(
        "ARCH-003",
        merged(
            **{
                "crates/netune-io/Cargo.toml": manifest(
                    name="netune-io",
                    dependencies="""
                        netune-trace = { path = "../netune-trace", version = "1.2.3" }
                        netune = { path = "../netune", version = "1.2.3" }
                    """,
                )
            }
        ),
        message="leaf depending on an orchestrator",
    )


# --- ARCH-004: probe links none of the stack -----------------------------


def test_probe_depending_on_the_stack_is_reported() -> None:
    expect(
        "ARCH-004",
        merged(
            **{
                "crates/netune-probe/Cargo.toml": manifest(
                    name="netune-probe",
                    dependencies="""
                        netune-trace = { path = "../netune-trace", version = "1.2.3" }
                    """,
                    features="inject = []",
                )
            }
        ),
        message="probe depending on the transport stack",
    )


# --- ARCH-005/006: no third-party protocol runtime ----------------------


def test_tungstenite_in_production_is_reported() -> None:
    expect(
        "ARCH-005",
        merged(
            **{
                "crates/netune-ws/Cargo.toml": manifest(
                    name="netune-ws",
                    dependencies="""
                        tokio-tungstenite = "0.28"
                    """,
                )
            }
        ),
        message="WebSocket runtime in a production graph",
    )


def test_tungstenite_as_a_dev_oracle_is_allowed() -> None:
    expect_clean("ARCH-005", BASE_FILES, message="the differential oracle as a dev-dependency")


def test_hyper_in_production_is_reported() -> None:
    expect(
        "ARCH-006",
        merged(
            **{
                "crates/netune/Cargo.toml": manifest(
                    name="netune",
                    dependencies="""
                        hyper = { version = "1.10", features = ["client", "http1"] }
                    """,
                )
            }
        ),
        message="third-party HTTP client in a production graph",
    )


def test_quic_runtime_in_production_is_reported() -> None:
    expect(
        "ARCH-005",
        merged(
            **{
                "crates/netune/Cargo.toml": manifest(
                    name="netune",
                    dependencies="""
                        quinn = "0.11"
                    """,
                )
            }
        ),
        message="QUIC runtime, which netune cannot shape (ADR-0010)",
    )


# --- ARCH-007/009: one version line -------------------------------------


def test_crate_with_a_literal_version_is_reported() -> None:
    expect(
        "ARCH-007",
        merged(
            **{"crates/netune-http2/Cargo.toml": manifest(name="netune-http2", version_inherited=False)}
        ),
        message="crate pinning its own version",
    )


def test_mismatched_workspace_pin_is_reported() -> None:
    expect(
        "ARCH-009",
        merged(
            **{
                "crates/netune-io/Cargo.toml": manifest(
                    name="netune-io",
                    dependencies="""
                        netune-trace = { path = "../netune-trace", version = "0.0.1" }
                    """,
                )
            }
        ),
        message="path dependency pinned off the workspace version",
    )


def test_path_dependency_without_version_is_reported() -> None:
    expect(
        "ARCH-009",
        merged(
            **{
                "crates/netune-io/Cargo.toml": manifest(
                    name="netune-io",
                    dependencies="""
                        netune-trace = { path = "../netune-trace" }
                    """,
                )
            }
        ),
        message="a workspace dependency with no version to resolve against",
    )


# --- ARCH-008: the transmit path ---------------------------------------


def test_ungated_send_frame_is_reported() -> None:
    expect(
        "ARCH-008",
        merged(
            **{
                "crates/netune-probe/src/capture.rs": """
                    pub struct Capture;

                    impl Capture {
                        pub fn send_frame(&self, _frame: &[u8]) -> std::io::Result<usize> {
                            Ok(0)
                        }
                    }
                """
            }
        ),
        message="transmit path compiled into a default build",
    )


def test_gate_on_the_impl_block_is_accepted() -> None:
    # This is how the real crate does it; pinning the rule to a function-level
    # attribute would fail a correct file.
    expect_clean("ARCH-008", BASE_FILES, message="a gate on the enclosing impl block")


def test_gate_on_the_function_is_accepted() -> None:
    expect_clean(
        "ARCH-008",
        merged(
            **{
                "crates/netune-probe/src/capture.rs": """
                    pub struct Capture;

                    impl Capture {
                        #[cfg(feature = "inject")]
                        pub fn send_frame(&self, _frame: &[u8]) -> std::io::Result<usize> {
                            Ok(0)
                        }
                    }
                """
            }
        ),
        message="a gate on the function itself",
    )


def test_missing_inject_feature_is_reported() -> None:
    expect(
        "ARCH-008",
        merged(
            **{
                "crates/netune-probe/Cargo.toml": manifest(name="netune-probe"),
                "crates/netune-probe/src/capture.rs": "pub struct Capture;\n",
            }
        ),
        message="probe without the inject feature",
    )


# --- driver ----------------------------------------------------------------


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
    print(f"architecture gate self-test clean ({len(tests)} tests)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
