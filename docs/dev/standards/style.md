# Documentation Style & Hyperlink Standards

This document defines link routing, formatting, and tone for every document in `netune`.

---

## 1. Hyperlinks

1. **Relative paths only.** Cross-references use paths relative to the file that contains them:

   ```markdown
   [taxonomy.md](taxonomy.md)                               # same directory
   [ADR-0007](../../adr/0007-owned-client-websocket-codec.md) # from docs/dev/standards/
   [setup.md](../setup.md)                                   # from docs/dev/standards/
   ```
2. **No absolute file URLs.** Never write `/home/...`, `file:///...`, or a hardcoded host that breaks on a fork or mirror.
3. **Every link resolves.** A dead relative link is a defect, not a cosmetic issue; `DOC-001` fails the build on one.
4. **Anchor hygiene.** Link to headings with GitHub's kebab-case anchors, and keep heading text stable once linked (`DOC-002`).
5. **Firewall compliance.** Never author a relative link from a public quadrant into `docs/dev/` (`DOC-004`).

---

## 2. Formatting

1. **One `#` heading per file, on line 1.** Descend `##` → `###`; never skip a level (`DOC-008`).
2. **Typed code fences.** Every fenced block declares a language: `rust`, `toml`, `bash`, `text`, `yaml`, `markdown`, `json` (`DOC-007`).
3. **Tables for matrices, lists for sequences.** Use `-` for unordered points and `1.` for ordered procedures.
4. **Commands are copy-pasteable.** Include the working directory assumption when it is not obvious.
5. **Line length is not enforced**, but keep prose lines within a readable width; do not hard-wrap inside code blocks.
6. **`rust` examples are compiled.** A `rust` block becomes a doctest (see [testing.md](../testing.md#6-documentation-examples-are-tests)); use `rust,no_run` for a program that must compile but cannot run in CI.

---

## 3. Tone and Vocabulary

1. **Direct and factual.** State what the system does and what enforces it. Avoid marketing language and pseudo-academic jargon.
2. **Mechanisms over aspirations.** Prefer "the decoder rejects a masked inbound frame with close code 1002" to "masking is handled correctly".
3. **No ghost history.** Do not cite commit SHAs, external decision numbers, or repositories that are not reachable from this one.
4. **Name the type.** When describing behaviour, name the type, method, or test that owns it.

---

## 4. Writing About Invariants

- Cite an invariant by its full tag and family: `[INV-WS-02]`.
- Pair it with its enforcement: "…enforced by `masking_direction` in `netune-ws`".
- Do not invent new `INV-*` tags in prose. A new invariant requires an ADR amendment first (see [`invariants.md`](../invariants.md)).
