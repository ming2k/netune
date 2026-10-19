# Documentation Style & Hyperlink Standards

This document defines link routing, formatting, and tone for every document in `netune`.

---

## 1. Hyperlinks

1. **Relative paths only.** Cross-references use paths relative to the file that contains them:

   ```markdown
   [architecture.md](architecture.md)                        # same directory
   [ADR-0007](../adr/0007-owned-client-websocket-codec.md)   # from docs/how-to/
   [setup.md](../setup.md)                                   # from docs/dev/standards/
   ```
2. **No absolute file URLs.** Never write `/home/...`, `file:///...`, or a hardcoded host that breaks on a fork or mirror.
3. **Every link resolves.** A dead relative link is a defect, not a cosmetic issue. Verify new links before committing.
4. **Anchor hygiene.** Link to headings with GitHub's kebab-case anchors, and keep heading text stable once linked.
5. **Firewall compliance.** Never author a relative link from a public quadrant into `docs/dev/`.

---

## 2. Formatting

1. **One `#` heading per file, on line 1.** Descend `##` → `###`; never skip a level.
2. **Typed code fences.** Every fenced block declares a language: `rust`, `toml`, `bash`, `text`, `yaml`, `markdown`.
3. **Tables for matrices, lists for sequences.** Use `-` for unordered points and `1.` for ordered procedures.
4. **Commands are copy-pasteable.** Include the working directory assumption when it is not obvious.
5. **Line length is not enforced**, but keep prose lines within a readable width; do not hard-wrap inside code blocks.

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
- Do not invent new `INV-*` tags in prose. A new invariant requires an ADR amendment first (see [`invariants.md`](invariants.md)).
