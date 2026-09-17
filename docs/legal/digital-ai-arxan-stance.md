# Digital.ai / Arxan (JS) legal stance

> This page records the project's legal posture toward Digital.ai / Arxan-protected JavaScript input and the engineering defaults that posture produces. If your use of `disrobe` against Digital.ai / Arxan output may implicate copyright, anti-circumvention, or contract law in your jurisdiction, you are responsible for obtaining your own counsel. See the project-wide [Responsible use](https://github.com/1-3-7/disrobe/blob/main/LEGAL.md) document for the general framing this page specializes.

Digital.ai Application Protection (formerly Arxan) is a commercial application-hardening product. Its JavaScript output wraps a program in self-identifying integrity guards, checksum loops, and tamper callouts rather than encrypting the program itself. Because `disrobe` ships a Digital.ai / Arxan recognizer and a static-marker strip, the project owes an explicit account of *what* it acts on, *when*, and *why*. The [Legal](../src/legal.md) page commits the project to a written stance in `docs/legal/<protector>-stance.md` before any gray-zone protector escalates from recognition to a peel; this is that file for Digital.ai / Arxan.

## What `disrobe` does to Digital.ai / Arxan input

The legal posture rests on the narrowness of the act.

- **Detect.** `disrobe` matches the family by its self-identifying static markers: the Digital.ai / Arxan banner comments, the `_ARXAN_` runtime tokens, the `__guard_<hex>` symbol shape, and the implemented guard patterns. Those patterns are the base64 checksum guard, the deterministic XOR checksum loop, and the integrity callout that compares against a constant. Detection emits a family identification and confidence, nothing more.
- **Strip matched static markers.** When authorized, `disrobe` removes those self-identifying static guard fragments so the surrounding application JavaScript reads cleanly for analysis. The patterns stripped are the specific shapes the recognizer keys on, not arbitrary code.
- **What it does not do.** `disrobe` does **not** circumvent Digital.ai / Arxan's runtime anti-tamper or integrity protection. It does not recover hidden keys, defeat a runtime integrity verdict, or reconstruct anything the product keeps off the static surface. The strip removes self-identifying static guard text from input the operator already possesses. It is not a bypass of the commercial runtime protection.
- **Validation is synthetic only.** The tests grade the behavior against synthesized fixtures matching the implemented guard patterns. There is **no real-sample oracle**; the project does not ship or test against third-party Digital.ai / Arxan-protected bytes. Treat the strip as a structural deobfuscation aid, not a measured defeat of a real protected artifact.

## Traffic-light verdict: AMBER

`disrobe` classifies every protector on a three-color scale:

| Color | Meaning | Default behavior |
|---|---|---|
| GREEN | Free / open / no commercial EULA restriction on analysis | Deobfuscate by default. |
| **AMBER** | **Commercial application-hardening with mixed, jurisdiction-sensitive EULA terms** | **Detect by default; gate the static-marker strip behind `--i-have-authorization`.** |
| RED | Protection of third-party copyrighted *content* with no interoperability nexus | Recognize only; never peel. |

**Digital.ai / Arxan is AMBER.** It is a commercial application-hardening product, and its deployment normally attaches EULA terms. Those terms commonly include anti-reverse-engineering or no-circumvention language. Whether that language is enforceable against a lawful acquirer performing statutorily permitted acts is jurisdiction-sensitive. `disrobe` therefore detects the family by default but runs the static-marker strip only when the operator asserts authorization via `--i-have-authorization`. Any deeper handling of the runtime anti-tamper or integrity protection is **not implemented**; were it ever built, it would sit behind the same explicit authorization gate and never run otherwise.

The gate is an assertion by the operator, not an adjudication by the tool. Passing `--i-have-authorization` is the operator's representation that they are authorized to analyze the input for the intended activity; the responsibility for that representation is the operator's.

## The contractual surface

Digital.ai / Arxan is licensed commercially, and a deployment that embeds its guards is typically governed by a EULA or enterprise agreement. The project does not enumerate specific clause text it cannot reliably attribute to a given version or license, and it does not represent any clause as enforceable or unenforceable. The posture is procedural: if such an agreement's anti-reverse-engineering or no-circumvention clause might bear on the act, `disrobe` runs the strip only after the operator asserts authorization. Whether such a clause binds a lawful acquirer performing acts a statute *expressly permits* is jurisdiction-specific, and this stance does not resolve that question for the operator.

## Statutory scope

[17 U.S.C. §1201(f)](https://www.copyright.gov/title17/92chap12.html#1201) provides a conditional interoperability exception. It requires a lawfully obtained right to use the program and limits the purpose, necessity, use, and disclosure of the information or means involved. It does not establish that every use or distribution of this tool qualifies.

[Directive 2009/24/EC](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32009L0024), Articles 5(3) and 6, addresses study and decompilation under stated conditions; Article 8 makes contrary contractual provisions ineffective within those exceptions. Applicability depends on the activity and the governing law. A product classification or authorization flag does not decide that question.

## What the stance produces in the tool

The stance is wired into the tool's defaults:

- **Detection runs by default.** Identifying the family and reporting its markers needs no authorization gate.
- **The static-marker strip is gated.** It runs only with `--i-have-authorization`. Without the flag, the operation returns an authorization-required error and does not modify the input.
- **No runtime bypass exists.** `disrobe` ships no defeat of the product's runtime anti-tamper or integrity protection; the gate would govern any such future capability.
- **No third-party protected bytes in the public corpus.** Fixtures are synthesized to match the implemented guard patterns. The repository ships the recognizer and strip logic, not protected sample bytes.

## Takedown and rights contact

If you assert that `disrobe`'s Digital.ai / Arxan handling infringes your rights, contact the maintainer before public action via a private security advisory at <https://github.com/1-3-7/disrobe/security/advisories/new>. Include the rights asserted, the specific artifact or commit at issue, the action requested, and an authorized representative's contact. The project is operated in good faith and will respond to substantiated, specific concerns. See [Responsible use](https://github.com/1-3-7/disrobe/blob/main/LEGAL.md) for the general procedure.
