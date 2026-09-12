# PACE (JS) legal stance

> This page records the project's legal posture toward PACE-protected JavaScript input and the engineering defaults that posture produces. If your use of `disrobe` against PACE output may implicate copyright, anti-circumvention, or contract law in your jurisdiction, you are responsible for obtaining your own counsel. See the project-wide [Responsible use](https://github.com/1-3-7/disrobe/blob/main/LEGAL.md) document for the general framing this page specializes.


PACE is a commercial application-hardening protector in the anti-piracy and integrity-guard class. The family covers PACE Anti-Piracy, PACE Fusion, and the iLok binding that PACE ships into JavaScript. PACE wraps a program in self-identifying runtime guards rather than encrypting the program itself. Because `disrobe` ships a PACE recognizer and a static-marker strip, the project owes an explicit account of *what* it acts on, *when*, and *why*. The [Legal](../src/legal.md) page commits the project to a written stance in `docs/legal/<protector>-stance.md` before any gray-zone protector escalates from recognition to a peel; this is that file for PACE.

## What `disrobe` does to PACE input

The legal posture rests on the narrowness of the act, so each item below states the capability exactly.

- **Detect.** `disrobe` matches PACE by its self-identifying static guard markers: the PACE Anti-Piracy / PACE Fusion banner comments, iLok binding tokens, the `__PACE__` and `_PACE_FUSION_` runtime tokens, and the documented static shapes of the presence check and the self-check interval. Detection emits a family identification and confidence, nothing more.
- **Strip static markers.** When authorized, `disrobe` removes those self-identifying static guard fragments (banner comments, the `window['__PACE__'] === undefined` presence-reload check, the `setInterval` self-check, the static `_PACE_FUSION_` config object, the static iLok token assignment) so the surrounding application JavaScript reads cleanly for analysis.
- **What it does not do.** `disrobe` does **not** circumvent PACE's runtime anti-tamper or integrity protection. It does not recover an iLok-bound key, defeat a license check at runtime, or reconstruct anything PACE keeps off the static surface. The strip removes self-identifying static guard text from input the operator already possesses. That is a text edit, not a bypass of the commercial runtime protection.
- **Validation is synthetic only.** `disrobe` grades the PACE behavior against synthesized fixtures matching the implemented marker patterns. There is **no real-sample oracle**; the project does not ship or test against third-party PACE-protected bytes. Treat the strip as a structural deobfuscation aid, not a measured defeat of a real protected artifact.

## Traffic-light verdict: AMBER

`disrobe` classifies every protector on a three-color scale:

| Color | Meaning | Default behavior |
|---|---|---|
| GREEN | Free / open / no commercial EULA restriction on analysis | Deobfuscate by default. |
| **AMBER** | **Commercial application-hardening with mixed, jurisdiction-sensitive EULA terms** | **Detect by default; gate the static-marker strip behind `--i-have-authorization`.** |
| RED | Protection of third-party copyrighted *content* with no interoperability nexus | Recognize only; never peel. |

**PACE is AMBER.** It is a commercial application-hardening product, and its deployment normally attaches EULA terms. Those terms commonly include anti-reverse-engineering or no-circumvention language. Enforceability of that language against a lawful acquirer performing statutorily permitted acts is jurisdiction-sensitive. `disrobe` therefore detects PACE by default but runs the static-marker strip only when the operator asserts authorization via `--i-have-authorization`. Any deeper handling of the runtime anti-tamper or integrity protection is **not implemented**; were it ever built, it would sit behind the same explicit authorization gate and never run otherwise.

The gate is an assertion by the operator, not an adjudication by the tool. Passing `--i-have-authorization` is the operator's representation that they are authorized to analyze the input for the intended activity. The operator carries that responsibility.

## The contractual surface

PACE is licensed commercially, and a deployment that embeds its guards is typically governed by a EULA. The project does not enumerate specific clause text it cannot reliably attribute to a given version or license. It does not represent any clause as enforceable or unenforceable. The posture is procedural: where a EULA's anti-reverse-engineering or no-circumvention clause might bear on the act, `disrobe` declines to run the strip absent the operator's explicit authorization assertion. Whether such a clause binds a lawful acquirer performing acts a statute *expressly permits* is a jurisdiction-specific question, and `disrobe` does not answer it for the operator.

## Statutory scope

[17 U.S.C. §1201(f)](https://www.copyright.gov/title17/92chap12.html#1201) provides a conditional interoperability exception. It requires a lawfully obtained right to use the program and limits the purpose, necessity, use, and disclosure of the information or means involved. It does not establish that every use or distribution of this tool qualifies.

[Directive 2009/24/EC](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32009L0024), Articles 5(3) and 6, addresses study and decompilation under stated conditions; Article 8 makes contrary contractual provisions ineffective within those exceptions. Applicability depends on the activity and the governing law. A product classification or authorization flag does not decide that question.

## What the stance produces in the tool

The posture is wired into the tool's defaults:

- **Detection runs by default.** Identifying PACE and reporting its markers needs no authorization gate.
- **The static-marker strip is gated.** It runs only with `--i-have-authorization`. Without the flag, the operation returns an authorization-required error and does not modify the input.
- **No runtime bypass exists.** `disrobe` ships no defeat of PACE's runtime anti-tamper, integrity, or iLok-binding protection; the gate would govern any such future capability.
- **No third-party PACE bytes in the public corpus.** The project synthesizes fixtures matching the implemented marker patterns. The repository ships the recognizer and strip logic, not protected sample bytes.

## Takedown and rights contact

If you assert that `disrobe`'s PACE handling infringes your rights, contact the maintainer before public action. Use a private security advisory at <https://github.com/1-3-7/disrobe/security/advisories/new>. Include the rights asserted, the specific artifact or commit at issue, the action requested, and an authorized representative's contact. The project operates in good faith and responds to substantiated, specific concerns. See [Responsible use](https://github.com/1-3-7/disrobe/blob/main/LEGAL.md) for the general procedure.
