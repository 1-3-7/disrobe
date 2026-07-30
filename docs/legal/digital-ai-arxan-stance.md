# Digital.ai / Arxan (JS) legal stance

> This page records the project's legal posture toward Digital.ai / Arxan-protected JavaScript input and the engineering defaults that posture produces. If your use of `disrobe` against Digital.ai / Arxan output may implicate copyright, anti-circumvention, or contract law in your jurisdiction, you are responsible for obtaining your own counsel. See the project-wide [Responsible use](https://github.com/1-3-7/disrobe/blob/main/LEGAL.md) document for the general framing this page specializes.

Digital.ai Application Protection (formerly Arxan) is a commercial application-hardening product. Its JavaScript output wraps a program in self-identifying integrity guards, checksum loops, and tamper callouts rather than encrypting the program itself. Because `disrobe` ships a Digital.ai / Arxan recognizer and a static-marker strip, the project owes an explicit account of *what* it acts on, *when*, and *why*. The [Legal](../src/legal.md) page commits the project to a written stance in `docs/legal/<protector>-stance.md` before any gray-zone protector escalates from recognition to a peel; this is that file for Digital.ai / Arxan.

## What `disrobe` does to Digital.ai / Arxan input

The legal posture rests on the narrowness of the act.

- **Detect.** `disrobe` matches the family by its self-identifying static markers: the Digital.ai / Arxan banner comments, the `_ARXAN_` runtime tokens, the `__guard_<hex>` symbol shape, and the publicly documented guard patterns. Those patterns are the base64 checksum guard, the deterministic XOR checksum loop, and the integrity callout that compares against a constant. Detection emits a family identification and confidence, nothing more.
- **Strip publicly documented markers.** When authorized, `disrobe` removes those self-identifying static guard fragments so the surrounding application JavaScript reads cleanly for analysis. The patterns stripped are exactly the publicly disclosed shapes the recognizer keys on, not arbitrary code.
- **What it does not do.** `disrobe` does **not** circumvent Digital.ai / Arxan's runtime anti-tamper or integrity protection. It does not recover hidden keys, defeat a runtime integrity verdict, or reconstruct anything the product keeps off the static surface. The strip removes self-identifying static guard text from input the operator already possesses. It is not a bypass of the commercial runtime protection.
- **Validation is synthetic only.** The tests grade the behavior against synthesized fixtures that mimic the public CVE-2024 disclosure and the vendor's published guard shapes. There is **no real-sample oracle**; the project does not ship or test against third-party Digital.ai / Arxan-protected bytes. Treat the strip as a structural deobfuscation aid, not a measured defeat of a real protected artifact.

## Traffic-light verdict: AMBER

`disrobe` classifies every protector on a three-color scale:

| Color | Meaning | Default behavior |
|---|---|---|
| GREEN | Free / open / no commercial EULA restriction on analysis | Deobfuscate by default. |
| **AMBER** | **Commercial application-hardening with mixed, jurisdiction-sensitive EULA terms** | **Detect by default; gate the static-marker strip behind `--i-have-authorization`.** |
| RED | Protection of third-party copyrighted *content* with no interoperability nexus | Recognize only; never peel. |

**Digital.ai / Arxan is AMBER.** It is a commercial application-hardening product, and its deployment normally attaches EULA terms. Those terms commonly include anti-reverse-engineering or no-circumvention language. Whether that language is enforceable against a lawful acquirer performing statutorily permitted acts is jurisdiction-sensitive. `disrobe` therefore detects the family by default but runs the static-marker strip only when the operator asserts authorization via `--i-have-authorization`. Any deeper handling of the runtime anti-tamper or integrity protection is **not implemented**; were it ever built, it would sit behind the same explicit authorization gate and never run otherwise.

The gate is an assertion by the operator, not an adjudication by the tool. Passing `--i-have-authorization` is the operator's representation that they are authorized to analyze the input under the statutory framing below; the responsibility for that representation is the operator's.

## The contractual surface

Digital.ai / Arxan is licensed commercially, and a deployment that embeds its guards is typically governed by a EULA or enterprise agreement. The project does not enumerate specific clause text it cannot reliably attribute to a given version or license, and it does not represent any clause as enforceable or unenforceable. The posture is procedural: if such an agreement's anti-reverse-engineering or no-circumvention clause might bear on the act, `disrobe` runs the strip only after the operator asserts authorization. Whether such a clause binds a lawful acquirer performing acts a statute *expressly permits* is jurisdiction-specific, and this stance does not resolve that question for the operator.

## DMCA §1201(f) - the U.S. interoperability carve-out

17 U.S.C. §1201(f) is the controlling reason `disrobe` can ship a Digital.ai / Arxan marker strip at all under U.S. law. The provision permits both the act of analyzing a technological protection measure and the development of tools to do so. That permission applies only where the activity is undertaken solely to identify and analyze the elements of a program necessary to achieve **interoperability** with an independently created program. It also requires that the information has not otherwise been readily available.

The strip removes self-identifying static guard markers to surface the underlying application JavaScript for interoperability analysis. That act is squarely within what §1201(f) describes, and it is narrower than the provision allows: `disrobe` strips publicly documented static markers on lawfully possessed input rather than defeating the runtime protection. The carve-out is *interoperability*, not a general decryption right, and the AMBER gate reflects that narrowness. `disrobe` additionally relies on the periodic anti-circumvention exemptions promulgated by the Librarian of Congress, including the security-research exemption renewed and expanded in the 2024 rulemaking. Statutory text: <https://www.law.cornell.edu/uscode/text/17/1201>.

## EU Software Directive Art. 6 - decompilation for interoperability

In the European Union, Article 6 of Directive 2009/24/EC (the Software Directive) permits decompilation of a computer program where it is indispensable to obtain the information necessary to achieve the **interoperability** of an independently created program with other programs. The conditions of Art. 6(1)(a)-(c) must be met: the act is performed by a lawful acquirer (or an authorized person), the interoperability information was not previously readily available, and the acts are confined to the parts of the program necessary for interoperability.

Article 6 is non-overridable by contract within its scope (Art. 8): a EULA clause purporting to forbid the decompilation that Art. 6 permits is, to that extent, ineffective under the Directive's own terms. This is the EU analog to the §1201(f) reasoning. Separately, **Art. 5(3)** lets a lawful acquirer observe, study, and test a program's functioning to determine its underlying ideas and principles while performing acts they are entitled to perform. That provision is the statutory basis for static study of Digital.ai / Arxan-guarded JavaScript short of full decompilation, which is what the marker strip supports. Directive text: <https://eur-lex.europa.eu/eli/dir/2009/24>.

## Other jurisdictions

Comparable interoperability and study provisions exist in the United Kingdom (CDPA §50B / §50BA), Canada (Copyright Act s.30.61), Australia (Copyright Act ss.47D-47F), and Japan (Copyright Act Art. 47-3 / 47-6). The project does not represent that its Digital.ai / Arxan handling fits each framework identically; operators in those jurisdictions should consult local counsel. The AMBER gate is the project's lowest-common-denominator response to that variation.

## What the stance produces in the tool

The stance is wired into the tool's defaults:

- **Detection runs by default.** Identifying the family and reporting its markers needs no authorization gate.
- **The static-marker strip is gated.** It runs only with `--i-have-authorization`. Without the flag, the operation returns an authorization-required error and does not modify the input.
- **No runtime bypass exists.** `disrobe` ships no defeat of the product's runtime anti-tamper or integrity protection; the gate would govern any such future capability.
- **No third-party protected bytes in the public corpus.** Fixtures are synthesized to mimic the public CVE-2024 disclosure and vendor-published guard shapes, and they are hash-referenced only. The repository ships the recognizer and strip logic, not protected sample bytes.

## Takedown and rights contact

If you assert that `disrobe`'s Digital.ai / Arxan handling infringes your rights, contact the maintainer before public action via a private security advisory at <https://github.com/1-3-7/disrobe/security/advisories/new>. Include the rights asserted, the specific artifact or commit at issue, the action requested, and an authorized representative's contact. The project is operated in good faith and will respond to substantiated, specific concerns. See [Responsible use](https://github.com/1-3-7/disrobe/blob/main/LEGAL.md) for the general procedure.
