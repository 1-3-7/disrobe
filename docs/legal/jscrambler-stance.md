# Jscrambler legal stance

> This page records the project's legal posture toward Jscrambler-protected JavaScript input and the engineering defaults that posture produces. If your use of `disrobe` against Jscrambler output may implicate copyright, anti-circumvention, or contract law in your jurisdiction, you are responsible for obtaining your own counsel. See the project-wide [Responsible use](https://github.com/1-3-7/disrobe/blob/main/LEGAL.md) document for the general framing this page specializes.

Jscrambler is a commercial JavaScript protection platform. It ships a free tier and paid tiers, and it applies protection as a configurable list of named transforms grouped into obfuscation, optimization, runtime application self-protection (RASP), and code locks. `disrobe` ships a Jscrambler detector, a reverser for each of the 36 transforms, 12 template chains, and an integrity-loop strip, so the project owes an explicit account of *what* it acts on, *when*, and *why*. The [Legal](../src/legal.md) page commits the project to a written stance in `docs/legal/<protector>-stance.md` before any grey-zone protector escalates from recognition to a peel; this is that file for Jscrambler.

This file also serves as the gate document for the whole JavaScript deobfuscation pass. `DR-JSDEOB-0010`, the authorization-required error, names this page whenever a gated reverser refuses to run. The other protectors that pass gates share it and keep their own stance files: [PreEmptive JSDefender](jsdefender-stance.md), [PACE (JS)](pace-js-stance.md), and [Digital.ai / Arxan (JS)](digital-ai-arxan-stance.md).

## What `disrobe` does to Jscrambler input

The legal posture rests on which transform category the act touches, so each item below states the capability exactly.

- **Detect.** `disrobe` scans the head of the input for a Jscrambler banner, counts hex-suffixed identifiers, and counts self-reference integrity loops. It then runs all 36 transform detectors and reports which transforms are present and which of the four code locks (browser, date, domain, OS) are present. Detection emits a tier label, a confidence, the markers, the detected transform set, and the code-lock set. Nothing more. The tier label is a signature heuristic. It gates nothing.
- **Reverse the obfuscation and optimization transforms.** 21 obfuscation reversers run without an authorization assertion: boolean-to-anything, char-to-ternary, comma-operator unfolding, control-flow flattening, dead-code injection, dot-to-bracket notation, duplicate-literals removal, extend-predicates, function outlining, function reordering, global-variable indirection, identifiers renaming, number-to-string, object-properties sparsing, property-keys obfuscation, property-keys reordering, regex obfuscation, string concealing, string encoding, variable grouping, and variable masking. 5 optimization reversers run on the same terms: assertions removal, constant folding, dead-code elimination, debug-code elimination, and whitespace removal.
- **Strip the integrity loop.** Before any transform reverser runs, `disrobe` removes the self-reference integrity construct, in both its wrapped and bare forms, and reports how many it removed and how many bytes that freed.
- **Reverse the RASP guards only when authorized.** 6 reversers are gated: anti-debugging, anti-monkey-patching, anti-tampering, dead objects, self-defending, and self-healing. Each deletes the matched guard construct. Without the authorization assertion, the tolerant entry point leaves the input unchanged and records the match as skipped with an authorization note, and the strict entry point returns `DR-JSDEOB-0010`.
- **Reverse the code locks only when authorized.** 4 reversers are gated on the same terms: browser lock, date lock, domain lock, and OS lock. Each replaces the matched guard expression with a constant true, so the locked branch becomes reachable for analysis.
- **Run a template chain.** 12 named chains match Jscrambler's published templates. Each runs its transform list in order and reports per-stage statistics. A RASP or code-lock stage inside a chain obeys the same gate as the standalone reverser.
- **What it does not do.** `disrobe` does not execute protected code, recover a runtime key, or defeat a server-side licensing check. It recovers nothing Jscrambler keeps off the static surface. It does not restore original identifier names; the renaming reverser assigns readable placeholders.
- **Validation.** The detector and the default pipeline are exercised against real free-tier Jscrambler 8.5 protected output. Behavioral grading runs recovered output and original source through a real JavaScript engine and compares the observable results. The paid templates are the weak point: their configuration files are on file, but their protected output is subscription-gated, so the end-to-end tests for those templates are marked pending rather than passing. There is **no real-sample oracle for the paid RASP and code-lock templates**. Treat those reversers as pattern-grounded, not as a measured defeat of a real protected artifact.

## Traffic-light verdict: AMBER

`disrobe` classifies every protector on a three-color scale:

| Color | Meaning | Default behavior |
|---|---|---|
| GREEN | Free / open / no commercial EULA restriction on analysis | Deobfuscate by default. |
| **AMBER** | **Commercial protection with mixed, jurisdiction-sensitive EULA terms** | **Detect and reverse obfuscation by default; gate RASP and code-lock reversal behind `--i-have-authorization`.** |
| RED | Protection of third-party copyrighted *content* with no interoperability nexus | Recognize only; never peel. |

**Jscrambler is AMBER.** The split is by capability category, not by license tier. Reversing an obfuscation or optimization transform recovers program structure, so it runs by default. Reversing a RASP guard or a code lock acts on the protection mechanism itself, so it runs only after the operator asserts authorization. The detector's free / paid tier label reports a signature, and it does not decide what runs.

That distinction matters because the two lines do not coincide. Self-defending and dead objects are available in Jscrambler's free tier, and `disrobe` gates both of them anyway. The gate tracks what the construct does, not what the customer paid.

The gate is an assertion by the operator, not an adjudication by the tool. Passing `--i-have-authorization` is the operator's representation that they are authorized to analyze the input under the statutory framing below. The operator carries that responsibility.

## The contractual surface

Jscrambler is licensed commercially, and a deployment that embeds its output is typically governed by a EULA or enterprise agreement. The project does not enumerate specific clause text it cannot reliably attribute to a given version or license. It does not represent any clause as enforceable or unenforceable. The posture is procedural: where such an agreement's anti-reverse-engineering or no-circumvention clause might bear on the act, `disrobe` declines to reverse a RASP guard or a code lock absent the operator's explicit authorization assertion. Whether such a clause binds a lawful acquirer performing acts a statute *expressly permits* is a jurisdiction-specific question, and `disrobe` does not answer it for the operator.

## DMCA §1201(f) - the U.S. interoperability carve-out

17 U.S.C. §1201(f) is the controlling reason `disrobe` can ship gated Jscrambler reversers at all under U.S. law. The provision permits both **the act of circumventing** a technological protection measure **and the development of the tools to do so**. Two conditions attach: the activity serves solely to identify and analyze the elements of a program necessary to achieve **interoperability** with an independently created program, and that information has not otherwise been readily available.

The two halves of the pass sit at different distances from the provision. Reversing an obfuscation transform is static analysis of a program the operator lawfully possesses, and it needs no carve-out. Reversing a code lock or a RASP guard is the act §1201(f) addresses directly, because a domain lock or an anti-tampering check is a measure that controls access to the program's behavior. Neutralizing one to read the protected branch is the paradigm the provision describes. The carve-out is *interoperability*, not a general right to defeat protection, and `disrobe`'s defaults reflect that narrowness by gating exactly those ten reversers. `disrobe` additionally relies on the periodic anti-circumvention exemptions promulgated by the Librarian of Congress, including the security-research exemption renewed and expanded in the 2024 rulemaking. Statutory text: <https://www.law.cornell.edu/uscode/text/17/1201>.

## EU Software Directive Art. 6 - decompilation for interoperability

In the European Union, Article 6 of Directive 2009/24/EC (the Software Directive) permits **decompilation** of a computer program. The decompilation must be indispensable to obtain the information necessary to achieve the **interoperability** of an independently created program with other programs. Art. 6(1)(a)-(c) sets three conditions: a lawful acquirer (or an authorized person) performs the act, the interoperability information was not previously readily available, and the acts stay confined to the parts of the program necessary for interoperability.

Contract cannot override Article 6 within its scope. A EULA clause that purports to forbid the decompilation Art. 6 permits is ineffective to that extent under the Directive's own terms (Art. 8). That mirrors the §1201(f) reasoning, so `disrobe`'s obfuscation-by-default posture is the same in the United States and the EU. Separately, **Art. 5(3)** lets a lawful acquirer observe, study, and test a program's functioning to determine its underlying ideas and principles while performing acts they are entitled to perform. Art. 5(3) is the statutory basis for static study of Jscrambler-protected JavaScript short of full decompilation, which is what the obfuscation reversers support. Directive text: <https://eur-lex.europa.eu/eli/dir/2009/24>.

## Other jurisdictions

Comparable interoperability and study provisions exist in the United Kingdom (CDPA §50B / §50BA), Canada (Copyright Act s.30.61), Australia (Copyright Act ss.47D-47F), and Japan (Copyright Act Art. 47-3 / 47-6). The project does not represent that its Jscrambler handling fits each framework identically; operators in those jurisdictions should consult local counsel. The AMBER gate is the project's lowest-common-denominator response to that variation.

## What the stance produces in the tool

The stance is wired into the pass defaults:

- **Detection runs by default.** Identifying Jscrambler, its transforms, and its code locks needs no authorization gate.
- **Obfuscation and optimization reversal runs by default.** The 21 obfuscation reversers and the 5 optimization reversers carry no gate. The integrity-loop strip carries no gate.
- **RASP and code-lock reversal is gated.** The 6 RASP reversers and the 4 code-lock reversers run only after the authorization assertion. Without it, the tolerant path leaves the input unchanged and reports the match as skipped; the strict path returns `DR-JSDEOB-0010`.
- **Template chains inherit the gate.** A chain that includes a RASP or code-lock stage still refuses that stage without the assertion, and reports the skip in its per-stage statistics.
- **No third-party protected bytes in the public corpus.** The corpus carries free-tier protected output generated from the project's own input, plus the template configuration files. The repository ships the detector and the reversers, not third-party protected sample bytes.

## Takedown and rights contact

If you assert that `disrobe`'s Jscrambler handling infringes your rights, contact the maintainer before public action. Use a private security advisory at <https://github.com/1-3-7/disrobe/security/advisories/new>. Include the rights asserted, the specific artifact or commit at issue, the action requested, and an authorized representative's contact. The project operates in good faith and responds to substantiated, specific concerns. See [Responsible use](https://github.com/1-3-7/disrobe/blob/main/LEGAL.md) for the general procedure.
