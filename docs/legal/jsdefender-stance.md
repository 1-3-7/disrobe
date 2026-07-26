# PreEmptive JSDefender legal stance

> This page records the project's legal posture toward JSDefender-protected JavaScript input and the engineering defaults that posture produces. If your use of `disrobe` against JSDefender output may implicate copyright, anti-circumvention, or contract law in your jurisdiction, you are responsible for obtaining your own counsel. See the project-wide [Responsible use](https://github.com/1-3-7/disrobe/blob/main/LEGAL.md) document for the general framing this page specializes.

PreEmptive Solutions licenses JSDefender as a commercial JavaScript protector. `disrobe` ships a JSDefender recognizer and a static-layer peel, so the project owes an explicit account of *what* it acts on, *when*, and *why*. The [Legal](../src/legal.md) page commits the project to a written stance in `docs/legal/<protector>-stance.md` before any grey-zone protector escalates from recognition to a peel; this is that file for JSDefender.

## What `disrobe` does to JSDefender input

The legal posture rests on the narrowness of the act, so each item below states the capability exactly.

- **Detect.** `disrobe` matches JSDefender on four self-identifying static markers: the PreEmptive Solutions copyright string, a JSDefender banner, the `_PreEmptive` symbol prefix, and the `__JSD__` runtime token. It adds two structural signals: a `switch` dispatcher paired with a string-array declaration, and a repeated always-true / always-false branch idiom. Each signal raises confidence, and the total is capped at 0.99. Detection emits a family identification, a confidence, and the marker list. Nothing more.
- **Peel the static layers.** When the caller asserts authorization, `disrobe` runs four static reversers in order: string-array recovery, which removes the rotator and inlines decoder call sites; control-flow unflattening of the `switch` dispatcher; dead-code-injection removal; and string-encoding decode. The result reports bytes in, bytes out, and a matched / reversed / skipped count per stage.
- **The peel is generic, not JSDefender-tuned.** Those four reversers are the project's shared static reversers, also used for its Jscrambler and obfuscator.io handling. `disrobe` ships no reverser written against JSDefender's own output shapes. The `_PreEmptive` and `__JSD__` tokens are read as detection markers only; the peel never strips or rewrites them.
- **What it does not do.** `disrobe` recovers nothing that JSDefender keeps off the static surface. It does not defeat a runtime check, recover a hidden key, or restore original identifier names. The peel reverses generic obfuscation on input the operator already possesses.
- **Validation is indirect.** The peel is graded against real output from an independent open-source JavaScript obfuscator, using a differential token oracle taken from the clean source plus two falsification controls that fail if recovery invents tokens or if the raw input already carried them. The JSDefender fixture in the public corpus is synthesized and drives detection only. There is **no real-sample JSDefender oracle**; the project does not ship or test against third-party JSDefender-protected bytes. Treat the peel as a structural deobfuscation aid, not a measured defeat of a real protected artifact.

## Traffic-light verdict: AMBER, leaning green

`disrobe` classifies every protector on a three-color scale:

| Color | Meaning | Default behavior |
|---|---|---|
| GREEN | Free / open / no commercial EULA restriction on analysis | Deobfuscate by default. |
| **AMBER** | **Commercial protection with mixed, jurisdiction-sensitive EULA terms** | **Detect by default; gate the peel behind `--i-have-authorization`.** |
| RED | Protection of third-party copyrighted *content* with no interoperability nexus | Recognize only; never peel. |

**JSDefender is AMBER, leaning green.** The project records two positions inside AMBER, and JSDefender holds the lighter one. Digital.ai / Arxan and PACE sit at the detect-only position, because what `disrobe` acts on there is a runtime integrity or licensing guard. JSDefender sits lower because every layer the peel touches is generic obfuscation: a string array, a flattened dispatcher, injected dead code, and encoded literals. Reversing those layers recovers program structure. It does not act on a protection mechanism.

The AMBER floor still applies. JSDefender is a commercial product, and its deployment normally attaches EULA terms. Those terms commonly include anti-reverse-engineering or no-circumvention language. Enforceability of that language against a lawful acquirer performing statutorily permitted acts is jurisdiction-sensitive. `disrobe` therefore detects JSDefender by default and runs the static-layer peel only after the caller asserts authorization.

The gate is an assertion by the operator, not an adjudication by the tool. Passing `--i-have-authorization` is the operator's representation that they are authorized to analyze the input under the statutory framing below. The operator carries that responsibility. The peel entry point refuses to run without the assertion and returns `DR-JSDEOB-0010`, which names the flag and points to the pass-wide gate document, [Jscrambler](jscrambler-stance.md). Detection output names this file as the governing stance.

## The contractual surface

JSDefender is licensed commercially, and a deployment that embeds its output is typically governed by a EULA. The project does not enumerate specific clause text it cannot reliably attribute to a given version or license. It does not represent any clause as enforceable or unenforceable. The posture is procedural: where a EULA's anti-reverse-engineering or no-circumvention clause might bear on the act, `disrobe` declines to run the peel absent the operator's explicit authorization assertion. Whether such a clause binds a lawful acquirer performing acts a statute *expressly permits* is a jurisdiction-specific question, and `disrobe` does not answer it for the operator.

## DMCA §1201(f) - the U.S. interoperability carve-out

17 U.S.C. §1201(f) is the controlling reason `disrobe` can ship a JSDefender peel at all under U.S. law. The provision permits the act of analyzing a technological protection measure, and it permits the development of tools to do so. Two conditions apply: the activity is undertaken solely to identify and analyze the elements of a program necessary to achieve **interoperability** with an independently created program, and that information has not otherwise been readily available.

Unflattening a dispatcher and inlining a string array surfaces the underlying application JavaScript for interoperability analysis. That act sits squarely within what §1201(f) describes, and it is narrower than the provision allows: `disrobe` reverses static obfuscation on lawfully possessed input rather than defeating a protection measure. The carve-out is *interoperability*, not a general decryption right, and the AMBER gate reflects that narrowness. `disrobe` additionally relies on the periodic anti-circumvention exemptions promulgated by the Librarian of Congress, including the security-research exemption renewed and expanded in the 2024 rulemaking. Statutory text: <https://www.law.cornell.edu/uscode/text/17/1201>.

## EU Software Directive Art. 6 - decompilation for interoperability

In the European Union, Article 6 of Directive 2009/24/EC (the Software Directive) permits decompilation of a computer program where decompilation is indispensable to obtain the information necessary to achieve the **interoperability** of an independently created program with other programs. Art. 6(1)(a)-(c) sets the conditions: the act is performed by a lawful acquirer (or an authorized person), the interoperability information was not previously readily available, and the acts are confined to the parts of the program necessary for interoperability.

Article 6 is non-overridable by contract within its scope (Art. 8): a EULA clause purporting to forbid the decompilation that Art. 6 permits is, to that extent, ineffective under the Directive's own terms. This is the EU analogue to the §1201(f) reasoning. Separately, **Art. 5(3)** lets a lawful acquirer observe, study, and test a program's functioning to determine its underlying ideas and principles while performing acts they are entitled to perform. That provision is the statutory basis for static study of JSDefender-protected JavaScript short of full decompilation, which is what the static-layer peel supports. Directive text: <https://eur-lex.europa.eu/eli/dir/2009/24>.

## Other jurisdictions

Comparable interoperability and study provisions exist in the United Kingdom (CDPA §50B / §50BA), Canada (Copyright Act s.30.61), Australia (Copyright Act ss.47D-47F), and Japan (Copyright Act Art. 47-3 / 47-6). The project does not represent that its JSDefender handling fits each framework identically; operators in those jurisdictions should consult local counsel. The AMBER gate is the project's lowest-common-denominator response to that variation.

## What the stance produces in the tool

The posture is wired into the tool's defaults:

- **Detection runs by default.** Identifying JSDefender and reporting its markers needs no authorization gate.
- **The static-layer peel is gated.** Without the authorization assertion the entry point returns `DR-JSDEOB-0010` and does not modify the input.
- **The peel is limited to four generic static reversers.** String-array recovery, control-flow unflattening, dead-code-injection removal, and string-encoding decode. No JSDefender-specific reverser exists.
- **No runtime bypass exists.** `disrobe` ships no defeat of any JSDefender runtime behavior; the gate would govern any such future capability.
- **No third-party JSDefender bytes in the public corpus.** The fixture is synthesized to carry the documented marker shapes and drives detection only. The repository ships the recognizer and the peel logic, not protected sample bytes.

## Takedown and rights contact

If you assert that `disrobe`'s JSDefender handling infringes your rights, contact the maintainer before public action. Use a private security advisory at <https://github.com/1-3-7/disrobe/security/advisories/new>. Include the rights asserted, the specific artifact or commit at issue, the action requested, and an authorized representative's contact. The project operates in good faith and responds to substantiated, specific concerns. See [Responsible use](https://github.com/1-3-7/disrobe/blob/main/LEGAL.md) for the general procedure.
