# PyArmor legal stance

> This document is **not legal advice.** It records the project's reasoned legal posture toward PyArmor-protected input and the engineering defaults that posture produces. Anyone whose use of `disrobe` against PyArmor output may implicate copyright, anti-circumvention, or contract law in their jurisdiction is responsible for obtaining their own counsel. See the project-wide [Responsible use](https://github.com/1-3-7/disrobe/blob/main/LEGAL.md) document for the general framing this page specializes.

PyArmor (by Dashingsoft) is the most widely deployed commercial Python obfuscator, spanning a free tier and several paid tiers. Because disrobe ships PyArmor recognizers and peels, the project owes an explicit account of *when* it will act on PyArmor input and *why* that account is defensible. This page is that account, written before the escalation logic it governs - the [Legal](../src/legal.md) page commits the project to a written stance committed to `docs/legal/<protector>-stance.md` before any grey-zone protector escalates from recognition to a full peel. This is that file for PyArmor.

## Traffic-light verdict: AMBER

disrobe classifies every protector on a three-color scale:

| Color | Meaning | Default behavior |
|---|---|---|
| GREEN | Free / open / no commercial EULA restriction on analysis | Deobfuscate by default. |
| **AMBER** | **Mixed: a free tier with permissive reality plus paid tiers with restrictive EULA terms** | **Detect and deobfuscate the free tier by default; gate paid-tier peels behind `--i-have-authorization`.** |
| RED | Protection of third-party copyrighted *content* with no interoperability nexus | Recognize only; never peel. |

**PyArmor is AMBER.** The free tier carries no contractual bar that the project treats as binding on lawful interoperability and security-research analysis, so free-tier detection and deobfuscation run by default. The paid tiers attach EULA terms whose anti-reverse-engineering clauses are jurisdiction-sensitive, so paid-tier peels are gated behind the explicit `--i-have-authorization` flag and never run otherwise.

## EULA tiers and what each one actually restricts

PyArmor's licensing splits the product, and the contractual surface differs by tier. The project's posture tracks that split rather than treating "PyArmor" as one undifferentiated thing.

- **Free tier.** Used without a paid license. The project's posture is that analyzing output you lawfully possess, for interoperability or security research, is not foreclosed by a contract you never formed, and that the statutory interoperability and study rights below govern. Free-tier output is GREEN-equivalent inside the AMBER classification: deobfuscated by default.
- **Basic / Pro paid tiers.** A paid license attaches EULA terms that typically include an anti-reverse-engineering / no-circumvention clause. Whether such a clause is enforceable against a lawful acquirer performing acts the relevant statute *expressly permits* is exactly the jurisdiction-specific question this document refuses to resolve on the user's behalf. disrobe's response is procedural: it does not run paid-tier peels unless the operator asserts authorization via `--i-have-authorization`.
- **Group / enterprise tiers.** Same contractual posture as Pro for the purposes of this stance; the gate is identical.

The gate is an assertion by the operator, not an adjudication by the tool. Passing `--i-have-authorization` is the operator's representation that they are authorized to analyze the input under the statutory framing below; the responsibility for that representation is the operator's.

## DMCA §1201(f) - the U.S. interoperability carve-out

17 U.S.C. §1201(f) is the controlling reason disrobe can ship a circumvention-capable PyArmor peel at all under U.S. law. The provision permits both **the act of circumventing** a technological protection measure **and the development of the tools to do so**, where the activity is undertaken solely to identify and analyze the elements of a program necessary to achieve **interoperability** with an independently created program, and where that information has not otherwise been readily available.

PyArmor is a technological protection measure over a Python program; lifting it to recover the bytecode necessary to interoperate with that program is the paradigm §1201(f) describes. The carve-out is narrow - it is *interoperability*, not a general right to decrypt - and disrobe's defaults reflect that narrowness by gating paid-tier behavior rather than peeling everything unconditionally. disrobe additionally relies on the periodic anti-circumvention exemptions promulgated by the Librarian of Congress, including the security-research exemption renewed and expanded in the 2024 rulemaking. Statutory text: <https://www.law.cornell.edu/uscode/text/17/1201>.

## EU Software Directive Art. 6 - decompilation for interoperability

In the European Union, Article 6 of Directive 2009/24/EC (the Software Directive) permits **decompilation** of a computer program where it is indispensable to obtain the information necessary to achieve the **interoperability** of an independently created program with other programs, provided the conditions of Art. 6(1)(a)-(c) are met: the act is performed by a lawful acquirer (or an authorized person), the interoperability information was not previously readily available, and the acts are confined to the parts of the program necessary for interoperability.

Article 6 is non-overridable by contract within its scope: a EULA clause purporting to forbid the decompilation that Art. 6 permits is, to that extent, ineffective under the Directive's own terms (Art. 8). This is the EU analogue to the §1201(f) reasoning and is why disrobe's free-tier-by-default posture is symmetric across the Atlantic. Separately, **Art. 5(3)** lets a lawful acquirer observe, study, and test a program's functioning to determine its underlying ideas and principles while performing acts they are entitled to perform - the statutory basis for static study of PyArmor-protected bytecode short of full decompilation. Directive text: <https://eur-lex.europa.eu/eli/dir/2009/24>.

## Other jurisdictions

Comparable interoperability and study provisions exist in the United Kingdom (CDPA §50B / §50BA), Canada (Copyright Act s.30.61), Australia (Copyright Act ss.47D-47F), and Japan (Copyright Act Art. 47-3 / 47-6). The project does not represent that its PyArmor handling fits each framework identically; operators in those jurisdictions should consult local counsel. The AMBER gate is the project's lowest-common-denominator response to that variation.

## What the stance produces in the tool

The legal posture above is not aspirational prose; it is wired into defaults:

- **Free-tier PyArmor: detect and deobfuscate by default.** The v8 and v9-pro static peels need no authorization gate.
- **Paid-tier and grey-zone PyArmor: gated.** Paid-tier peels run only with `--i-have-authorization`. Without it, the operation does not run.
- **The `decryption-keys` LLM category is gated by the same flag.** Requesting that category without `--i-have-authorization` fails fast with an authorization-required diagnostic rather than running the peel.
- **Dynamic execution is doubly gated.** PyArmor v6/v7 dynamic-hook and BCC native-body lift each additionally require `--allow-dynamic` / `--allow-bcc` and run under a watchdog; see the [Forensics and malware-safety posture](../src/forensics-safety.md).
- **No third-party PyArmor bytecode in the public corpus.** Fixtures are self-generated or hash-referenced only; the repository ships the *parser*, not protected sample bytes.

## Takedown and rights contact

If you assert that disrobe's PyArmor handling infringes your rights, contact the maintainer before public action via a private security advisory at <https://github.com/1-3-7/disrobe/security/advisories/new>, including the rights asserted, the specific artifact or commit at issue, the action requested, and an authorized representative's contact. The project is operated in good faith and will respond to substantiated, specific concerns. See [Responsible use](https://github.com/1-3-7/disrobe/blob/main/LEGAL.md) for the general procedure.
