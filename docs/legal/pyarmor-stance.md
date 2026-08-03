# PyArmor legal stance

> This page records the project's legal posture toward PyArmor-protected input and the engineering defaults that posture produces. If your use of `disrobe` against PyArmor output may implicate copyright, anti-circumvention, or contract law in your jurisdiction, you are responsible for obtaining your own counsel. See the project-wide [Responsible use](https://github.com/1-3-7/disrobe/blob/main/LEGAL.md) document for the general framing this page specializes.

PyArmor (by Dashingsoft) is the most widely deployed commercial Python obfuscator. It ships a free tier and several paid tiers. `disrobe` ships PyArmor recognizers and peels, so the project owes an explicit account of *when* it acts on PyArmor input and *why*. The [Legal](../src/legal.md) page commits the project to a written stance in `docs/legal/<protector>-stance.md` before any gray-zone protector escalates from recognition to a full peel. This file is that stance for PyArmor.

## Traffic-light verdict: AMBER

`disrobe` classifies every protector on a three-color scale:

| Color | Meaning | Default behavior |
|---|---|---|
| GREEN | Free / open / no commercial EULA restriction on analysis | Deobfuscate by default. |
| **AMBER** | **Mixed: a free tier with permissive reality plus paid tiers with restrictive EULA terms** | **Detect and deobfuscate the free tier by default; gate paid-tier peels behind `--i-have-authorization`.** |
| RED | Protection of third-party copyrighted *content* with no interoperability nexus | Recognize only; never peel. |

**PyArmor is AMBER.** The free tier carries no contractual bar that the project treats as binding on lawful interoperability and security-research analysis. Free-tier detection and deobfuscation therefore run by default. The paid tiers attach EULA terms whose anti-reverse-engineering clauses are jurisdiction-sensitive. `disrobe` gates paid-tier peels behind the explicit `--i-have-authorization` flag and never runs them without it.

## EULA tiers and what each one actually restricts

PyArmor's licensing splits the product, and the contractual surface differs by tier. The project's posture tracks that split instead of treating "PyArmor" as a single product.

- **Free tier.** Used without a paid license. The project's posture is that a contract you never formed does not foreclose analysis of output you lawfully possess, for interoperability or security research. The statutory interoperability and study rights below govern instead. Free-tier output is GREEN-equivalent inside the AMBER classification: deobfuscated by default.
- **Basic / Pro paid tiers.** A paid license attaches EULA terms that typically include an anti-reverse-engineering / no-circumvention clause. Whether such a clause is enforceable against a lawful acquirer performing acts the relevant statute *expressly permits* is jurisdiction-specific. The project does not resolve that question on the operator's behalf. `disrobe`'s response is procedural: it does not run paid-tier peels unless the operator asserts authorization via `--i-have-authorization`.
- **Group / enterprise tiers.** Same contractual posture as Pro for the purposes of this stance; the gate is identical.

The gate is an assertion by the operator, not an adjudication by the tool. Passing `--i-have-authorization` is the operator's representation that they are authorized to analyze the input under the statutory framing below. The operator carries the responsibility for that representation.

## DMCA §1201(f) - the U.S. interoperability carve-out

17 U.S.C. §1201(f) is the controlling reason `disrobe` can ship a circumvention-capable PyArmor peel at all under U.S. law. The provision permits both **the act of circumventing** a technological protection measure **and the development of the tools to do so**. Two conditions attach: the activity serves solely to identify and analyze the elements of a program necessary to achieve **interoperability** with an independently created program, and that information has not otherwise been readily available.

PyArmor is a technological protection measure over a Python program. Lifting it to recover the bytecode necessary to interoperate with that program is the paradigm §1201(f) describes. The carve-out is narrow. It covers *interoperability*, not a general right to decrypt. `disrobe`'s defaults reflect that narrowness by gating paid-tier behavior instead of peeling everything unconditionally. `disrobe` additionally relies on the periodic anti-circumvention exemptions that the Librarian of Congress promulgates, including the security-research exemption renewed and expanded in the 2024 rulemaking. Statutory text: <https://www.law.cornell.edu/uscode/text/17/1201>.

## EU Software Directive Art. 6 - decompilation for interoperability

In the European Union, Article 6 of Directive 2009/24/EC (the Software Directive) permits **decompilation** of a computer program. The decompilation must be indispensable to obtain the information necessary to achieve the **interoperability** of an independently created program with other programs. Art. 6(1)(a)-(c) sets three conditions: a lawful acquirer (or an authorized person) performs the act, the interoperability information was not previously readily available, and the acts stay confined to the parts of the program necessary for interoperability.

Contract cannot override Article 6 within its scope. A EULA clause that purports to forbid the decompilation Art. 6 permits is ineffective to that extent under the Directive's own terms (Art. 8). That mirrors the §1201(f) reasoning, so `disrobe`'s free-tier-by-default posture is the same in the United States and the EU. Separately, **Art. 5(3)** lets a lawful acquirer observe, study, and test a program's functioning to determine its underlying ideas and principles, while performing acts they are entitled to perform. Art. 5(3) is the statutory basis for static study of PyArmor-protected bytecode short of full decompilation. Directive text: <https://eur-lex.europa.eu/eli/dir/2009/24>.

## Other jurisdictions

Comparable interoperability and study provisions exist in the United Kingdom (CDPA §50B / §50BA), Canada (Copyright Act s.30.61), Australia (Copyright Act ss.47D-47F), and Japan (Copyright Act Art. 47-3 / 47-6). The project does not represent that its PyArmor handling fits each framework identically; operators in those jurisdictions should consult local counsel. The AMBER gate is the project's lowest-common-denominator response to that variation.

## What the stance produces in the tool

The stance is wired into the CLI defaults:

- **Free-tier PyArmor: detect and deobfuscate by default.** The v8 and v9-pro static peels need no authorization gate.
- **Paid-tier and gray-zone PyArmor: gated.** Paid-tier peels run only with `--i-have-authorization`.
- **The same flag gates the `decryption-keys` LLM category.** If you request that category without `--i-have-authorization`, `disrobe` fails fast with an authorization-required diagnostic instead of running the peel.
- **Dynamic execution is confined to the v6/v7 fallback.** That fallback requires `--allow-dynamic` and runs the protected wrapper in a watchdog-controlled subprocess. BCC native-body lifting separately requires `--allow-bcc`, but the lift statically analyzes native blobs in-process. The current CLI does not serialize the resulting BCC lift or emit recovered BCC pseudo-C or source. See the [Forensics and malware-safety posture](../src/forensics-safety.md).
- **No third-party PyArmor bytecode in the public corpus.** Fixtures are self-generated or hash-referenced only; the repository ships the *parser*, not protected sample bytes.

## Takedown and rights contact

If you assert that `disrobe`'s PyArmor handling infringes your rights, contact the maintainer before public action. Use a private security advisory at <https://github.com/1-3-7/disrobe/security/advisories/new>. Include the rights asserted, the specific artifact or commit at issue, the action requested, and an authorized representative's contact. The maintainer operates the project in good faith and responds to substantiated, specific concerns. See [Responsible use](https://github.com/1-3-7/disrobe/blob/main/LEGAL.md) for the general procedure.
