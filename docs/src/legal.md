# Legal

This page states the project's legal policy, its per-protector stances, and the takedown channel. An authorization flag records the user's assertion of permission; it does not establish that a particular use satisfies the applicable law or contract.

## Responsible use

This document states the project's posture, its intended use, and the procedure for legal-adjacent contact. If your use of `disrobe` may implicate copyright, computer-misuse, or contract law in your jurisdiction, obtain your own legal counsel.

### Intended use

`disrobe` is intended for, and supports:

- **Security research and malware analysis.** Reverse-engineering hostile binaries to understand their behavior, build detections, or publish findings.
- **Interoperability research.** Reverse-engineering an artifact you lawfully possess in order to enable interoperation with an independently created program. This applies when no information needed for that interoperation is otherwise readily available.
- **Recovery of your own source.** Reconstructing software you authored and have lost the source for.
- **Education, archaeology, and curation.** Studying program behavior, preserving historical bytecode, teaching reverse-engineering.

`disrobe` is **not** intended for:

- Bypassing technological protection measures applied to copyrighted content you do not own and have no lawful right to access.
- Circumventing license-key validation or terms-of-service enforcement of software you have not lawfully obtained.
- Building or distributing pirated or counterfeit software.
- Producing derivative works that infringe a copyright holder's exclusive rights.

The line between research and infringement is jurisdiction- and fact-specific. Where the line falls is your responsibility, not the project's.

### Statutory framing the project relies on

#### United States: DMCA §1201(f)

17 U.S.C. §1201(f) is the "interoperability" exemption from the anti-circumvention rule. It permits the circumvention of technological protection measures, and the development of tools for that purpose, under two conditions. The activity must be undertaken solely to identify and analyze the elements of a program necessary to achieve interoperability with an independently created program, and the information must not have previously been readily available. `disrobe` is a tool of that kind. See: <https://www.law.cornell.edu/uscode/text/17/1201>.

`disrobe` also relies on the periodic anti-circumvention exemptions promulgated by the Librarian of Congress. Those include the exemptions covering security research, most recently renewed and expanded by the 2024 rulemaking.

#### European Union: Software Directive 2009/24/EC

Article 6 of Directive 2009/24/EC ("the Software Directive") permits decompilation of a computer program where the decompilation is indispensable to obtain the information necessary to achieve the interoperability of an independently created program with other programs. The conditions of paragraphs (a)-(c) must be met. `disrobe` is a tool that supports this analysis. See: <https://eur-lex.europa.eu/eli/dir/2009/24>.

Article 5(3) of the same Directive permits the lawful acquirer of a program to observe, study, or test the functioning of the program in order to determine the underlying ideas and principles. That right covers acts of loading, displaying, running, transmitting, or storing the program which the acquirer is entitled to perform.

#### Other jurisdictions

Comparable provisions exist in the United Kingdom (CDPA §50B/50BA), Canada (Copyright Act s.30.61), Australia (Copyright Act ss.47D-47F), Japan (Copyright Act Art. 47-3/47-6), and elsewhere. Users in those jurisdictions should consult local counsel. The project does not represent that its tools fit those frameworks identically.

### What `disrobe` does and does not ship

- The repository **does not ship** third-party copyrighted obfuscated bytecode in its public test corpus. Test inputs include project-authored fixtures, licensed third-party regression inputs identified in [NOTICE](NOTICE), and samples referenced by hash whose bytes must be fetched separately under their applicable terms.
- The repository **does ship** parsers, decoders, decompilers, and orchestrator wrappers (Ghidra / jadx / CFR / Vineflower / ILSpy / de4dot, headless). Applied to a sample, those can produce output that may be considered a derivative work of that sample under applicable copyright law. Producing that output lawfully is the user's responsibility.

### Responsible disclosure

If you believe a release of `disrobe` is being used to infringe your rights, contact the maintainer before pursuing public action. The project is operated in good faith and responds to substantiated concerns.

### Takedown contact

For copyright concerns, EULA concerns, or any other rights-based contact regarding this repository or its release artifacts:

- Open a private security advisory at <https://github.com/1-3-7/disrobe/security/advisories/new>

Please include: (1) a description of the rights you assert, (2) the specific artifact or commit at issue, (3) a clear statement of the action you are requesting, and (4) the contact information of an authorized representative. Vague or boilerplate notices may not receive a substantive response.

### Warranty disclaimer

The Work is licensed under the Disrobe Source-Available License, Version 1.1, and provided "AS IS" without warranties of any kind (see LICENSE). Nothing on this page modifies that disclaimer or any other term of the License.

### Limitations

This document does not exhaustively enumerate every statute, case, regulation, or contract that may bear on a particular use of `disrobe`. It is a starting point, not a substitute for legal counsel.

## The authorization gate

Legally sensitive recovery paths that expose `--i-have-authorization` require the flag before they run. Passing the flag is your assertion that you are authorized to analyze the input under the statutory framing above. Use is your responsibility.

The same flag unlocks the `decryption-keys` category of the `--llm` sidecar; without it, requesting that category fails with `DR-CLI-0420`.

## What `disrobe` will not do

- It does not ship copyrighted third-party obfuscated bytecode in its public corpus. Fixtures are baked locally from known-good inputs.
- Grey-zone protectors ship recognizers first; escalation to a full peel only happens after a written legal-posture review recorded under [Per-protector stances](#per-protector-stances).
- Local static analysis does not require a network service. `prowl` and optional tool installation make network requests; `serve` exposes the explicitly selected server transport. Consult each command's options before enabling it.

## Per-protector stances

Each section records the project's posture toward one protector's output and the engineering defaults that posture produces. If your use of `disrobe` against that output may implicate copyright, anti-circumvention, or contract law in your jurisdiction, obtain your own counsel.

### Jscrambler

Jscrambler is a commercial JavaScript protection platform. It ships a free tier and paid tiers, and it applies protection as a configurable list of named transforms grouped into obfuscation, optimization, runtime application self-protection (RASP), and code locks. `disrobe` ships a Jscrambler detector, a reverser for each of the 36 transforms, 12 template chains, and an integrity-loop strip, so the project owes an explicit account of *what* it acts on, *when*, and *why*. The project commits to a written stance in this section before any gray-zone protector escalates from recognition to a peel; this is that file for Jscrambler.

This file also serves as the gate document for the whole JavaScript deobfuscation pass. `DR-JSDEOB-0010`, the authorization-required error, names this page whenever a gated reverser refuses to run. The other protectors that pass gates share it and keep their own stance files: [PreEmptive JSDefender](jsdefender-stance.md), [PACE (JS)](pace-js-stance.md), and [Digital.ai / Arxan (JS)](digital-ai-arxan-stance.md).

#### What `disrobe` does to Jscrambler input

The legal posture rests on which transform category the act touches, so each item below states the capability exactly.

- **Detect.** `disrobe` scans the head of the input for a Jscrambler banner, counts hex-suffixed identifiers, and counts self-reference integrity loops. It then runs all 36 transform detectors and reports which transforms are present and which of the four code locks (browser, date, domain, OS) are present. Detection emits a tier label, a confidence, the markers, the detected transform set, and the code-lock set. Nothing more. The tier label is a signature heuristic. It gates nothing.
- **Reverse the obfuscation and optimization transforms.** 21 obfuscation reversers run without an authorization assertion: boolean-to-anything, char-to-ternary, comma-operator unfolding, control-flow flattening, dead-code injection, dot-to-bracket notation, duplicate-literals removal, extend-predicates, function outlining, function reordering, global-variable indirection, identifiers renaming, number-to-string, object-properties sparsing, property-keys obfuscation, property-keys reordering, regex obfuscation, string concealing, string encoding, variable grouping, and variable masking. 5 optimization reversers run on the same terms: assertions removal, constant folding, dead-code elimination, debug-code elimination, and whitespace removal.
- **Strip the integrity loop.** Before any transform reverser runs, `disrobe` removes the self-reference integrity construct, in both its wrapped and bare forms, and reports how many it removed and how many bytes that freed.
- **Reverse the RASP guards only when authorized.** 6 reversers are gated: anti-debugging, anti-monkey-patching, anti-tampering, dead objects, self-defending, and self-healing. Each deletes the matched guard construct. Without the authorization assertion, the tolerant entry point leaves the input unchanged and records the match as skipped with an authorization note, and the strict entry point returns `DR-JSDEOB-0010`.
- **Reverse the code locks only when authorized.** 4 reversers are gated on the same terms: browser lock, date lock, domain lock, and OS lock. Each replaces the matched guard expression with a constant true, so the locked branch becomes reachable for analysis.
- **Run a template chain.** 12 named chains match Jscrambler's published templates. Each runs its transform list in order and reports per-stage statistics. A RASP or code-lock stage inside a chain obeys the same gate as the standalone reverser.
- **What it does not do.** `disrobe` does not execute protected code, recover a runtime key, or defeat a server-side licensing check. It recovers nothing Jscrambler keeps off the static surface. It does not restore original identifier names; the renaming reverser assigns readable placeholders.
- **Validation.** The detector and default pipeline are exercised against seven SHA-pinned free-tier Jscrambler 8.5 protected bundles. Tests check static transform results, parsed output, and recovered literals. The acquired bundles contain no original source, so these checks do not establish behavioral equivalence. The paid templates are the weak point: their configuration files are on file, but their protected output is subscription-gated, so the end-to-end tests for those templates are marked pending rather than passing. There is **no real-sample oracle for the paid RASP and code-lock templates**. Treat those reversers as pattern-grounded, not as a measured defeat of a real protected artifact.

#### Traffic-light verdict: AMBER

`disrobe` classifies every protector on a three-color scale:

| Color | Meaning | Default behavior |
|---|---|---|
| GREEN | Free / open / no commercial EULA restriction on analysis | Deobfuscate by default. |
| **AMBER** | **Commercial protection with mixed, jurisdiction-sensitive EULA terms** | **Detect and reverse obfuscation by default; gate RASP and code-lock reversal behind `--i-have-authorization`.** |
| RED | Protection of third-party copyrighted *content* with no interoperability nexus | Recognize only; never peel. |

**Jscrambler is AMBER.** The split is by capability category, not by license tier. Reversing an obfuscation or optimization transform recovers program structure, so it runs by default. Reversing a RASP guard or a code lock acts on the protection mechanism itself, so it runs only after the operator asserts authorization. The detector's free / paid tier label reports a signature, and it does not decide what runs.

That distinction matters because the two lines do not coincide. Self-defending and dead objects are available in Jscrambler's free tier, and `disrobe` gates both of them anyway. The gate tracks what the construct does, not what the customer paid.

The gate is an assertion by the operator, not an adjudication by the tool. Passing `--i-have-authorization` is the operator's representation that they are authorized to analyze the input for the intended activity. The operator carries that responsibility.

#### The contractual surface

Jscrambler is licensed commercially, and a deployment that embeds its output is typically governed by a EULA or enterprise agreement. The project does not enumerate specific clause text it cannot reliably attribute to a given version or license. It does not represent any clause as enforceable or unenforceable. The posture is procedural: where such an agreement's anti-reverse-engineering or no-circumvention clause might bear on the act, `disrobe` declines to reverse a RASP guard or a code lock absent the operator's explicit authorization assertion. Whether such a clause binds a lawful acquirer performing acts a statute *expressly permits* is a jurisdiction-specific question, and `disrobe` does not answer it for the operator.

#### Statutory scope

[17 U.S.C. §1201(f)](https://www.copyright.gov/title17/92chap12.html#1201) provides a conditional interoperability exception. It requires a lawfully obtained right to use the program and limits the purpose, necessity, use, and disclosure of the information or means involved. It does not establish that every use or distribution of this tool qualifies.

[Directive 2009/24/EC](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32009L0024), Articles 5(3) and 6, addresses study and decompilation under stated conditions; Article 8 makes contrary contractual provisions ineffective within those exceptions. Applicability depends on the activity and the governing law. A product classification or authorization flag does not decide that question.

#### What the stance produces in the tool

The stance is wired into the pass defaults:

- **Detection runs by default.** Identifying Jscrambler, its transforms, and its code locks needs no authorization gate.
- **Obfuscation and optimization reversal runs by default.** The 21 obfuscation reversers and the 5 optimization reversers carry no gate. The integrity-loop strip carries no gate.
- **RASP and code-lock reversal is gated.** The 6 RASP reversers and the 4 code-lock reversers run only after the authorization assertion. Without it, the tolerant path leaves the input unchanged and reports the match as skipped; the strict path returns `DR-JSDEOB-0010`.
- **Template chains inherit the gate.** A chain that includes a RASP or code-lock stage still refuses that stage without the assertion, and reports the skip in its per-stage statistics.
- **Fixture provenance.** The corpus includes seven acquired free-tier Jscrambler 8.5 protected bundles and template configuration files. The acquired bundles have no accompanying original source, so they support static recovery checks only. Paid-tier protected output is not in the corpus.

#### Takedown and rights contact

If you assert that `disrobe`'s Jscrambler handling infringes your rights, contact the maintainer before public action. Use a private security advisory at <https://github.com/1-3-7/disrobe/security/advisories/new>. Include the rights asserted, the specific artifact or commit at issue, the action requested, and an authorized representative's contact. The project operates in good faith and responds to substantiated, specific concerns. See [Responsible use](https://1-3-7.github.io/disrobe/latest/legal.html) for the general procedure.

### JSDefender

PreEmptive Solutions licenses JSDefender as a commercial JavaScript protector. `disrobe` ships a JSDefender recognizer and a static-layer peel, so the project owes an explicit account of *what* it acts on, *when*, and *why*. The project commits to a written stance in this section before any gray-zone protector escalates from recognition to a peel; this is that file for JSDefender.

#### What `disrobe` does to JSDefender input

The legal posture rests on the narrowness of the act, so each item below states the capability exactly.

- **Detect.** `disrobe` matches JSDefender on four self-identifying static markers: the PreEmptive Solutions copyright string, a JSDefender banner, the `_PreEmptive` symbol prefix, and the `__JSD__` runtime token. It adds two structural signals: a `switch` dispatcher paired with a string-array declaration, and a repeated always-true / always-false branch idiom. Each signal raises confidence, and the total is capped at 0.99. Detection emits a family identification, a confidence, and the marker list. Nothing more.
- **Peel the static layers.** When the caller asserts authorization, `disrobe` runs four static reversers in order: string-array recovery, which removes the rotator and inlines decoder call sites; control-flow unflattening of the `switch` dispatcher; dead-code-injection removal; and string-encoding decode. The result reports bytes in, bytes out, and a matched / reversed / skipped count per stage.
- **The peel is generic, not JSDefender-tuned.** Those four reversers are the project's shared static reversers, also used for its Jscrambler and obfuscator.io handling. `disrobe` ships no reverser written against JSDefender's own output shapes. The `_PreEmptive` and `__JSD__` tokens are read as detection markers only; the peel never strips or rewrites them.
- **What it does not do.** `disrobe` recovers nothing that JSDefender keeps off the static surface. It does not defeat a runtime check, recover a hidden key, or restore original identifier names. The peel reverses generic obfuscation on input the operator already possesses.
- **Validation is indirect.** The peel is graded against real output from an independent open-source JavaScript obfuscator, using a differential token oracle taken from the clean source plus two falsification controls that fail if recovery invents tokens or if the raw input already carried them. The JSDefender fixture in the public corpus is synthesized and drives detection only. There is **no real-sample JSDefender oracle**; the project does not ship or test against third-party JSDefender-protected bytes. Treat the peel as a structural deobfuscation aid, not a measured defeat of a real protected artifact.

#### Traffic-light verdict: AMBER, leaning green

`disrobe` classifies every protector on a three-color scale:

| Color | Meaning | Default behavior |
|---|---|---|
| GREEN | Free / open / no commercial EULA restriction on analysis | Deobfuscate by default. |
| **AMBER** | **Commercial protection with mixed, jurisdiction-sensitive EULA terms** | **Detect by default; gate the peel behind `--i-have-authorization`.** |
| RED | Protection of third-party copyrighted *content* with no interoperability nexus | Recognize only; never peel. |

**JSDefender is AMBER, leaning green.** The project records two positions inside AMBER, and JSDefender holds the lighter one. Digital.ai / Arxan and PACE sit at the detect-only position, because what `disrobe` acts on there is a runtime integrity or licensing guard. JSDefender sits lower because every layer the peel touches is generic obfuscation: a string array, a flattened dispatcher, injected dead code, and encoded literals. Reversing those layers recovers program structure. It does not act on a protection mechanism.

The AMBER floor still applies. JSDefender is a commercial product, and its deployment normally attaches EULA terms. Those terms commonly include anti-reverse-engineering or no-circumvention language. Enforceability of that language against a lawful acquirer performing statutorily permitted acts is jurisdiction-sensitive. `disrobe` therefore detects JSDefender by default and runs the static-layer peel only after the caller asserts authorization.

The gate is an assertion by the operator, not an adjudication by the tool. Passing `--i-have-authorization` is the operator's representation that they are authorized to analyze the input for the intended activity. The operator carries that responsibility. The peel entry point refuses to run without the assertion and returns `DR-JSDEOB-0010`, which names the flag and points to the pass-wide gate document, [Jscrambler](jscrambler-stance.md). Detection output names this file as the governing stance.

#### The contractual surface

JSDefender is licensed commercially, and a deployment that embeds its output is typically governed by a EULA. The project does not enumerate specific clause text it cannot reliably attribute to a given version or license. It does not represent any clause as enforceable or unenforceable. The posture is procedural: where a EULA's anti-reverse-engineering or no-circumvention clause might bear on the act, `disrobe` declines to run the peel absent the operator's explicit authorization assertion. Whether such a clause binds a lawful acquirer performing acts a statute *expressly permits* is a jurisdiction-specific question, and `disrobe` does not answer it for the operator.

#### Statutory scope

[17 U.S.C. §1201(f)](https://www.copyright.gov/title17/92chap12.html#1201) provides a conditional interoperability exception. It requires a lawfully obtained right to use the program and limits the purpose, necessity, use, and disclosure of the information or means involved. It does not establish that every use or distribution of this tool qualifies.

[Directive 2009/24/EC](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32009L0024), Articles 5(3) and 6, addresses study and decompilation under stated conditions; Article 8 makes contrary contractual provisions ineffective within those exceptions. Applicability depends on the activity and the governing law. A product classification or authorization flag does not decide that question.

#### What the stance produces in the tool

The posture is wired into the tool's defaults:

- **Detection runs by default.** Identifying JSDefender and reporting its markers needs no authorization gate.
- **The static-layer peel is gated.** Without the authorization assertion the entry point returns `DR-JSDEOB-0010` and does not modify the input.
- **The peel is limited to four generic static reversers.** String-array recovery, control-flow unflattening, dead-code-injection removal, and string-encoding decode. No JSDefender-specific reverser exists.
- **No runtime bypass exists.** `disrobe` ships no defeat of any JSDefender runtime behavior; the gate would govern any such future capability.
- **No third-party JSDefender bytes in the public corpus.** The fixture is synthesized to carry the documented marker shapes and drives detection only. The repository ships the recognizer and the peel logic, not protected sample bytes.

#### Takedown and rights contact

If you assert that `disrobe`'s JSDefender handling infringes your rights, contact the maintainer before public action. Use a private security advisory at <https://github.com/1-3-7/disrobe/security/advisories/new>. Include the rights asserted, the specific artifact or commit at issue, the action requested, and an authorized representative's contact. The project operates in good faith and responds to substantiated, specific concerns. See [Responsible use](https://1-3-7.github.io/disrobe/latest/legal.html) for the general procedure.

### Arxan

Digital.ai Application Protection (formerly Arxan) is a commercial application-hardening product. Its JavaScript output wraps a program in self-identifying integrity guards, checksum loops, and tamper callouts rather than encrypting the program itself. Because `disrobe` ships a Digital.ai / Arxan recognizer and a static-marker strip, the project owes an explicit account of *what* it acts on, *when*, and *why*. The project commits to a written stance in this section before any gray-zone protector escalates from recognition to a peel; this is that file for Digital.ai / Arxan.

#### What `disrobe` does to Digital.ai / Arxan input

The legal posture rests on the narrowness of the act.

- **Detect.** `disrobe` matches the family by its self-identifying static markers: the Digital.ai / Arxan banner comments, the `_ARXAN_` runtime tokens, the `__guard_<hex>` symbol shape, and the implemented guard patterns. Those patterns are the base64 checksum guard, the deterministic XOR checksum loop, and the integrity callout that compares against a constant. Detection emits a family identification and confidence, nothing more.
- **Strip matched static markers.** When authorized, `disrobe` removes those self-identifying static guard fragments so the surrounding application JavaScript reads cleanly for analysis. The patterns stripped are the specific shapes the recognizer keys on, not arbitrary code.
- **What it does not do.** `disrobe` does **not** circumvent Digital.ai / Arxan's runtime anti-tamper or integrity protection. It does not recover hidden keys, defeat a runtime integrity verdict, or reconstruct anything the product keeps off the static surface. The strip removes self-identifying static guard text from input the operator already possesses. It is not a bypass of the commercial runtime protection.
- **Validation is synthetic only.** The tests grade the behavior against synthesized fixtures matching the implemented guard patterns. There is **no real-sample oracle**; the project does not ship or test against third-party Digital.ai / Arxan-protected bytes. Treat the strip as a structural deobfuscation aid, not a measured defeat of a real protected artifact.

#### Traffic-light verdict: AMBER

`disrobe` classifies every protector on a three-color scale:

| Color | Meaning | Default behavior |
|---|---|---|
| GREEN | Free / open / no commercial EULA restriction on analysis | Deobfuscate by default. |
| **AMBER** | **Commercial application-hardening with mixed, jurisdiction-sensitive EULA terms** | **Detect by default; gate the static-marker strip behind `--i-have-authorization`.** |
| RED | Protection of third-party copyrighted *content* with no interoperability nexus | Recognize only; never peel. |

**Digital.ai / Arxan is AMBER.** It is a commercial application-hardening product, and its deployment normally attaches EULA terms. Those terms commonly include anti-reverse-engineering or no-circumvention language. Whether that language is enforceable against a lawful acquirer performing statutorily permitted acts is jurisdiction-sensitive. `disrobe` therefore detects the family by default but runs the static-marker strip only when the operator asserts authorization via `--i-have-authorization`. Any deeper handling of the runtime anti-tamper or integrity protection is **not implemented**; were it ever built, it would sit behind the same explicit authorization gate and never run otherwise.

The gate is an assertion by the operator, not an adjudication by the tool. Passing `--i-have-authorization` is the operator's representation that they are authorized to analyze the input for the intended activity; the responsibility for that representation is the operator's.

#### The contractual surface

Digital.ai / Arxan is licensed commercially, and a deployment that embeds its guards is typically governed by a EULA or enterprise agreement. The project does not enumerate specific clause text it cannot reliably attribute to a given version or license, and it does not represent any clause as enforceable or unenforceable. The posture is procedural: if such an agreement's anti-reverse-engineering or no-circumvention clause might bear on the act, `disrobe` runs the strip only after the operator asserts authorization. Whether such a clause binds a lawful acquirer performing acts a statute *expressly permits* is jurisdiction-specific, and this stance does not resolve that question for the operator.

#### Statutory scope

[17 U.S.C. §1201(f)](https://www.copyright.gov/title17/92chap12.html#1201) provides a conditional interoperability exception. It requires a lawfully obtained right to use the program and limits the purpose, necessity, use, and disclosure of the information or means involved. It does not establish that every use or distribution of this tool qualifies.

[Directive 2009/24/EC](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32009L0024), Articles 5(3) and 6, addresses study and decompilation under stated conditions; Article 8 makes contrary contractual provisions ineffective within those exceptions. Applicability depends on the activity and the governing law. A product classification or authorization flag does not decide that question.

#### What the stance produces in the tool

The stance is wired into the tool's defaults:

- **Detection runs by default.** Identifying the family and reporting its markers needs no authorization gate.
- **The static-marker strip is gated.** It runs only with `--i-have-authorization`. Without the flag, the operation returns an authorization-required error and does not modify the input.
- **No runtime bypass exists.** `disrobe` ships no defeat of the product's runtime anti-tamper or integrity protection; the gate would govern any such future capability.
- **No third-party protected bytes in the public corpus.** Fixtures are synthesized to match the implemented guard patterns. The repository ships the recognizer and strip logic, not protected sample bytes.

#### Takedown and rights contact

If you assert that `disrobe`'s Digital.ai / Arxan handling infringes your rights, contact the maintainer before public action via a private security advisory at <https://github.com/1-3-7/disrobe/security/advisories/new>. Include the rights asserted, the specific artifact or commit at issue, the action requested, and an authorized representative's contact. The project is operated in good faith and will respond to substantiated, specific concerns. See [Responsible use](https://1-3-7.github.io/disrobe/latest/legal.html) for the general procedure.

### PACE

PACE is a commercial application-hardening protector in the anti-piracy and integrity-guard class. The family covers PACE Anti-Piracy, PACE Fusion, and the iLok binding that PACE ships into JavaScript. PACE wraps a program in self-identifying runtime guards rather than encrypting the program itself. Because `disrobe` ships a PACE recognizer and a static-marker strip, the project owes an explicit account of *what* it acts on, *when*, and *why*. The project commits to a written stance in this section before any gray-zone protector escalates from recognition to a peel; this is that file for PACE.

#### What `disrobe` does to PACE input

The legal posture rests on the narrowness of the act, so each item below states the capability exactly.

- **Detect.** `disrobe` matches PACE by its self-identifying static guard markers: the PACE Anti-Piracy / PACE Fusion banner comments, iLok binding tokens, the `__PACE__` and `_PACE_FUSION_` runtime tokens, and the documented static shapes of the presence check and the self-check interval. Detection emits a family identification and confidence, nothing more.
- **Strip static markers.** When authorized, `disrobe` removes those self-identifying static guard fragments (banner comments, the `window['__PACE__'] === undefined` presence-reload check, the `setInterval` self-check, the static `_PACE_FUSION_` config object, the static iLok token assignment) so the surrounding application JavaScript reads cleanly for analysis.
- **What it does not do.** `disrobe` does **not** circumvent PACE's runtime anti-tamper or integrity protection. It does not recover an iLok-bound key, defeat a license check at runtime, or reconstruct anything PACE keeps off the static surface. The strip removes self-identifying static guard text from input the operator already possesses. That is a text edit, not a bypass of the commercial runtime protection.
- **Validation is synthetic only.** `disrobe` grades the PACE behavior against synthesized fixtures matching the implemented marker patterns. There is **no real-sample oracle**; the project does not ship or test against third-party PACE-protected bytes. Treat the strip as a structural deobfuscation aid, not a measured defeat of a real protected artifact.

#### Traffic-light verdict: AMBER

`disrobe` classifies every protector on a three-color scale:

| Color | Meaning | Default behavior |
|---|---|---|
| GREEN | Free / open / no commercial EULA restriction on analysis | Deobfuscate by default. |
| **AMBER** | **Commercial application-hardening with mixed, jurisdiction-sensitive EULA terms** | **Detect by default; gate the static-marker strip behind `--i-have-authorization`.** |
| RED | Protection of third-party copyrighted *content* with no interoperability nexus | Recognize only; never peel. |

**PACE is AMBER.** It is a commercial application-hardening product, and its deployment normally attaches EULA terms. Those terms commonly include anti-reverse-engineering or no-circumvention language. Enforceability of that language against a lawful acquirer performing statutorily permitted acts is jurisdiction-sensitive. `disrobe` therefore detects PACE by default but runs the static-marker strip only when the operator asserts authorization via `--i-have-authorization`. Any deeper handling of the runtime anti-tamper or integrity protection is **not implemented**; were it ever built, it would sit behind the same explicit authorization gate and never run otherwise.

The gate is an assertion by the operator, not an adjudication by the tool. Passing `--i-have-authorization` is the operator's representation that they are authorized to analyze the input for the intended activity. The operator carries that responsibility.

#### The contractual surface

PACE is licensed commercially, and a deployment that embeds its guards is typically governed by a EULA. The project does not enumerate specific clause text it cannot reliably attribute to a given version or license. It does not represent any clause as enforceable or unenforceable. The posture is procedural: where a EULA's anti-reverse-engineering or no-circumvention clause might bear on the act, `disrobe` declines to run the strip absent the operator's explicit authorization assertion. Whether such a clause binds a lawful acquirer performing acts a statute *expressly permits* is a jurisdiction-specific question, and `disrobe` does not answer it for the operator.

#### Statutory scope

[17 U.S.C. §1201(f)](https://www.copyright.gov/title17/92chap12.html#1201) provides a conditional interoperability exception. It requires a lawfully obtained right to use the program and limits the purpose, necessity, use, and disclosure of the information or means involved. It does not establish that every use or distribution of this tool qualifies.

[Directive 2009/24/EC](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32009L0024), Articles 5(3) and 6, addresses study and decompilation under stated conditions; Article 8 makes contrary contractual provisions ineffective within those exceptions. Applicability depends on the activity and the governing law. A product classification or authorization flag does not decide that question.

#### What the stance produces in the tool

The posture is wired into the tool's defaults:

- **Detection runs by default.** Identifying PACE and reporting its markers needs no authorization gate.
- **The static-marker strip is gated.** It runs only with `--i-have-authorization`. Without the flag, the operation returns an authorization-required error and does not modify the input.
- **No runtime bypass exists.** `disrobe` ships no defeat of PACE's runtime anti-tamper, integrity, or iLok-binding protection; the gate would govern any such future capability.
- **No third-party PACE bytes in the public corpus.** The project synthesizes fixtures matching the implemented marker patterns. The repository ships the recognizer and strip logic, not protected sample bytes.

#### Takedown and rights contact

If you assert that `disrobe`'s PACE handling infringes your rights, contact the maintainer before public action. Use a private security advisory at <https://github.com/1-3-7/disrobe/security/advisories/new>. Include the rights asserted, the specific artifact or commit at issue, the action requested, and an authorized representative's contact. The project operates in good faith and responds to substantiated, specific concerns. See [Responsible use](https://1-3-7.github.io/disrobe/latest/legal.html) for the general procedure.

### PyArmor

PyArmor is a commercial Python obfuscator. This page records Disrobe's handling of protected input and the limits of its authorization controls.

#### Input handling and authorization

Disrobe classifies PyArmor as AMBER because permission to analyze protected output depends on the operator's rights and the applicable law and contract. A free or paid license tier alone does not determine those rights.

The dedicated `pyarmor unpack` command does not enforce a free-versus-paid authorization gate. Its static v8/v9 recovery paths are available without `--i-have-authorization`; callers must establish permission independently. The `decryption-keys` LLM category separately requires that assertion. This flag records the user's assertion and does not establish legal permission.

Dynamic execution in the v6/v7 fallback requires `--allow-dynamic` and runs the wrapper in a watchdog-controlled subprocess. BCC native-body lifting separately requires `--allow-bcc` and analyzes native blobs in process. These flags select technical behavior; they do not grant rights to the input. See [Forensics and malware safety](../src/forensics-safety.md).

#### Statutory scope

[17 U.S.C. §1201(f)](https://www.copyright.gov/title17/92chap12.html#1201) provides a conditional interoperability exception. It requires a lawfully obtained right to use the program and limits the purpose, necessity, use, and disclosure of the information or means involved. It does not establish that every use or distribution of this tool qualifies.

[Directive 2009/24/EC](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32009L0024), Articles 5(3) and 6, addresses study and decompilation under stated conditions; Article 8 makes contrary contractual provisions ineffective within those exceptions. Applicability depends on the activity and the governing law. A product classification or authorization flag does not decide that question.

#### Takedown and rights contact

If you assert that `disrobe`'s PyArmor handling infringes your rights, contact the maintainer before public action. Use a private security advisory at <https://github.com/1-3-7/disrobe/security/advisories/new>. Include the rights asserted, the specific artifact or commit at issue, the action requested, and an authorized representative's contact. The maintainer operates the project in good faith and responds to substantiated, specific concerns. See [Responsible use](https://1-3-7.github.io/disrobe/latest/legal.html) for the general procedure.

## License

`disrobe` is proprietary, source-available software under the [Disrobe Source-Available License, Version 1.1](https://github.com/1-3-7/disrobe/blob/main/LICENSE), which supersedes the Elastic License 2.0 and Version 1.0 for every version as described in the [relicensing notice](https://github.com/1-3-7/disrobe/blob/main/RELICENSING-NOTICE.md). Free use is limited to individuals' own hobby projects, learning, and independent security research, nonprofit education and research, and bona fide journalism. Any use by or for a company or other for-profit organization requires a prior signed paid license; see [commercial licensing](https://github.com/1-3-7/disrobe/blob/main/COMMERCIAL.md). Redistribution, forks other than for contributing, rebranding, hosted or embedded offerings, and building competing products from exposure to Disrobe are prohibited. Every publication, report, filing, or deliverable that used Disrobe or its output must carry the credit "This work used Disrobe, created by 1-3-7: https://github.com/1-3-7/disrobe"; see the [attribution guide](https://github.com/1-3-7/disrobe/blob/main/ATTRIBUTION.md). The software is provided as is, and its author has no responsibility for how anyone uses it. Contributions require accepting the [contributor terms](https://github.com/1-3-7/disrobe/blob/main/CONTRIBUTING-LICENSE.md). The [LICENSE](https://github.com/1-3-7/disrobe/blob/main/LICENSE) and [NOTICE](https://github.com/1-3-7/disrobe/blob/main/NOTICE) govern; the [plain-language summary](https://github.com/1-3-7/disrobe/blob/main/LICENSE-SUMMARY.md) is not the license.
