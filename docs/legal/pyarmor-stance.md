# PyArmor legal stance

PyArmor is a commercial Python obfuscator. This page records Disrobe's handling of protected input and the limits of its authorization controls. See [Responsible use](https://github.com/1-3-7/disrobe/blob/main/LEGAL.md) for the project policy and rights contact.

## Input handling and authorization

Disrobe classifies PyArmor as AMBER because permission to analyze protected output depends on the operator's rights and the applicable law and contract. A free or paid license tier alone does not determine those rights.

The dedicated `pyarmor unpack` command does not enforce a free-versus-paid authorization gate. Its static v8/v9 recovery paths are available without `--i-have-authorization`; callers must establish permission independently. The `decryption-keys` LLM category separately requires that assertion. This flag records the user's assertion and does not establish legal permission.

Dynamic execution in the v6/v7 fallback requires `--allow-dynamic` and runs the wrapper in a watchdog-controlled subprocess. BCC native-body lifting separately requires `--allow-bcc` and analyzes native blobs in process. These flags select technical behavior; they do not grant rights to the input. See [Forensics and malware safety](../src/forensics-safety.md).

## Statutory scope

[17 U.S.C. §1201(f)](https://www.copyright.gov/title17/92chap12.html#1201) provides a conditional interoperability exception. It requires a lawfully obtained right to use the program and limits the purpose, necessity, use, and disclosure of the information or means involved. It does not establish that every use or distribution of this tool qualifies.

[Directive 2009/24/EC](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32009L0024), Articles 5(3) and 6, addresses study and decompilation under stated conditions; Article 8 makes contrary contractual provisions ineffective within those exceptions. Applicability depends on the activity and the governing law. A product classification or authorization flag does not decide that question.

## Takedown and rights contact

If you assert that `disrobe`'s PyArmor handling infringes your rights, contact the maintainer before public action. Use a private security advisory at <https://github.com/1-3-7/disrobe/security/advisories/new>. Include the rights asserted, the specific artifact or commit at issue, the action requested, and an authorized representative's contact. The maintainer operates the project in good faith and responds to substantiated, specific concerns. See [Responsible use](https://github.com/1-3-7/disrobe/blob/main/LEGAL.md) for the general procedure.
