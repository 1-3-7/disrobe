# Standards validation schemas

The CLI integration tests validate emitted documents against these upstream schemas.

- `spdx-2.3.schema.json` is `schemas/spdx-schema.json` from the SPDX 2.3 tag at commit `aadf3b0b8dbbabdb4d880b0fc714255fea436ff7`. The Git blob is `ee61e6686e885f8139c132647fd0b4f483b8fb81`.
- `openvex-0.2.0.schema.json` is `openvex_json_schema.json` from OpenVEX commit `d29fab0c81cfea04159436d54c3edc32947039ac`. The Git blob is `2a6aecb81ad26393c2f173bf70e5280e3dc4f1e8`.
- `sarif-2.1.0.schema.json` is `sarif-2.1/schema/sarif-schema-2.1.0.json` from `oasis-tcs/sarif-spec` commit `a560296ca8c921f3bdb8d4a8db57ab83dae968a7`. The Git blob is `0f58372b548f60c84d20fca77687435e71b3b3a3`.
- `stix-2.1/` holds `schemas/common/` and `schemas/sdos/` files from `oasis-open/cti-stix2-json-schemas` commit `d8d71ec4419c5c6d09ed046a2a04317e5ad6c358`. Only the files the emitted bundle needs are vendored: the three object schemas `sdos/indicator.json`, `sdos/identity.json`, and `sdos/malware-analysis.json`, plus every file they reach through `$ref`. `common/bundle.json` is not vendored because it references every STIX object type; the tests validate the bundle envelope against the specification text and each contained object against its own schema.

No MAEC 5.0 schema is vendored. The `MAECProject/schemas` repository publishes no license file, so the MAEC assertions are written from the schema text instead of validating against a copy of it. The rules the tests enforce come from `package.json` and `behavior.json` at commit `83176eb94ee54b6a8072965a2766c1fda7aea67d`: a package requires `type`, `id`, `schema_version`, and `maec_objects`, `schema_version` must be `5.0`, and a behavior requires `id`, `type`, and `name`.

The JSON schema values are unmodified. This checkout adds a final line feed to the SPDX file.

SPDX publishes its specification under [CC-BY-3.0](https://github.com/spdx/spdx-spec/blob/v2.3/LICENSE). The OpenVEX specification repository applies [CC0-1.0](https://github.com/openvex/spec/blob/d29fab0c81cfea04159436d54c3edc32947039ac/LICENSE). The `oasis-open/cti-stix2-json-schemas` repository applies [BSD-3-Clause](https://github.com/oasis-open/cti-stix2-json-schemas/blob/master/LICENSE). Content in `oasis-tcs/sarif-spec` is contributed under the OASIS Intellectual Property Rights Policy in RF on RAND Terms Mode; see the repository [license terms](https://github.com/oasis-tcs/sarif-spec/blob/a560296ca8c921f3bdb8d4a8db57ab83dae968a7/LICENSE.md).
