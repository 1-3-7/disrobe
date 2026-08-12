# SBOM and VEX validation schemas

The CLI integration tests validate emitted documents against these upstream schemas.

- `spdx-2.3.schema.json` is `schemas/spdx-schema.json` from the SPDX 2.3 tag at commit `aadf3b0b8dbbabdb4d880b0fc714255fea436ff7`. The Git blob is `ee61e6686e885f8139c132647fd0b4f483b8fb81`.
- `openvex-0.2.0.schema.json` is `openvex_json_schema.json` from OpenVEX commit `d29fab0c81cfea04159436d54c3edc32947039ac`. The Git blob is `2a6aecb81ad26393c2f173bf70e5280e3dc4f1e8`.

The JSON schema values are unmodified. This checkout adds a final line feed to the SPDX file. SPDX publishes its specification under [CC-BY-3.0](https://github.com/spdx/spdx-spec/blob/v2.3/LICENSE). The OpenVEX specification repository applies [CC0-1.0](https://github.com/openvex/spec/blob/d29fab0c81cfea04159436d54c3edc32947039ac/LICENSE).
