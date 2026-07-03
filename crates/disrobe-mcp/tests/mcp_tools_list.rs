#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use disrobe_mcp::DisrobeMcp;
use rmcp::handler::server::tool::ToolRouter;

#[test]
fn tools_list_exposes_real_tools_with_object_schemas() {
    let router: ToolRouter<DisrobeMcp> = DisrobeMcp::tool_router();
    let tools: Vec<rmcp::model::Tool> = router.list_all();

    let names: Vec<&str> = tools
        .iter()
        .map(|t: &rmcp::model::Tool| t.name.as_ref())
        .collect();
    for expected in [
        "verify",
        "rename",
        "annot",
        "provenance_lookup",
        "ioc",
        "behavior",
        "strings",
    ] {
        assert!(names.contains(&expected), "missing tool {expected}");
    }
    #[cfg(feature = "chain")]
    for expected in ["auto", "decompile"] {
        assert!(names.contains(&expected), "missing chain tool {expected}");
    }
    let expected_count: usize = if cfg!(feature = "chain") { 9 } else { 7 };
    assert_eq!(
        tools.len(),
        expected_count,
        "expected exactly {expected_count} tools, got {names:?}"
    );

    for t in &tools {
        let schema: &serde_json::Map<String, serde_json::Value> = t.input_schema.as_ref();
        assert_eq!(
            schema
                .get("type")
                .and_then(|v: &serde_json::Value| v.as_str()),
            Some("object"),
            "tool {} input_schema must be an object",
            t.name
        );
        assert!(
            schema
                .get("properties")
                .and_then(|v: &serde_json::Value| v.as_object())
                .is_some_and(|p: &serde_json::Map<String, serde_json::Value>| !p.is_empty()),
            "tool {} must expose non-empty properties",
            t.name
        );
        assert!(
            t.description
                .as_ref()
                .is_some_and(|d: &std::borrow::Cow<'static, str>| !d.is_empty()),
            "tool {} must carry a description",
            t.name
        );
    }

    let verify: &rmcp::model::Tool = tools
        .iter()
        .find(|t: &&rmcp::model::Tool| t.name == "verify")
        .unwrap();
    assert!(verify.input_schema["properties"].get("bytes_b64").is_some());

    let rename: &rmcp::model::Tool = tools
        .iter()
        .find(|t: &&rmcp::model::Tool| t.name == "rename")
        .unwrap();
    assert!(rename.input_schema["properties"].get("old").is_some());
    assert!(rename.input_schema["properties"].get("new").is_some());

    let annot: &rmcp::model::Tool = tools
        .iter()
        .find(|t: &&rmcp::model::Tool| t.name == "annot")
        .unwrap();
    assert!(annot.input_schema["properties"].get("target").is_some());

    let plk: &rmcp::model::Tool = tools
        .iter()
        .find(|t: &&rmcp::model::Tool| t.name == "provenance_lookup")
        .unwrap();
    assert!(plk.input_schema["properties"].get("line").is_some());
    assert!(plk.input_schema["properties"].get("map_json").is_some());

    for name in ["ioc", "behavior", "strings"] {
        let t: &rmcp::model::Tool = tools
            .iter()
            .find(|t: &&rmcp::model::Tool| t.name == name)
            .unwrap();
        assert!(
            t.input_schema["properties"].get("bytes_b64").is_some(),
            "tool {name} must accept bytes_b64"
        );
    }

    #[cfg(feature = "chain")]
    for name in ["auto", "decompile"] {
        let t: &rmcp::model::Tool = tools
            .iter()
            .find(|t: &&rmcp::model::Tool| t.name == name)
            .unwrap();
        assert!(
            t.input_schema["properties"].get("bytes_b64").is_some(),
            "tool {name} must accept bytes_b64"
        );
    }
}
