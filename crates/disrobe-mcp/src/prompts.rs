use rmcp::ErrorData;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{PromptMessage, Role};
use serde::Deserialize;

use super::DisrobeMcp;

const MAX_PROMPT_ARGUMENT_BYTES: usize = 4096;

#[derive(Debug, Deserialize, rmcp::schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(crate = "rmcp::schemars")]
pub(super) struct TargetPromptArgs {
    pub path: String,
}

#[derive(Debug, Deserialize, rmcp::schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(crate = "rmcp::schemars")]
pub(super) struct TraceFeatureArgs {
    pub path: String,
    pub feature: String,
}

#[derive(Debug, Deserialize, rmcp::schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(crate = "rmcp::schemars")]
pub(super) struct ExplainFunctionArgs {
    pub path: String,
    pub function: String,
}

const EVIDENCE_RULE: &str = "Report evidence, not impressions: cite the target's sha256, virtual addresses, file offsets and the tool that produced each fact. When a tool refuses (a DR-* code), quote the code and its reason as the finding instead of guessing past it. Record conclusions with add_note so later steps and later sessions see them.";

#[rmcp::prompt_router(vis = "pub(super)")]
#[allow(clippy::unused_self)]
impl DisrobeMcp {
    #[rmcp::prompt(
        name = "triage",
        description = "First look at a file: identity, build and packer evidence, layout, strings, behaviour, and a plan for the next step."
    )]
    fn triage_prompt(
        &self,
        Parameters(args): Parameters<TargetPromptArgs>,
    ) -> Result<Vec<PromptMessage>, ErrorData> {
        let path: &str = prompt_argument("path", &args.path)?;
        Ok(steps(
            &format!("Triage {path} with the disrobe tools."),
            &[
                format!("open_target with path \"{path}\": note target_id, size, sha256, format and architecture, or the reason it is not a native image."),
                format!("run_command with command [\"identify\"] and args [\"{path}\"] for the compiler, linker, packer or protector and the disrobe pass that handles it; for non-native inputs use command [\"detect\"]."),
                "target_layout with the target_id: sections, imports and exports. Executable sections whose file size is far below their virtual size, with few imports, point at a packer.".to_owned(),
                "find_strings with the target_id (referenced_only true first): URLs, paths, registry keys, commands and error text, each with the functions that reference it.".to_owned(),
                "behavior with the target_id: capability categories and ATT&CK techniques with the evidence behind each.".to_owned(),
                "Plan: if packed or protected, continue with the unpack_and_decompile prompt; if managed or script code, run_command [\"auto\"] on the file; otherwise pick entry points and the functions behind interesting strings and continue with explain_function or trace_feature.".to_owned(),
            ],
        ))
    }

    #[rmcp::prompt(
        name = "unpack_and_decompile",
        description = "Peel packers and protectors off a file and decompile what they hid."
    )]
    fn unpack_and_decompile_prompt(
        &self,
        Parameters(args): Parameters<TargetPromptArgs>,
    ) -> Result<Vec<PromptMessage>, ErrorData> {
        let path: &str = prompt_argument("path", &args.path)?;
        Ok(steps(
            &format!("Unpack and decompile {path} with the disrobe tools."),
            &[
                format!("open_target with path \"{path}\" and record its sha256."),
                format!("run_command with command [\"identify\"] and args [\"{path}\"]; name the packer or protector and its version from the evidence it reports."),
                format!("run_command with command [\"auto\"] and args [\"{path}\"]: the chain unpacks, deobfuscates and decompiles layer by layer. Read the per-pass verdicts in its JSON and the files it wrote under the run directory (outputs lists each with size and sha256)."),
                format!("For a native packer the chain does not cover, run_command [\"native\", \"unpack\"] with args [\"{path}\"]."),
                "open_target on each recovered image from the outputs listing (paths are relative to run_dir), then list_functions and decompile_function on its entry point and the functions behind its strings.".to_owned(),
                "Compare the original and the recovered image: target_layout of both, and native_match when you need to pair functions across them.".to_owned(),
            ],
        ))
    }

    #[rmcp::prompt(
        name = "trace_feature",
        description = "Find the code behind a string, import or behaviour and follow its callers back to an entry point."
    )]
    fn trace_feature_prompt(
        &self,
        Parameters(args): Parameters<TraceFeatureArgs>,
    ) -> Result<Vec<PromptMessage>, ErrorData> {
        let path: &str = prompt_argument("path", &args.path)?;
        let feature: &str = prompt_argument("feature", &args.feature)?;
        Ok(steps(
            &format!("Trace the code behind \"{feature}\" in {path}."),
            &[
                format!("open_target with path \"{path}\"."),
                format!("find_strings with the target_id and contains \"{feature}\"; if the feature is an import, read target_layout imports; if it is a byte pattern, search_bytes."),
                "references_to on each hit's address: the instructions, pointer slots and switch tables that use it, with the containing function.".to_owned(),
                "locate any address you hold to map it between virtual address, file offset, section and function.".to_owned(),
                "neighborhood with direction \"callers\", or call_path from the entry point to the referencing function to see how execution reaches it.".to_owned(),
                "decompile_function on each function along that path, reading arguments and the conditions that guard the feature.".to_owned(),
                "add_note (kind comment or rename) on the functions you identified, with the evidence addresses.".to_owned(),
            ],
        ))
    }

    #[rmcp::prompt(
        name = "explain_function",
        description = "Explain what one function does, with its callers, callees and the data it touches."
    )]
    fn explain_function_prompt(
        &self,
        Parameters(args): Parameters<ExplainFunctionArgs>,
    ) -> Result<Vec<PromptMessage>, ErrorData> {
        let path: &str = prompt_argument("path", &args.path)?;
        let function: &str = prompt_argument("function", &args.function)?;
        Ok(steps(
            &format!("Explain function {function} in {path}."),
            &[
                format!("open_target with path \"{path}\"."),
                format!("list_functions with the target_id and name_contains \"{function}\" (or use the address directly) to confirm the function's address and size."),
                "disassemble_function for the exact instructions, then decompile_function for the pseudo-C.".to_owned(),
                "references_to the function's address for its callers; neighborhood for callers and callees a few levels out.".to_owned(),
                "read_bytes on the data addresses it loads (tables, keys, strings) and find_strings for the text it references.".to_owned(),
                "Explain inputs, outputs, side effects and the role of each callee, citing addresses; add_note with kind rename for a proposed name and kind comment for the summary.".to_owned(),
            ],
        ))
    }
}

fn prompt_argument<'a>(name: &str, value: &'a str) -> Result<&'a str, ErrorData> {
    let trimmed: &str = value.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_PROMPT_ARGUMENT_BYTES {
        return Err(ErrorData::invalid_params(
            format!(
                "DR-MCP-0850: prompt argument `{name}` must be 1 to {MAX_PROMPT_ARGUMENT_BYTES} bytes"
            ),
            None,
        ));
    }
    Ok(trimmed)
}

fn steps(goal: &str, items: &[String]) -> Vec<PromptMessage> {
    let mut text: String = format!("{goal}\n\nSteps:\n");
    text.extend(
        items
            .iter()
            .enumerate()
            .map(|(index, item): (usize, &String)| format!("{}. {item}\n", index + 1)),
    );
    text.push('\n');
    text.push_str("For anything these tools do not cover (strings over a whole file, IOC extraction, deobfuscation of scripts and bytecode, archive extraction), list_commands shows the read-only CLI subcommands run_command can run.\n\n");
    text.push_str(EVIDENCE_RULE);
    vec![PromptMessage::new_text(Role::User, text)]
}
