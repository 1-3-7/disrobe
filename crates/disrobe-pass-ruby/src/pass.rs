use disrobe_core::debug::DebugLog;
use serde::{Deserialize, Serialize};

use crate::detect::{Flavor, sniff};
use crate::jruby::{JrubyDelegation, delegate as jruby_delegate};
use crate::mri::{MriAst, parse_mri};
use crate::mruby::{MrubyAnalysis, analyze as mruby_analyze};
use crate::truffleruby::{TruffleRubyAot, walk as truffle_walk};
use crate::wrappers::{WrapperExtract, extract as wrapper_extract};
use crate::yarv::{YarvAnalysis, analyze as yarv_analyze};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RubyAnalysis {
    pub flavor: Flavor,
    pub source_path: String,
    pub input_len: u32,
    pub input_hash: [u8; 32],
    pub mri: Option<MriAst>,
    pub yarv: Option<YarvAnalysis>,
    pub mruby: Option<MrubyAnalysis>,
    pub jruby: Option<JrubyDelegation>,
    pub truffleruby: Option<TruffleRubyAot>,
    pub wrapper: Option<WrapperExtract>,
}

pub fn analyze_bytes(bytes: &[u8], source_path: &str) -> crate::error::Result<RubyAnalysis> {
    let dbg: DebugLog = DebugLog::for_scope("ruby");
    dbg.section("ruby.analyze");
    dbg.kv("input_len", || bytes.len().to_string());
    let flavor: Flavor = sniff(bytes, source_path)?;
    dbg.kv("flavor", || format!("{flavor:?}"));
    let mut analysis: RubyAnalysis = RubyAnalysis {
        flavor,
        source_path: source_path.to_owned(),
        input_len: u32::try_from(bytes.len()).unwrap_or(u32::MAX),
        input_hash: blake3::hash(bytes).into(),
        mri: None,
        yarv: None,
        mruby: None,
        jruby: None,
        truffleruby: None,
        wrapper: None,
    };
    match flavor {
        Flavor::MriSource => analysis.mri = Some(parse_mri(bytes, source_path)?),
        Flavor::YarvBinary => analysis.yarv = Some(yarv_analyze(bytes)?),
        Flavor::MrubyBinary => analysis.mruby = Some(mruby_analyze(bytes)?),
        Flavor::JrubyClass => analysis.jruby = Some(jruby_delegate(bytes)?),
        Flavor::TruffleRubyAot => analysis.truffleruby = Some(truffle_walk(bytes)?),
        Flavor::Ruby2Exe | Flavor::Ocra => analysis.wrapper = Some(wrapper_extract(bytes)?),
    }
    dbg.line(|| format!("recovered via {flavor:?} branch"));
    Ok(analysis)
}
