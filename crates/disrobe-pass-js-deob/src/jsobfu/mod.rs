mod detect;
mod fold_chars;
mod rewrite;

use serde::Serialize;

pub use detect::{JsObfuDetection, detect_jsobfu};
pub use fold_chars::{CharFoldStats, fold_char_constructors};
pub use rewrite::{JsObfuRewriteStats, rewrite_bracket_access};

use crate::unminify::{AstUnminifyStats, UnminifyStats, unminify, unminify_ast};

const MAX_RECOVER_PASSES: usize = 6;

#[derive(Debug, Clone, Default, Serialize)]
pub struct JsObfuRecovery {
    pub source: String,
    pub char_fold: CharFoldStats,
    pub bracket_rewrite: JsObfuRewriteStats,
    pub passes_run: usize,
}

#[must_use]
pub fn recover(source: &str) -> JsObfuRecovery {
    let mut current: String = source.to_owned();
    let mut recovery: JsObfuRecovery = JsObfuRecovery::default();
    for _ in 0..MAX_RECOVER_PASSES {
        recovery.passes_run += 1;
        let before: String = current.clone();
        let (folded, fold_stats): (String, CharFoldStats) = fold_char_constructors(&current);
        recovery.char_fold.from_char_code_calls_folded += fold_stats.from_char_code_calls_folded;
        recovery.char_fold.string_iifes_folded += fold_stats.string_iifes_folded;
        recovery.char_fold.passes_run += fold_stats.passes_run;
        let (rewritten, rewrite_stats): (String, JsObfuRewriteStats) =
            rewrite_bracket_access(&folded);
        recovery.bracket_rewrite.bracket_to_dot_rewrites += rewrite_stats.bracket_to_dot_rewrites;
        recovery.bracket_rewrite.array_join_folded += rewrite_stats.array_join_folded;
        current = rewritten;
        if current == before {
            break;
        }
    }
    let (peeled, _peephole): (String, UnminifyStats) = unminify(&current);
    let (beautified, _ast): (String, AstUnminifyStats) = unminify_ast(&peeled);
    recovery.source = beautified;
    recovery
}
