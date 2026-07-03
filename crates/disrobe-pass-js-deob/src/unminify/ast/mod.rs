mod alias_inline;
mod arg_rest;
mod argument_spread;
mod async_restore;
mod block_statement;
mod bracket_to_dot;
mod chained_assign;
mod conditional_statement;
mod de_morgan;
mod dead_code;
mod default_param;
mod es6_class;
mod exponent;
mod export_rename;
mod for_of;
mod for_to_while;
mod iife_unwrap;
mod import_rename;
mod indirect_call;
mod interop_unwrap;
mod jsx_automatic;
mod jsx_restore;
mod literal_length;
mod literal_logic;
mod literal_normalize;
mod logical_assign;
mod loop_comma_body;
mod mba_simplify;
mod merge_else_if;
mod nullish_coalescing;
mod numeric_literal;
mod object_param;
mod object_shorthand;
mod optional_chaining;
mod regenerator_restore;
mod rename_scope;
mod require_alias;
mod require_destructure;
mod require_member;
mod sequence_split;
mod split_var;
mod spread_clone;
mod spread_rebuild;
mod template_literal;
mod then_catch;
mod type_constructor;
mod undefined_init;
mod var_to_block;

use oxc_allocator::Allocator;
use oxc_parser::Parser;
use oxc_span::SourceType;
use serde::Serialize;

use alias_inline::AliasInlineStats;
use arg_rest::ArgRestStats;
use argument_spread::ArgumentSpreadStats;
use async_restore::AsyncRestoreStats;
use block_statement::BlockStatementStats;
use bracket_to_dot::BracketToDotStats;
use chained_assign::ChainedAssignStats;
use conditional_statement::ConditionalStatementStats;
use de_morgan::DeMorganStats;
use dead_code::DeadCodeStats;
use default_param::DefaultParamStats;
use es6_class::ClassRecoveryStats;
use exponent::ExponentStats;
use export_rename::ExportRenameStats;
use for_of::ForOfStats;
use for_to_while::ForToWhileStats;
use iife_unwrap::IifeUnwrapStats;
use import_rename::ImportRenameStats;
use indirect_call::IndirectCallStats;
use interop_unwrap::InteropUnwrapStats;
use jsx_automatic::JsxAutomaticStats;
use jsx_restore::JsxRestoreStats;
use literal_length::LiteralLengthStats;
use literal_logic::LiteralLogicStats;
use literal_normalize::LiteralNormalizeStats;
use logical_assign::LogicalAssignStats;
use loop_comma_body::LoopCommaBodyStats;
use mba_simplify::MbaSimplifyStats;
use merge_else_if::MergeElseIfStats;
use nullish_coalescing::NullishCoalescingStats;
use numeric_literal::NumericLiteralStats;
use object_param::ObjectParamStats;
use object_shorthand::ObjectShorthandStats;
use optional_chaining::OptionalChainingStats;
use regenerator_restore::RegeneratorRestoreStats;
use require_alias::RequireAliasStats;
use require_destructure::RequireDestructureStats;
use require_member::RequireMemberStats;
use sequence_split::SequenceSplitStats;
use split_var::SplitVarStats;
use spread_clone::SpreadCloneStats;
use spread_rebuild::SpreadRebuildStats;
use template_literal::TemplateLiteralStats;
use then_catch::ThenCatchStats;
use type_constructor::TypeConstructorStats;
use undefined_init::UndefinedInitStats;
use var_to_block::VarToBlockStats;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum RuleStage {
    IifeUnwrap = 0,
    IndirectCall = 1,
    ArgumentSpread = 2,
    AsyncRestore = 3,
    ClassReconstruction = 4,
    SpreadRebuild = 5,
    ObjectParam = 6,
    SplitVar = 7,
    SequenceSplit = 8,
    ChainedAssign = 9,
    LogicalAssign = 10,
    ConditionalStatement = 11,
    MergeElseIf = 12,
    DeMorgan = 13,
    LiteralLogic = 14,
    LiteralNormalize = 15,
    BracketToDot = 16,
    TemplateLiteral = 17,
    OptionalChaining = 18,
    NullishCoalescing = 19,
    ObjectShorthand = 20,
    ForOf = 21,
    AliasInline = 22,
    DeadCode = 23,
    InteropUnwrap = 24,
    JsxRestore = 25,
    JsxAutomatic = 26,
    MbaSimplify = 27,
    LoopCommaBody = 28,
    ForToWhile = 29,
    BlockStatement = 30,
    UndefinedInit = 31,
    VarToBlock = 32,
    NumericLiteral = 33,
    Exponent = 34,
    TypeConstructor = 35,
    ThenCatch = 36,
    DefaultParam = 37,
    ArgRest = 38,
    ImportRename = 39,
    ExportRename = 40,
    LiteralLength = 41,
    SpreadClone = 42,
    RegeneratorRestore = 43,
    RequireAlias = 44,
    RequireDestructure = 45,
    RequireMember = 46,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AstRuleId {
    IifeUnwrap,
    IndirectCall,
    ArgumentSpread,
    AsyncRestore,
    Es6Class,
    SpreadRebuild,
    SplitVar,
    SequenceSplit,
    ChainedAssign,
    ConditionalStatement,
    MergeElseIf,
    DeMorgan,
    LiteralLogic,
    LiteralNormalize,
    BracketToDot,
    TemplateLiteral,
    OptionalChaining,
    NullishCoalescing,
    ObjectShorthand,
    AliasInline,
    DeadCode,
    InteropUnwrap,
    JsxRestore,
    JsxAutomatic,
    MbaSimplify,
    LoopCommaBody,
    ForToWhile,
    BlockStatement,
    VarToBlock,
    NumericLiteral,
    UndefinedInit,
    Exponent,
    TypeConstructor,
    ThenCatch,
    DefaultParam,
    ArgRest,
    ForOf,
    ObjectParam,
    ImportRename,
    ExportRename,
    LogicalAssign,
    LiteralLength,
    SpreadClone,
    RegeneratorRestore,
    RequireAlias,
    RequireDestructure,
    RequireMember,
}

struct Edit {
    start: usize,
    end: usize,
    replacement: String,
}

struct RuleOutcome {
    edits: Vec<Edit>,
}

impl RuleOutcome {
    const fn empty() -> Self {
        Self { edits: Vec::new() }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct AstUnminifyStats {
    pub classes_reconstructed: usize,
    pub babel_helper_classes: usize,
    pub prototype_classes: usize,
    pub classes_with_extends: usize,
    pub static_members_lifted: usize,
    pub accessors_lifted: usize,
    pub async_functions_restored: usize,
    pub regenerator_functions_restored: usize,
    pub infinity_folds: usize,
    pub typeof_undefined_normalized: usize,
    pub yoda_flips: usize,
    pub json_parse_folds: usize,
    pub object_assignment_merges: usize,
    pub boolean_shorthands_normalized: usize,
    pub void_undefineds_normalized: usize,
    pub double_not_coercions_normalized: usize,
    pub string_concats_folded: usize,
    pub numeric_constants_folded: usize,
    pub array_spreads_rebuilt: usize,
    pub object_spreads_rebuilt: usize,
    pub array_destructures_rebuilt: usize,
    pub iifes_unwrapped: usize,
    pub iife_statements_hoisted: usize,
    pub var_declarations_split: usize,
    pub var_declarators_emitted: usize,
    pub aliases_inlined: usize,
    pub alias_references_rewritten: usize,
    pub sequence_statement_splits: usize,
    pub sequence_return_splits: usize,
    pub sequence_if_test_hoists: usize,
    pub chained_assignments_split: usize,
    pub chained_assignments_emitted: usize,
    pub ternary_statements_expanded: usize,
    pub and_short_circuits_expanded: usize,
    pub or_short_circuits_expanded: usize,
    pub else_if_merges: usize,
    pub if_else_inversions: usize,
    pub de_morgan_and_negations: usize,
    pub de_morgan_or_negations: usize,
    pub object_value_shorthands: usize,
    pub object_method_shorthands: usize,
    pub constant_if_folds: usize,
    pub unreachable_statement_drops: usize,
    pub import_merges: usize,
    pub wildcard_imports_unwrapped: usize,
    pub esmodule_markers_stripped: usize,
    pub jsx_elements_restored: usize,
    pub jsx_fragments_restored: usize,
    pub jsx_automatic_elements_restored: usize,
    pub jsx_automatic_fragments_restored: usize,
    pub mba_expressions_collapsed: usize,
    pub mba_opaque_branches_folded: usize,
    pub loop_comma_bodies_split: usize,
    pub branch_comma_bodies_split: usize,
    pub indirect_calls_simplified: usize,
    pub apply_calls_spread: usize,
    pub bracket_accesses_dotted: usize,
    pub template_literals_rebuilt: usize,
    pub optional_chains_rebuilt: usize,
    pub nullish_coalesces_rebuilt: usize,
    pub for_loops_to_while: usize,
    pub statement_bodies_blocked: usize,
    pub vars_promoted_to_const: usize,
    pub vars_promoted_to_let: usize,
    pub numeric_literals_normalized: usize,
    pub undefined_inits_dropped: usize,
    pub math_pow_to_exponent: usize,
    pub number_coercions_named: usize,
    pub string_coercions_named: usize,
    pub array_holes_named: usize,
    pub then_to_catch: usize,
    pub default_params_recovered: usize,
    pub object_params_restructured: usize,
    pub arguments_copy_loops_to_rest: usize,
    pub index_loops_to_for_of: usize,
    pub helper_loops_to_for_of: usize,
    pub aliased_imports_renamed: usize,
    pub aliased_exports_renamed: usize,
    pub and_assignments_recovered: usize,
    pub or_assignments_recovered: usize,
    pub nullish_assignments_recovered: usize,
    pub literal_lengths_folded: usize,
    pub spread_clones_merged: usize,
    pub require_aliases_renamed: usize,
    pub require_members_unaliased: usize,
    pub require_member_aliases_renamed: usize,
}

enum RuleStats {
    IifeUnwrap(IifeUnwrapStats),
    IndirectCall(IndirectCallStats),
    ArgumentSpread(ArgumentSpreadStats),
    Async(AsyncRestoreStats),
    Class(ClassRecoveryStats),
    SpreadRebuild(SpreadRebuildStats),
    SplitVar(SplitVarStats),
    SequenceSplit(SequenceSplitStats),
    ChainedAssign(ChainedAssignStats),
    AliasInline(AliasInlineStats),
    ConditionalStatement(ConditionalStatementStats),
    MergeElseIf(MergeElseIfStats),
    DeMorgan(DeMorganStats),
    LiteralLogic(LiteralLogicStats),
    LiteralNormalize(LiteralNormalizeStats),
    BracketToDot(BracketToDotStats),
    TemplateLiteral(TemplateLiteralStats),
    OptionalChaining(OptionalChainingStats),
    NullishCoalescing(NullishCoalescingStats),
    ObjectShorthand(ObjectShorthandStats),
    DeadCode(DeadCodeStats),
    InteropUnwrap(InteropUnwrapStats),
    JsxRestore(JsxRestoreStats),
    JsxAutomatic(JsxAutomaticStats),
    MbaSimplify(MbaSimplifyStats),
    LoopCommaBody(LoopCommaBodyStats),
    ForToWhile(ForToWhileStats),
    BlockStatement(BlockStatementStats),
    VarToBlock(VarToBlockStats),
    NumericLiteral(NumericLiteralStats),
    UndefinedInit(UndefinedInitStats),
    Exponent(ExponentStats),
    TypeConstructor(TypeConstructorStats),
    ThenCatch(ThenCatchStats),
    DefaultParam(DefaultParamStats),
    ArgRest(ArgRestStats),
    ForOf(ForOfStats),
    ObjectParam(ObjectParamStats),
    ImportRename(ImportRenameStats),
    ExportRename(ExportRenameStats),
    LogicalAssign(LogicalAssignStats),
    LiteralLength(LiteralLengthStats),
    SpreadClone(SpreadCloneStats),
    RegeneratorRestore(RegeneratorRestoreStats),
    RequireAlias(RequireAliasStats),
    RequireDestructure(RequireDestructureStats),
    RequireMember(RequireMemberStats),
}

struct Rule {
    id: AstRuleId,
    stage: RuleStage,
    requires: &'static [AstRuleId],
    enabled: bool,
}

pub struct AstPipeline {
    rules: Vec<Rule>,
}

impl core::fmt::Debug for AstPipeline {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let enabled: Vec<AstRuleId> = self
            .rules
            .iter()
            .filter(|rule| rule.enabled)
            .map(|rule| rule.id)
            .collect();
        f.debug_struct("AstPipeline")
            .field("enabled", &enabled)
            .finish()
    }
}

impl Default for AstPipeline {
    fn default() -> Self {
        Self {
            rules: vec![
                Rule {
                    id: AstRuleId::IifeUnwrap,
                    stage: RuleStage::IifeUnwrap,
                    requires: &[],
                    enabled: true,
                },
                Rule {
                    id: AstRuleId::IndirectCall,
                    stage: RuleStage::IndirectCall,
                    requires: &[],
                    enabled: true,
                },
                Rule {
                    id: AstRuleId::ArgumentSpread,
                    stage: RuleStage::ArgumentSpread,
                    requires: &[],
                    enabled: true,
                },
                Rule {
                    id: AstRuleId::AsyncRestore,
                    stage: RuleStage::AsyncRestore,
                    requires: &[],
                    enabled: true,
                },
                Rule {
                    id: AstRuleId::Es6Class,
                    stage: RuleStage::ClassReconstruction,
                    requires: &[],
                    enabled: true,
                },
                Rule {
                    id: AstRuleId::SpreadRebuild,
                    stage: RuleStage::SpreadRebuild,
                    requires: &[],
                    enabled: true,
                },
                Rule {
                    id: AstRuleId::SplitVar,
                    stage: RuleStage::SplitVar,
                    requires: &[],
                    enabled: true,
                },
                Rule {
                    id: AstRuleId::SequenceSplit,
                    stage: RuleStage::SequenceSplit,
                    requires: &[],
                    enabled: true,
                },
                Rule {
                    id: AstRuleId::ChainedAssign,
                    stage: RuleStage::ChainedAssign,
                    requires: &[],
                    enabled: true,
                },
                Rule {
                    id: AstRuleId::ConditionalStatement,
                    stage: RuleStage::ConditionalStatement,
                    requires: &[],
                    enabled: true,
                },
                Rule {
                    id: AstRuleId::MergeElseIf,
                    stage: RuleStage::MergeElseIf,
                    requires: &[],
                    enabled: true,
                },
                Rule {
                    id: AstRuleId::DeMorgan,
                    stage: RuleStage::DeMorgan,
                    requires: &[],
                    enabled: true,
                },
                Rule {
                    id: AstRuleId::LiteralLogic,
                    stage: RuleStage::LiteralLogic,
                    requires: &[],
                    enabled: true,
                },
                Rule {
                    id: AstRuleId::LiteralNormalize,
                    stage: RuleStage::LiteralNormalize,
                    requires: &[],
                    enabled: true,
                },
                Rule {
                    id: AstRuleId::BracketToDot,
                    stage: RuleStage::BracketToDot,
                    requires: &[],
                    enabled: true,
                },
                Rule {
                    id: AstRuleId::TemplateLiteral,
                    stage: RuleStage::TemplateLiteral,
                    requires: &[],
                    enabled: true,
                },
                Rule {
                    id: AstRuleId::OptionalChaining,
                    stage: RuleStage::OptionalChaining,
                    requires: &[],
                    enabled: true,
                },
                Rule {
                    id: AstRuleId::NullishCoalescing,
                    stage: RuleStage::NullishCoalescing,
                    requires: &[],
                    enabled: true,
                },
                Rule {
                    id: AstRuleId::ObjectShorthand,
                    stage: RuleStage::ObjectShorthand,
                    requires: &[],
                    enabled: true,
                },
                Rule {
                    id: AstRuleId::AliasInline,
                    stage: RuleStage::AliasInline,
                    requires: &[],
                    enabled: true,
                },
                Rule {
                    id: AstRuleId::DeadCode,
                    stage: RuleStage::DeadCode,
                    requires: &[],
                    enabled: true,
                },
                Rule {
                    id: AstRuleId::InteropUnwrap,
                    stage: RuleStage::InteropUnwrap,
                    requires: &[],
                    enabled: true,
                },
                Rule {
                    id: AstRuleId::JsxRestore,
                    stage: RuleStage::JsxRestore,
                    requires: &[],
                    enabled: true,
                },
                Rule {
                    id: AstRuleId::JsxAutomatic,
                    stage: RuleStage::JsxAutomatic,
                    requires: &[],
                    enabled: true,
                },
                Rule {
                    id: AstRuleId::MbaSimplify,
                    stage: RuleStage::MbaSimplify,
                    requires: &[],
                    enabled: true,
                },
                Rule {
                    id: AstRuleId::LoopCommaBody,
                    stage: RuleStage::LoopCommaBody,
                    requires: &[],
                    enabled: true,
                },
                Rule {
                    id: AstRuleId::ForToWhile,
                    stage: RuleStage::ForToWhile,
                    requires: &[],
                    enabled: true,
                },
                Rule {
                    id: AstRuleId::BlockStatement,
                    stage: RuleStage::BlockStatement,
                    requires: &[],
                    enabled: true,
                },
                Rule {
                    id: AstRuleId::VarToBlock,
                    stage: RuleStage::VarToBlock,
                    requires: &[AstRuleId::SplitVar, AstRuleId::DeadCode],
                    enabled: true,
                },
                Rule {
                    id: AstRuleId::NumericLiteral,
                    stage: RuleStage::NumericLiteral,
                    requires: &[],
                    enabled: true,
                },
                Rule {
                    id: AstRuleId::UndefinedInit,
                    stage: RuleStage::UndefinedInit,
                    requires: &[AstRuleId::LiteralNormalize],
                    enabled: true,
                },
                Rule {
                    id: AstRuleId::Exponent,
                    stage: RuleStage::Exponent,
                    requires: &[],
                    enabled: true,
                },
                Rule {
                    id: AstRuleId::TypeConstructor,
                    stage: RuleStage::TypeConstructor,
                    requires: &[],
                    enabled: true,
                },
                Rule {
                    id: AstRuleId::ThenCatch,
                    stage: RuleStage::ThenCatch,
                    requires: &[],
                    enabled: true,
                },
                Rule {
                    id: AstRuleId::DefaultParam,
                    stage: RuleStage::DefaultParam,
                    requires: &[],
                    enabled: true,
                },
                Rule {
                    id: AstRuleId::ArgRest,
                    stage: RuleStage::ArgRest,
                    requires: &[],
                    enabled: true,
                },
                Rule {
                    id: AstRuleId::ForOf,
                    stage: RuleStage::ForOf,
                    requires: &[],
                    enabled: true,
                },
                Rule {
                    id: AstRuleId::ObjectParam,
                    stage: RuleStage::ObjectParam,
                    requires: &[],
                    enabled: true,
                },
                Rule {
                    id: AstRuleId::ImportRename,
                    stage: RuleStage::ImportRename,
                    requires: &[],
                    enabled: true,
                },
                Rule {
                    id: AstRuleId::ExportRename,
                    stage: RuleStage::ExportRename,
                    requires: &[],
                    enabled: true,
                },
                Rule {
                    id: AstRuleId::LogicalAssign,
                    stage: RuleStage::LogicalAssign,
                    requires: &[],
                    enabled: true,
                },
                Rule {
                    id: AstRuleId::LiteralLength,
                    stage: RuleStage::LiteralLength,
                    requires: &[],
                    enabled: true,
                },
                Rule {
                    id: AstRuleId::SpreadClone,
                    stage: RuleStage::SpreadClone,
                    requires: &[],
                    enabled: true,
                },
                Rule {
                    id: AstRuleId::RegeneratorRestore,
                    stage: RuleStage::RegeneratorRestore,
                    requires: &[],
                    enabled: true,
                },
                Rule {
                    id: AstRuleId::RequireAlias,
                    stage: RuleStage::RequireAlias,
                    requires: &[],
                    enabled: true,
                },
                Rule {
                    id: AstRuleId::RequireDestructure,
                    stage: RuleStage::RequireDestructure,
                    requires: &[],
                    enabled: true,
                },
                Rule {
                    id: AstRuleId::RequireMember,
                    stage: RuleStage::RequireMember,
                    requires: &[],
                    enabled: true,
                },
            ],
        }
    }
}

impl AstPipeline {
    #[must_use]
    pub fn with_rule(mut self, id: AstRuleId, enabled: bool) -> Self {
        for rule in &mut self.rules {
            if rule.id == id {
                rule.enabled = enabled;
            }
        }
        self
    }

    fn ordered(&self) -> Vec<&Rule> {
        let mut active: Vec<&Rule> = self.rules.iter().filter(|rule| rule.enabled).collect();
        active.sort_by(|a, b| {
            a.stage
                .cmp(&b.stage)
                .then_with(|| a.requires.len().cmp(&b.requires.len()))
        });
        active
    }

    #[must_use]
    pub fn run(&self, source: &str) -> (String, AstUnminifyStats) {
        let mut current: String = source.to_owned();
        let mut stats: AstUnminifyStats = AstUnminifyStats::default();
        crate::debug::dbg_section("unminify ast pipeline");
        crate::debug::dbg_kv("input-bytes", || source.len().to_string());
        for rule in self.ordered() {
            let (outcome, rule_stats): (RuleOutcome, RuleStats) = apply_rule(rule.id, &current);
            if outcome.edits.is_empty() {
                continue;
            }
            let edit_count: usize = outcome.edits.len();
            let Some(next): Option<String> = apply_edits(&current, &outcome.edits) else {
                crate::debug::dbg_kv("rule-rejected", || {
                    format!("{:?} reason=edit-splice-failed", rule.id)
                });
                continue;
            };
            if !reparses(&next) {
                crate::debug::dbg_kv("rule-rejected", || {
                    format!("{:?} reason=reparse-failed edits={edit_count}", rule.id)
                });
                continue;
            }
            crate::debug::dbg_kv("rule-applied", || {
                format!("{:?} edits={edit_count}", rule.id)
            });
            current = next;
            merge_stats(&mut stats, &rule_stats);
        }
        (current, stats)
    }
}

fn apply_rule(id: AstRuleId, source: &str) -> (RuleOutcome, RuleStats) {
    match id {
        AstRuleId::IifeUnwrap => {
            let (outcome, iife_stats): (RuleOutcome, IifeUnwrapStats) =
                iife_unwrap::recover(source);
            (outcome, RuleStats::IifeUnwrap(iife_stats))
        }
        AstRuleId::IndirectCall => {
            let (outcome, indirect_stats): (RuleOutcome, IndirectCallStats) =
                indirect_call::recover(source);
            (outcome, RuleStats::IndirectCall(indirect_stats))
        }
        AstRuleId::ArgumentSpread => {
            let (outcome, spread_stats): (RuleOutcome, ArgumentSpreadStats) =
                argument_spread::recover(source);
            (outcome, RuleStats::ArgumentSpread(spread_stats))
        }
        AstRuleId::BracketToDot => {
            let (outcome, bracket_stats): (RuleOutcome, BracketToDotStats) =
                bracket_to_dot::recover(source);
            (outcome, RuleStats::BracketToDot(bracket_stats))
        }
        AstRuleId::TemplateLiteral => {
            let (outcome, template_stats): (RuleOutcome, TemplateLiteralStats) =
                template_literal::recover(source);
            (outcome, RuleStats::TemplateLiteral(template_stats))
        }
        AstRuleId::OptionalChaining => {
            let (outcome, optional_stats): (RuleOutcome, OptionalChainingStats) =
                optional_chaining::recover(source);
            (outcome, RuleStats::OptionalChaining(optional_stats))
        }
        AstRuleId::NullishCoalescing => {
            let (outcome, nullish_stats): (RuleOutcome, NullishCoalescingStats) =
                nullish_coalescing::recover(source);
            (outcome, RuleStats::NullishCoalescing(nullish_stats))
        }
        AstRuleId::JsxAutomatic => {
            let (outcome, jsx_stats): (RuleOutcome, JsxAutomaticStats) =
                jsx_automatic::recover(source);
            (outcome, RuleStats::JsxAutomatic(jsx_stats))
        }
        AstRuleId::ForToWhile => {
            let (outcome, for_stats): (RuleOutcome, ForToWhileStats) =
                for_to_while::recover(source);
            (outcome, RuleStats::ForToWhile(for_stats))
        }
        AstRuleId::BlockStatement => {
            let (outcome, block_stats): (RuleOutcome, BlockStatementStats) =
                block_statement::recover(source);
            (outcome, RuleStats::BlockStatement(block_stats))
        }
        AstRuleId::VarToBlock => {
            let (outcome, var_stats): (RuleOutcome, VarToBlockStats) =
                var_to_block::recover(source);
            (outcome, RuleStats::VarToBlock(var_stats))
        }
        AstRuleId::NumericLiteral => {
            let (outcome, numeric_stats): (RuleOutcome, NumericLiteralStats) =
                numeric_literal::recover(source);
            (outcome, RuleStats::NumericLiteral(numeric_stats))
        }
        AstRuleId::UndefinedInit => {
            let (outcome, undefined_stats): (RuleOutcome, UndefinedInitStats) =
                undefined_init::recover(source);
            (outcome, RuleStats::UndefinedInit(undefined_stats))
        }
        AstRuleId::Exponent => {
            let (outcome, exponent_stats): (RuleOutcome, ExponentStats) = exponent::recover(source);
            (outcome, RuleStats::Exponent(exponent_stats))
        }
        AstRuleId::TypeConstructor => {
            let (outcome, type_stats): (RuleOutcome, TypeConstructorStats) =
                type_constructor::recover(source);
            (outcome, RuleStats::TypeConstructor(type_stats))
        }
        AstRuleId::ThenCatch => {
            let (outcome, then_stats): (RuleOutcome, ThenCatchStats) = then_catch::recover(source);
            (outcome, RuleStats::ThenCatch(then_stats))
        }
        AstRuleId::DefaultParam => {
            let (outcome, default_stats): (RuleOutcome, DefaultParamStats) =
                default_param::recover(source);
            (outcome, RuleStats::DefaultParam(default_stats))
        }
        AstRuleId::ArgRest => {
            let (outcome, arg_stats): (RuleOutcome, ArgRestStats) = arg_rest::recover(source);
            (outcome, RuleStats::ArgRest(arg_stats))
        }
        AstRuleId::ForOf => {
            let (outcome, for_of_stats): (RuleOutcome, ForOfStats) = for_of::recover(source);
            (outcome, RuleStats::ForOf(for_of_stats))
        }
        AstRuleId::ObjectParam => {
            let (outcome, object_stats): (RuleOutcome, ObjectParamStats) =
                object_param::recover(source);
            (outcome, RuleStats::ObjectParam(object_stats))
        }
        AstRuleId::ImportRename => {
            let (outcome, import_stats): (RuleOutcome, ImportRenameStats) =
                import_rename::recover(source);
            (outcome, RuleStats::ImportRename(import_stats))
        }
        AstRuleId::ExportRename => {
            let (outcome, export_stats): (RuleOutcome, ExportRenameStats) =
                export_rename::recover(source);
            (outcome, RuleStats::ExportRename(export_stats))
        }
        AstRuleId::LogicalAssign => {
            let (outcome, logical_stats): (RuleOutcome, LogicalAssignStats) =
                logical_assign::recover(source);
            (outcome, RuleStats::LogicalAssign(logical_stats))
        }
        AstRuleId::LiteralLength => {
            let (outcome, length_stats): (RuleOutcome, LiteralLengthStats) =
                literal_length::recover(source);
            (outcome, RuleStats::LiteralLength(length_stats))
        }
        AstRuleId::SpreadClone => {
            let (outcome, clone_stats): (RuleOutcome, SpreadCloneStats) =
                spread_clone::recover(source);
            (outcome, RuleStats::SpreadClone(clone_stats))
        }
        AstRuleId::RegeneratorRestore => {
            let (outcome, regen_stats): (RuleOutcome, RegeneratorRestoreStats) =
                regenerator_restore::recover(source);
            (outcome, RuleStats::RegeneratorRestore(regen_stats))
        }
        AstRuleId::RequireAlias => {
            let (outcome, require_stats): (RuleOutcome, RequireAliasStats) =
                require_alias::recover(source);
            (outcome, RuleStats::RequireAlias(require_stats))
        }
        AstRuleId::RequireDestructure => {
            let (outcome, destructure_stats): (RuleOutcome, RequireDestructureStats) =
                require_destructure::recover(source);
            (outcome, RuleStats::RequireDestructure(destructure_stats))
        }
        AstRuleId::RequireMember => {
            let (outcome, member_stats): (RuleOutcome, RequireMemberStats) =
                require_member::recover(source);
            (outcome, RuleStats::RequireMember(member_stats))
        }
        AstRuleId::SplitVar => {
            let (outcome, split_stats): (RuleOutcome, SplitVarStats) = split_var::recover(source);
            (outcome, RuleStats::SplitVar(split_stats))
        }
        AstRuleId::AliasInline => {
            let (outcome, alias_stats): (RuleOutcome, AliasInlineStats) =
                alias_inline::recover(source);
            (outcome, RuleStats::AliasInline(alias_stats))
        }
        AstRuleId::AsyncRestore => {
            let (outcome, async_stats): (RuleOutcome, AsyncRestoreStats) =
                async_restore::recover(source);
            (outcome, RuleStats::Async(async_stats))
        }
        AstRuleId::Es6Class => {
            let (outcome, class_stats): (RuleOutcome, ClassRecoveryStats) =
                es6_class::recover(source);
            (outcome, RuleStats::Class(class_stats))
        }
        AstRuleId::SpreadRebuild => {
            let (outcome, spread_stats): (RuleOutcome, SpreadRebuildStats) =
                spread_rebuild::recover(source);
            (outcome, RuleStats::SpreadRebuild(spread_stats))
        }
        AstRuleId::SequenceSplit => {
            let (outcome, seq_stats): (RuleOutcome, SequenceSplitStats) =
                sequence_split::recover(source);
            (outcome, RuleStats::SequenceSplit(seq_stats))
        }
        AstRuleId::ChainedAssign => {
            let (outcome, chain_stats): (RuleOutcome, ChainedAssignStats) =
                chained_assign::recover(source);
            (outcome, RuleStats::ChainedAssign(chain_stats))
        }
        AstRuleId::ConditionalStatement => {
            let (outcome, cond_stats): (RuleOutcome, ConditionalStatementStats) =
                conditional_statement::recover(source);
            (outcome, RuleStats::ConditionalStatement(cond_stats))
        }
        AstRuleId::MergeElseIf => {
            let (outcome, merge_stats): (RuleOutcome, MergeElseIfStats) =
                merge_else_if::recover(source);
            (outcome, RuleStats::MergeElseIf(merge_stats))
        }
        AstRuleId::DeMorgan => {
            let (outcome, dm_stats): (RuleOutcome, DeMorganStats) = de_morgan::recover(source);
            (outcome, RuleStats::DeMorgan(dm_stats))
        }
        AstRuleId::LiteralLogic => {
            let (outcome, lit_stats): (RuleOutcome, LiteralLogicStats) =
                literal_logic::recover(source);
            (outcome, RuleStats::LiteralLogic(lit_stats))
        }
        AstRuleId::LiteralNormalize => {
            let (outcome, normalize_stats): (RuleOutcome, LiteralNormalizeStats) =
                literal_normalize::recover(source);
            (outcome, RuleStats::LiteralNormalize(normalize_stats))
        }
        AstRuleId::ObjectShorthand => {
            let (outcome, shorthand_stats): (RuleOutcome, ObjectShorthandStats) =
                object_shorthand::recover(source);
            (outcome, RuleStats::ObjectShorthand(shorthand_stats))
        }
        AstRuleId::DeadCode => {
            let (outcome, dead_stats): (RuleOutcome, DeadCodeStats) = dead_code::recover(source);
            (outcome, RuleStats::DeadCode(dead_stats))
        }
        AstRuleId::InteropUnwrap => {
            let (outcome, interop_stats): (RuleOutcome, InteropUnwrapStats) =
                interop_unwrap::recover(source);
            (outcome, RuleStats::InteropUnwrap(interop_stats))
        }
        AstRuleId::JsxRestore => {
            let (outcome, jsx_stats): (RuleOutcome, JsxRestoreStats) = jsx_restore::recover(source);
            (outcome, RuleStats::JsxRestore(jsx_stats))
        }
        AstRuleId::MbaSimplify => {
            let (outcome, mba_stats): (RuleOutcome, MbaSimplifyStats) =
                mba_simplify::recover(source);
            (outcome, RuleStats::MbaSimplify(mba_stats))
        }
        AstRuleId::LoopCommaBody => {
            let (outcome, loop_stats): (RuleOutcome, LoopCommaBodyStats) =
                loop_comma_body::recover(source);
            (outcome, RuleStats::LoopCommaBody(loop_stats))
        }
    }
}

const fn merge_stats(stats: &mut AstUnminifyStats, rule_stats: &RuleStats) {
    match rule_stats {
        RuleStats::IifeUnwrap(iife_stats) => {
            stats.iifes_unwrapped += iife_stats.iifes_unwrapped;
            stats.iife_statements_hoisted += iife_stats.statements_hoisted;
        }
        RuleStats::IndirectCall(indirect_stats) => {
            stats.indirect_calls_simplified += indirect_stats.calls_simplified;
        }
        RuleStats::ArgumentSpread(spread_stats) => {
            stats.apply_calls_spread += spread_stats.apply_calls_spread;
        }
        RuleStats::BracketToDot(bracket_stats) => {
            stats.bracket_accesses_dotted += bracket_stats.accesses_rewritten;
        }
        RuleStats::TemplateLiteral(template_stats) => {
            stats.template_literals_rebuilt += template_stats.chains_rebuilt;
        }
        RuleStats::OptionalChaining(optional_stats) => {
            stats.optional_chains_rebuilt += optional_stats.chains_rebuilt;
        }
        RuleStats::NullishCoalescing(nullish_stats) => {
            stats.nullish_coalesces_rebuilt += nullish_stats.coalesces_rebuilt;
        }
        RuleStats::JsxAutomatic(jsx_stats) => {
            stats.jsx_automatic_elements_restored += jsx_stats.elements_restored;
            stats.jsx_automatic_fragments_restored += jsx_stats.fragments_restored;
        }
        RuleStats::ForToWhile(for_stats) => {
            stats.for_loops_to_while += for_stats.loops_converted;
        }
        RuleStats::BlockStatement(block_stats) => {
            stats.statement_bodies_blocked += block_stats.bodies_wrapped;
        }
        RuleStats::VarToBlock(var_stats) => {
            stats.vars_promoted_to_const += var_stats.promoted_to_const;
            stats.vars_promoted_to_let += var_stats.promoted_to_let;
        }
        RuleStats::NumericLiteral(numeric_stats) => {
            stats.numeric_literals_normalized += numeric_stats.literals_normalized;
        }
        RuleStats::UndefinedInit(undefined_stats) => {
            stats.undefined_inits_dropped += undefined_stats.inits_dropped;
        }
        RuleStats::Exponent(exponent_stats) => {
            stats.math_pow_to_exponent += exponent_stats.powers_rewritten;
        }
        RuleStats::TypeConstructor(type_stats) => {
            stats.number_coercions_named += type_stats.number_coercions;
            stats.string_coercions_named += type_stats.string_coercions;
            stats.array_holes_named += type_stats.array_holes_named;
        }
        RuleStats::ThenCatch(then_stats) => {
            stats.then_to_catch += then_stats.then_to_catch;
        }
        RuleStats::DefaultParam(default_stats) => {
            stats.default_params_recovered += default_stats.defaults_recovered;
        }
        RuleStats::ArgRest(arg_stats) => {
            stats.arguments_copy_loops_to_rest += arg_stats.copy_loops_to_rest;
        }
        RuleStats::ForOf(for_of_stats) => {
            stats.index_loops_to_for_of += for_of_stats.loops_converted;
            stats.helper_loops_to_for_of += for_of_stats.helper_loops_converted;
        }
        RuleStats::ObjectParam(object_stats) => {
            stats.object_params_restructured += object_stats.params_restructured;
        }
        RuleStats::ImportRename(import_stats) => {
            stats.aliased_imports_renamed += import_stats.imports_renamed;
        }
        RuleStats::ExportRename(export_stats) => {
            stats.aliased_exports_renamed += export_stats.exports_renamed;
        }
        RuleStats::LogicalAssign(logical_stats) => {
            stats.and_assignments_recovered += logical_stats.logical_and;
            stats.or_assignments_recovered += logical_stats.logical_or;
            stats.nullish_assignments_recovered += logical_stats.coalesce;
        }
        RuleStats::LiteralLength(length_stats) => {
            stats.literal_lengths_folded += length_stats.lengths_folded;
        }
        RuleStats::SpreadClone(clone_stats) => {
            stats.spread_clones_merged += clone_stats.clones_merged;
        }
        RuleStats::RegeneratorRestore(regen_stats) => {
            stats.regenerator_functions_restored += regen_stats.generators_restored;
            stats.async_functions_restored += regen_stats.async_functions_restored;
        }
        RuleStats::RequireAlias(require_stats) => {
            stats.require_aliases_renamed += require_stats.requires_renamed;
        }
        RuleStats::RequireDestructure(destructure_stats) => {
            stats.require_members_unaliased += destructure_stats.members_unaliased;
        }
        RuleStats::RequireMember(member_stats) => {
            stats.require_member_aliases_renamed += member_stats.members_renamed;
        }
        RuleStats::SplitVar(split_stats) => {
            stats.var_declarations_split += split_stats.declarations_split;
            stats.var_declarators_emitted += split_stats.declarators_emitted;
        }
        RuleStats::AliasInline(alias_stats) => {
            stats.aliases_inlined += alias_stats.aliases_inlined;
            stats.alias_references_rewritten += alias_stats.references_rewritten;
        }
        RuleStats::Async(async_stats) => {
            stats.async_functions_restored += async_stats.async_to_generator;
            stats.regenerator_functions_restored += async_stats.regenerator;
        }
        RuleStats::Class(class_stats) => {
            stats.classes_reconstructed += class_stats.babel_helper + class_stats.prototype;
            stats.babel_helper_classes += class_stats.babel_helper;
            stats.prototype_classes += class_stats.prototype;
            stats.classes_with_extends += class_stats.with_extends;
            stats.static_members_lifted += class_stats.static_members;
            stats.accessors_lifted += class_stats.accessors;
        }
        RuleStats::SpreadRebuild(spread_stats) => {
            stats.array_spreads_rebuilt += spread_stats.array_spreads;
            stats.object_spreads_rebuilt += spread_stats.object_spreads;
            stats.array_destructures_rebuilt += spread_stats.array_destructures;
        }
        RuleStats::SequenceSplit(seq_stats) => {
            stats.sequence_statement_splits += seq_stats.statement_splits;
            stats.sequence_return_splits += seq_stats.return_splits;
            stats.sequence_if_test_hoists += seq_stats.if_test_hoists;
        }
        RuleStats::ChainedAssign(chain_stats) => {
            stats.chained_assignments_split += chain_stats.chains_split;
            stats.chained_assignments_emitted += chain_stats.assignments_emitted;
        }
        RuleStats::ConditionalStatement(cond_stats) => {
            stats.ternary_statements_expanded += cond_stats.ternary_to_if;
            stats.and_short_circuits_expanded += cond_stats.and_to_if;
            stats.or_short_circuits_expanded += cond_stats.or_to_if;
        }
        RuleStats::MergeElseIf(merge_stats) => {
            stats.else_if_merges += merge_stats.merges;
            stats.if_else_inversions += merge_stats.inversions;
        }
        RuleStats::DeMorgan(dm_stats) => {
            stats.de_morgan_and_negations += dm_stats.and_negations;
            stats.de_morgan_or_negations += dm_stats.or_negations;
        }
        RuleStats::LiteralNormalize(normalize_stats) => {
            stats.boolean_shorthands_normalized += normalize_stats.boolean_shorthands;
            stats.void_undefineds_normalized += normalize_stats.void_undefineds;
            stats.double_not_coercions_normalized += normalize_stats.double_not_coercions;
            stats.string_concats_folded += normalize_stats.string_concat_folds;
            stats.numeric_constants_folded += normalize_stats.numeric_folds;
        }
        RuleStats::ObjectShorthand(shorthand_stats) => {
            stats.object_value_shorthands += shorthand_stats.value_shorthands;
            stats.object_method_shorthands += shorthand_stats.method_shorthands;
        }
        RuleStats::DeadCode(dead_stats) => {
            stats.constant_if_folds += dead_stats.constant_if_folds;
            stats.unreachable_statement_drops += dead_stats.unreachable_drops;
            stats.import_merges += dead_stats.import_merges;
        }
        RuleStats::InteropUnwrap(interop_stats) => {
            stats.wildcard_imports_unwrapped += interop_stats.wildcard_imports;
            stats.esmodule_markers_stripped += interop_stats.esmodule_markers_stripped;
        }
        RuleStats::JsxRestore(jsx_stats) => {
            stats.jsx_elements_restored += jsx_stats.elements_restored;
            stats.jsx_fragments_restored += jsx_stats.fragments_restored;
        }
        RuleStats::LiteralLogic(lit_stats) => {
            stats.infinity_folds += lit_stats.infinity_folds;
            stats.typeof_undefined_normalized += lit_stats.typeof_undefined;
            stats.yoda_flips += lit_stats.yoda_flips;
            stats.json_parse_folds += lit_stats.json_parse_folds;
            stats.object_assignment_merges += lit_stats.object_merges;
        }
        RuleStats::MbaSimplify(mba_stats) => {
            stats.mba_expressions_collapsed += mba_stats.expressions_collapsed;
            stats.mba_opaque_branches_folded += mba_stats.opaque_branches_folded;
        }
        RuleStats::LoopCommaBody(loop_stats) => {
            stats.loop_comma_bodies_split += loop_stats.loop_bodies_split;
            stats.branch_comma_bodies_split += loop_stats.branch_bodies_split;
        }
    }
}

fn apply_edits(source: &str, edits: &[Edit]) -> Option<String> {
    splice_edits(source, edits)
}

fn splice_edits(source: &str, edits: &[Edit]) -> Option<String> {
    let mut sorted: Vec<&Edit> = edits.iter().collect();
    sorted.sort_by(|a, b| b.start.cmp(&a.start).then_with(|| b.end.cmp(&a.end)));
    let mut out: String = source.to_owned();
    let mut last_start: usize = out.len() + 1;
    for edit in sorted {
        if edit.start > edit.end || edit.end > last_start || edit.end > out.len() {
            return None;
        }
        if !out.is_char_boundary(edit.start) || !out.is_char_boundary(edit.end) {
            return None;
        }
        let padded: String = pad_replacement(&out, edit);
        out.replace_range(edit.start..edit.end, &padded);
        last_start = edit.start;
    }
    Some(out)
}

fn pad_replacement(out: &str, edit: &Edit) -> String {
    let preceding: Option<char> = out
        .get(..edit.start)
        .and_then(|s: &str| s.chars().next_back());
    let following: Option<char> = out.get(edit.end..).and_then(|s: &str| s.chars().next());
    let leading: Option<char> = edit.replacement.chars().next();
    let trailing: Option<char> = edit.replacement.chars().next_back();

    let need_lead: bool = matches!((preceding, leading), (Some(p), Some(l)) if glues(p, l));
    let need_trail: bool = matches!((trailing, following), (Some(t), Some(f)) if glues(t, f));

    match (need_lead, need_trail) {
        (false, false) => edit.replacement.clone(),
        (true, false) => format!(" {}", edit.replacement),
        (false, true) => format!("{} ", edit.replacement),
        (true, true) => format!(" {} ", edit.replacement),
    }
}

const fn glues(left: char, right: char) -> bool {
    is_word_char(left) && is_word_char(right)
}

const fn is_word_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '$'
}

fn reparses(source: &str) -> bool {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("input.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    parsed.errors.is_empty() && !parsed.panicked
}

#[must_use]
pub fn unminify_ast(source: &str) -> (String, AstUnminifyStats) {
    AstPipeline::default().run(source)
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::{AstPipeline, AstRuleId, AstUnminifyStats};

    const PROTOTYPE_INPUT: &str = r"
function Rect(w, h) { this.w = w; this.h = h; }
Rect.prototype.area = function() { return this.w * this.h; };
";

    #[test]
    fn default_pipeline_fires_class_rule() {
        let pipeline: AstPipeline = AstPipeline::default();
        let (out, stats): (String, AstUnminifyStats) = pipeline.run(PROTOTYPE_INPUT);
        assert_eq!(stats.classes_reconstructed, 1);
        assert!(out.contains("class Rect"), "got: {out}");
    }

    #[test]
    fn disabled_class_rule_is_a_no_op() {
        let pipeline: AstPipeline = AstPipeline::default().with_rule(AstRuleId::Es6Class, false);
        let (out, stats): (String, AstUnminifyStats) = pipeline.run(PROTOTYPE_INPUT);
        assert_eq!(stats.classes_reconstructed, 0);
        assert!(!out.contains("class "), "rule disabled but fired: {out}");
        assert_eq!(out, PROTOTYPE_INPUT);
    }
}
