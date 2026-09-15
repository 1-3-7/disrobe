mod dispatch;
mod emit;
mod interp;
mod ir;
mod lower;
mod value;

use oxc_allocator::Allocator;
use oxc_parser::Parser;
use oxc_span::SourceType;

use self::interp::{Flow, Interp, Limits};
use self::ir::{Expr, Stmt};
use self::value::{Scope, Value};

#[derive(Debug, Clone)]
pub(super) struct CffVmResult {
    pub generators_devirtualized: usize,
    pub rewritten_source: String,
}

pub(super) fn devirtualize_cff(source: &str) -> CffVmResult {
    if !looks_like_generator_cff(source) {
        return passthrough(source);
    }
    let allocator: Allocator = Allocator::default();
    let parsed: oxc_parser::ParserReturn<'_> =
        Parser::new(&allocator, source, SourceType::cjs()).parse();
    if parsed.panicked || !parsed.errors.is_empty() {
        return passthrough(source);
    }
    let lowerer: lower::Lowerer<'_> = lower::Lowerer::new(source);
    let program: Vec<Stmt> = lowerer.lower_program(&parsed.program);
    if !program_drives_generator(&program) {
        return passthrough(source);
    }

    let mut interp: Interp = Interp::new(Limits::default());
    let scope: Scope = Scope::root();
    scope.declare("undefined", Value::Undefined);
    let (residual, flow): (Vec<Stmt>, Flow) = interp.run_program(&program, &scope);

    if interp.bailed || matches!(flow, Flow::Bail) || residual.is_empty() {
        return passthrough(source);
    }
    let rewritten: String = emit::emit_stmts(&residual);
    let reparse_alloc: Allocator = Allocator::default();
    let reparse: oxc_parser::ParserReturn<'_> =
        Parser::new(&reparse_alloc, &rewritten, SourceType::cjs()).parse();
    if reparse.panicked || !reparse.errors.is_empty() {
        return passthrough(source);
    }

    CffVmResult {
        generators_devirtualized: count_generators(source),
        rewritten_source: rewritten,
    }
}

fn passthrough(source: &str) -> CffVmResult {
    CffVmResult {
        generators_devirtualized: 0,
        rewritten_source: source.to_owned(),
    }
}

fn looks_like_generator_cff(source: &str) -> bool {
    if !source.contains("function*") {
        return false;
    }
    let has_with: bool = source.contains("with(") || source.contains("with (");
    let has_drive: bool =
        source.contains("[\"next\"]()[\"value\"]") || source.contains(".next().value");
    has_with && has_drive
}

fn count_generators(source: &str) -> usize {
    source.matches("function*").count()
}

fn program_drives_generator(program: &[Stmt]) -> bool {
    program.iter().any(|stmt: &Stmt| match stmt {
        Stmt::Expr(e) => expr_drives_generator(e),
        _ => false,
    })
}

fn expr_drives_generator(expr: &Expr) -> bool {
    match expr {
        Expr::Member {
            object, property, ..
        } => {
            if let Expr::Str(s) = property.as_ref()
                && s == "value"
            {
                return true;
            }
            expr_drives_generator(object)
        }
        Expr::Call { callee, .. } => expr_drives_generator(callee),
        _ => false,
    }
}
