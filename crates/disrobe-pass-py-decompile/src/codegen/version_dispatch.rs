use crate::bytecode::version::PyVersion;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyntaxEra {
    Py2,
    Py3Early,
    Py3Modern,
    Py3Latest,
}

#[must_use]
pub fn syntax_era_for(version: &PyVersion) -> SyntaxEra {
    let (maj, min): (u8, u8) = (version.major(), version.minor());
    match maj {
        1 | 2 => SyntaxEra::Py2,
        3 if min <= 7 => SyntaxEra::Py3Early,
        3 if min <= 11 => SyntaxEra::Py3Modern,
        _ => SyntaxEra::Py3Latest,
    }
}

#[must_use]
pub fn is_python2(version: &PyVersion) -> bool {
    let (maj, _): (u8, u8) = (version.major(), version.minor());
    maj < 3
}

#[must_use]
pub fn supports_positional_only(version: &PyVersion) -> bool {
    let (maj, min): (u8, u8) = (version.major(), version.minor());
    maj > 3 || (maj == 3 && min >= 8)
}

#[must_use]
pub fn supports_parenthesized_with(version: &PyVersion) -> bool {
    let (maj, min): (u8, u8) = (version.major(), version.minor());
    maj > 3 || (maj == 3 && min >= 10)
}

#[must_use]
pub fn supports_async(version: &PyVersion) -> bool {
    version.supports_async()
}

#[must_use]
pub fn supports_fstring(version: &PyVersion) -> bool {
    version.supports_fstring()
}

#[must_use]
pub fn supports_walrus(version: &PyVersion) -> bool {
    version.supports_walrus()
}

#[must_use]
pub fn supports_match(version: &PyVersion) -> bool {
    version.supports_match()
}

#[must_use]
pub fn supports_tstring(version: &PyVersion) -> bool {
    version.supports_tstring()
}

#[must_use]
pub fn supports_try_star(version: &PyVersion) -> bool {
    version.supports_except_groups()
}

#[must_use]
pub fn supports_pep_695(version: &PyVersion) -> bool {
    version.supports_pep_695()
}

#[must_use]
pub fn supports_type_alias_stmt(version: &PyVersion) -> bool {
    version.supports_pep_695()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrintCallShape {
    PyStatement,
    PyFunction,
}

#[must_use]
pub fn print_call_shape(version: &PyVersion) -> PrintCallShape {
    if is_python2(version) {
        PrintCallShape::PyStatement
    } else {
        PrintCallShape::PyFunction
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecCallShape {
    PyStatement,
    PyFunction,
}

#[must_use]
pub fn exec_call_shape(version: &PyVersion) -> ExecCallShape {
    if is_python2(version) {
        ExecCallShape::PyStatement
    } else {
        ExecCallShape::PyFunction
    }
}

#[must_use]
pub fn use_angle_inequality(version: &PyVersion) -> bool {
    is_python2(version)
}

#[must_use]
pub fn supports_tuple_unpacking_params(version: &PyVersion) -> bool {
    is_python2(version)
}
