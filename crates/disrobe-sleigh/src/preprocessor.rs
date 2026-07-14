use std::collections::BTreeMap;

use crate::SleighError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreprocessorLimits {
    pub conditional_depth: usize,
    pub expanded_bytes: usize,
    pub include_depth: usize,
    pub macro_expansions: usize,
    pub source_files: usize,
    pub source_bytes: usize,
}

impl Default for PreprocessorLimits {
    fn default() -> Self {
        Self {
            conditional_depth: 64,
            expanded_bytes: 4 * 1024 * 1024,
            include_depth: 64,
            macro_expansions: 256,
            source_files: 256,
            source_bytes: 4 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ConditionalFrame {
    active: bool,
    branch_taken: bool,
    parent_active: bool,
    saw_else: bool,
}

#[derive(Debug)]
struct Preprocessor<'a> {
    conditionals: Vec<ConditionalFrame>,
    include_stack: Vec<String>,
    limits: PreprocessorLimits,
    macros: BTreeMap<String, String>,
    output: String,
    source_bytes: usize,
    source_count: usize,
    sources: &'a BTreeMap<String, String>,
}

pub fn preprocess_sources(
    entry: &str,
    sources: &BTreeMap<String, String>,
    limits: PreprocessorLimits,
) -> Result<String, SleighError> {
    let entry_path: String = normalize_path(entry)?;
    let mut preprocessor: Preprocessor<'_> = Preprocessor {
        conditionals: Vec::new(),
        include_stack: Vec::new(),
        limits,
        macros: BTreeMap::new(),
        output: String::new(),
        source_bytes: 0,
        source_count: 0,
        sources,
    };
    preprocessor.expand_file(&entry_path)?;
    if !preprocessor.conditionals.is_empty() {
        return Err(SleighError::UnbalancedConditional { path: entry_path });
    }
    Ok(preprocessor.output)
}

impl Preprocessor<'_> {
    fn expand_file(&mut self, path: &str) -> Result<(), SleighError> {
        if self.include_stack.len() >= self.limits.include_depth {
            return Err(SleighError::IncludeDepth {
                limit: self.limits.include_depth,
            });
        }
        if let Some(position) = self
            .include_stack
            .iter()
            .position(|candidate: &String| candidate == path)
        {
            let mut stack: Vec<String> = self.include_stack[position..].to_vec();
            stack.push(path.to_owned());
            return Err(SleighError::IncludeCycle { stack });
        }
        self.source_count = self.source_count.saturating_add(1);
        if self.source_count > self.limits.source_files {
            return Err(SleighError::SourceCountLimit {
                limit: self.limits.source_files,
            });
        }
        let Some(source) = self.sources.get(path) else {
            return Err(SleighError::MissingSource {
                path: path.to_owned(),
            });
        };
        let Some(source_bytes) = self.source_bytes.checked_add(source.len()) else {
            return Err(SleighError::SourceBytesLimit {
                limit: self.limits.source_bytes,
            });
        };
        if source_bytes > self.limits.source_bytes {
            return Err(SleighError::SourceBytesLimit {
                limit: self.limits.source_bytes,
            });
        }
        self.source_bytes = source_bytes;
        let source_text: String = source.clone();
        let conditional_depth: usize = self.conditionals.len();
        self.include_stack.push(path.to_owned());
        for line in source_text.lines() {
            self.process_line(path, line)?;
        }
        let removed: Option<String> = self.include_stack.pop();
        if removed.is_none() || self.conditionals.len() != conditional_depth {
            return Err(SleighError::UnbalancedConditional {
                path: path.to_owned(),
            });
        }
        Ok(())
    }

    fn process_line(&mut self, path: &str, line: &str) -> Result<(), SleighError> {
        let trimmed: &str = line.trim_start();
        if trimmed.starts_with('@') {
            return self.process_directive(path, trimmed);
        }
        if self.is_active() {
            let expanded: String = if line.trim_start().starts_with('#') {
                line.to_owned()
            } else {
                self.expand_macros(line)?
            };
            self.append_line(&expanded)?;
        }
        Ok(())
    }

    fn process_directive(&mut self, path: &str, line: &str) -> Result<(), SleighError> {
        let directive: &str = line.trim();
        let boundary: usize = directive
            .find(char::is_whitespace)
            .unwrap_or(directive.len());
        let command: &str = &directive[..boundary];
        let argument: &str = strip_directive_comment(directive[boundary..].trim());
        match command {
            "@define" if self.is_active() => self.define_macro(argument),
            "@define" => parse_macro_definition(argument).map(|_: (String, String)| ()),
            "@undef" => {
                let name: &str = directive_identifier(argument).ok_or_else(|| {
                    SleighError::InvalidDirective {
                        line: line.to_owned(),
                    }
                })?;
                if self.is_active() {
                    let removed: Option<String> = self.macros.remove(name);
                    let _: Option<String> = removed;
                }
                Ok(())
            }
            "@include" => {
                let include_name: String =
                    parse_quoted(argument).ok_or_else(|| SleighError::InvalidDirective {
                        line: line.to_owned(),
                    })?;
                if !self.is_active() {
                    return Ok(());
                }
                let include_path: String = resolve_include(path, &include_name)?;
                self.expand_file(&include_path)
            }
            "@ifdef" => {
                let name: &str = directive_identifier(argument).ok_or_else(|| {
                    SleighError::InvalidDirective {
                        line: line.to_owned(),
                    }
                })?;
                let condition: bool = self.macros.contains_key(name);
                self.push_condition(condition)
            }
            "@ifndef" => {
                let name: &str = directive_identifier(argument).ok_or_else(|| {
                    SleighError::InvalidDirective {
                        line: line.to_owned(),
                    }
                })?;
                let condition: bool = !self.macros.contains_key(name);
                self.push_condition(condition)
            }
            "@if" => {
                let condition: bool = self.evaluate_condition(argument)?;
                self.push_condition(condition)
            }
            "@elif" => self.continue_condition(argument),
            "@else" if argument.is_empty() => self.else_condition(),
            "@endif" => {
                if !argument.is_empty() {
                    return Err(SleighError::InvalidDirective {
                        line: line.to_owned(),
                    });
                }
                let removed: Option<ConditionalFrame> = self.conditionals.pop();
                if removed.is_none() {
                    return Err(SleighError::InvalidDirective {
                        line: line.to_owned(),
                    });
                }
                Ok(())
            }
            _ => Err(SleighError::InvalidDirective {
                line: line.to_owned(),
            }),
        }
    }

    fn define_macro(&mut self, argument: &str) -> Result<(), SleighError> {
        let (name, value): (String, String) = parse_macro_definition(argument)?;
        let previous: Option<String> = self.macros.insert(name, value);
        let _: Option<String> = previous;
        Ok(())
    }

    fn evaluate_condition(&self, expression: &str) -> Result<bool, SleighError> {
        let cleaned: &str = strip_directive_comment(expression);
        if let Some(name) = cleaned
            .strip_prefix("defined(")
            .and_then(|rest: &str| rest.strip_suffix(')'))
        {
            let symbol: &str =
                directive_identifier(name).ok_or_else(|| SleighError::ConditionalSyntax {
                    line: expression.to_owned(),
                })?;
            return Ok(self.macros.contains_key(symbol));
        }
        for operator in ["==", "!="] {
            if let Some((name, raw_value)) = cleaned.split_once(operator) {
                let key: &str =
                    directive_identifier(name).ok_or_else(|| SleighError::ConditionalSyntax {
                        line: expression.to_owned(),
                    })?;
                let trimmed_value: &str = raw_value.trim();
                if trimmed_value.is_empty() {
                    return Err(SleighError::ConditionalSyntax {
                        line: expression.to_owned(),
                    });
                }
                let expected: String = if trimmed_value.starts_with('"') {
                    parse_quoted(trimmed_value).ok_or_else(|| SleighError::ConditionalSyntax {
                        line: expression.to_owned(),
                    })?
                } else {
                    trimmed_value.to_owned()
                };
                let actual: Option<&String> = self.macros.get(key);
                let equal: bool = actual.is_some_and(|value: &String| value == &expected);
                return Ok(if operator == "==" { equal } else { !equal });
            }
        }
        let symbol: &str =
            directive_identifier(cleaned).ok_or_else(|| SleighError::ConditionalSyntax {
                line: expression.to_owned(),
            })?;
        Ok(self.macros.contains_key(symbol))
    }

    fn push_condition(&mut self, condition: bool) -> Result<(), SleighError> {
        if self.conditionals.len() >= self.limits.conditional_depth {
            return Err(SleighError::ConditionalDepth {
                limit: self.limits.conditional_depth,
            });
        }
        let parent_active: bool = self.is_active();
        self.conditionals.push(ConditionalFrame {
            active: parent_active && condition,
            branch_taken: condition,
            parent_active,
            saw_else: false,
        });
        Ok(())
    }

    fn continue_condition(&mut self, expression: &str) -> Result<(), SleighError> {
        let condition: bool = self.evaluate_condition(expression)?;
        let Some(frame) = self.conditionals.last_mut() else {
            return Err(SleighError::InvalidDirective {
                line: expression.to_owned(),
            });
        };
        if frame.saw_else {
            return Err(SleighError::InvalidDirective {
                line: expression.to_owned(),
            });
        }
        let eligible: bool = !frame.branch_taken && condition;
        frame.active = frame.parent_active && eligible;
        frame.branch_taken |= condition;
        Ok(())
    }

    fn else_condition(&mut self) -> Result<(), SleighError> {
        let Some(frame) = self.conditionals.last_mut() else {
            return Err(SleighError::InvalidDirective {
                line: "@else".to_owned(),
            });
        };
        if frame.saw_else {
            return Err(SleighError::InvalidDirective {
                line: "@else".to_owned(),
            });
        }
        frame.active = frame.parent_active && !frame.branch_taken;
        frame.branch_taken = true;
        frame.saw_else = true;
        Ok(())
    }

    fn is_active(&self) -> bool {
        self.conditionals
            .last()
            .is_none_or(|frame: &ConditionalFrame| frame.active)
    }

    fn expand_macros(&self, line: &str) -> Result<String, SleighError> {
        if line.len() > self.limits.expanded_bytes {
            return Err(SleighError::ExpandedSourceLimit {
                limit: self.limits.expanded_bytes,
            });
        }
        let mut expanded: String = line.to_owned();
        let mut replacements: usize = 0;
        loop {
            let Some(start) = expanded.find("$(") else {
                return Ok(expanded);
            };
            let name_start: usize = start.saturating_add(2);
            let Some(relative_end) = expanded[name_start..].find(')') else {
                return Err(SleighError::InvalidDirective {
                    line: line.to_owned(),
                });
            };
            let end: usize = name_start.saturating_add(relative_end);
            let name: String = expanded[name_start..end].to_owned();
            let Some(value) = self.macros.get(&name) else {
                return Err(SleighError::MissingMacro { name });
            };
            let replace_end: usize = end.saturating_add(1);
            let replaced_len: usize = replace_end.saturating_sub(start);
            let Some(next_len) = expanded
                .len()
                .checked_sub(replaced_len)
                .and_then(|remaining: usize| remaining.checked_add(value.len()))
            else {
                return Err(SleighError::ExpandedSourceLimit {
                    limit: self.limits.expanded_bytes,
                });
            };
            if next_len > self.limits.expanded_bytes {
                return Err(SleighError::ExpandedSourceLimit {
                    limit: self.limits.expanded_bytes,
                });
            }
            expanded.replace_range(start..replace_end, value);
            replacements = replacements.saturating_add(1);
            if replacements > self.limits.macro_expansions {
                return Err(SleighError::MacroExpansionLimit {
                    limit: self.limits.macro_expansions,
                });
            }
        }
    }

    fn append_line(&mut self, line: &str) -> Result<(), SleighError> {
        let additional: usize = line.len().saturating_add(1);
        let Some(next_len) = self.output.len().checked_add(additional) else {
            return Err(SleighError::ExpandedSourceLimit {
                limit: self.limits.expanded_bytes,
            });
        };
        if next_len > self.limits.expanded_bytes {
            return Err(SleighError::ExpandedSourceLimit {
                limit: self.limits.expanded_bytes,
            });
        }
        self.output.push_str(line);
        self.output.push('\n');
        Ok(())
    }
}

fn parse_macro_definition(argument: &str) -> Result<(String, String), SleighError> {
    let boundary: usize = argument.find(char::is_whitespace).unwrap_or(argument.len());
    let name: &str = argument[..boundary].trim();
    let raw_value: &str = argument[boundary..].trim();
    if directive_identifier(name).is_none() || raw_value.is_empty() {
        return Err(SleighError::InvalidDirective {
            line: argument.to_owned(),
        });
    }
    let value: String = if raw_value.starts_with('"') {
        parse_quoted(raw_value).ok_or_else(|| SleighError::InvalidDirective {
            line: argument.to_owned(),
        })?
    } else {
        raw_value.to_owned()
    };
    Ok((name.to_owned(), value))
}

fn directive_identifier(argument: &str) -> Option<&str> {
    let name: &str = argument.trim();
    let mut characters: std::str::Chars<'_> = name.chars();
    let first: char = characters.next()?;
    if first != '_' && !first.is_ascii_alphabetic() {
        return None;
    }
    characters
        .all(|character: char| character == '_' || character.is_ascii_alphanumeric())
        .then_some(name)
}

fn strip_directive_comment(argument: &str) -> &str {
    let mut quoted: bool = false;
    let mut escaped: bool = false;
    for (index, character) in argument.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match character {
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            '#' if !quoted => return argument[..index].trim(),
            _ => {}
        }
    }
    argument.trim()
}

fn parse_quoted(value: &str) -> Option<String> {
    let trimmed: &str = value.trim();
    let content: &str = trimmed.strip_prefix('"')?.strip_suffix('"')?;
    (!content.contains('"')).then(|| content.to_owned())
}

fn resolve_include(current: &str, include: &str) -> Result<String, SleighError> {
    let base: &str = current
        .rsplit_once('/')
        .map_or("", |(parent, _): (&str, &str)| parent);
    let combined: String = if base.is_empty() {
        include.to_owned()
    } else {
        format!("{base}/{include}")
    };
    normalize_path(&combined)
}

fn normalize_path(path: &str) -> Result<String, SleighError> {
    if path.is_empty() || path.starts_with('/') || path.contains(':') {
        return Err(SleighError::InvalidPath {
            path: path.to_owned(),
        });
    }
    let normalized_separators: String = path.replace('\\', "/");
    let mut components: Vec<&str> = Vec::new();
    for component in normalized_separators.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                if components.pop().is_none() {
                    return Err(SleighError::InvalidPath {
                        path: path.to_owned(),
                    });
                }
            }
            value => components.push(value),
        }
    }
    if components.is_empty() {
        return Err(SleighError::InvalidPath {
            path: path.to_owned(),
        });
    }
    Ok(components.join("/"))
}
