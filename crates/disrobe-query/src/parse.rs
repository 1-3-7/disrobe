use crate::query::{Capability, Query};

pub const MAX_QUERY_BYTES: usize = 8 * 1024;
pub const MAX_QUERY_ARGUMENT_BYTES: usize = 4 * 1024;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ParseError {
    #[error("empty query")]
    Empty,
    #[error("query is too long; max {max} bytes")]
    TooLong { max: usize },
    #[error("query `{verb}` argument is too long; max {max} bytes")]
    ArgumentTooLong { verb: &'static str, max: usize },
    #[error(
        "unknown query verb `{0}`; expected one of: functions, calls-to, xrefs-to, string-decoders, complexity-over, capability, implementors"
    )]
    UnknownVerb(String),
    #[error("query `{verb}` requires an argument: {hint}")]
    MissingArgument {
        verb: &'static str,
        hint: &'static str,
    },
    #[error("query `{verb}` takes no argument, got `{got}`")]
    UnexpectedArgument { verb: &'static str, got: String },
    #[error("`complexity-over` argument must be a non-negative integer, got `{0}`")]
    BadThreshold(String),
    #[error("unknown capability `{0}`; expected network, crypto, filesystem, or process")]
    BadCapability(String),
}

pub fn parse_query(expr: &str) -> Result<Query, ParseError> {
    if expr.len() > MAX_QUERY_BYTES {
        return Err(ParseError::TooLong {
            max: MAX_QUERY_BYTES,
        });
    }
    let trimmed: &str = expr.trim();
    if trimmed.is_empty() {
        return Err(ParseError::Empty);
    }
    let (verb, rest): (&str, &str) = match trimmed.split_once(char::is_whitespace) {
        Some((v, r)) => (v, r.trim()),
        None => (trimmed, ""),
    };
    let normalized: String = verb.to_ascii_lowercase().replace('_', "-");
    match normalized.as_str() {
        "functions" | "funcs" => no_arg(Query::Functions, "functions", rest),
        "calls-to" | "callsto" | "calls" => {
            let target: String = require_arg("calls-to", "a symbol name to find callers of", rest)?;
            Ok(Query::CallsTo { target })
        }
        "xrefs-to" | "xrefsto" | "xrefs" | "refs" => {
            let symbol: String =
                require_arg("xrefs-to", "a symbol name to find references to", rest)?;
            Ok(Query::XrefsTo { symbol })
        }
        "string-decoders" | "string-decoder" | "decoders" => {
            no_arg(Query::StringDecoders, "string-decoders", rest)
        }
        "complexity-over" | "complexity" | "cc-over" => {
            let raw: String = require_arg("complexity-over", "an integer threshold N", rest)?;
            let threshold: u32 = raw
                .parse::<u32>()
                .map_err(|_| ParseError::BadThreshold(raw))?;
            Ok(Query::ComplexityOver { threshold })
        }
        "capability" | "cap" | "capability-sites" => {
            let raw: String = require_arg(
                "capability",
                "network | crypto | filesystem | process",
                rest,
            )?;
            let capability: Capability =
                Capability::parse(&raw).ok_or(ParseError::BadCapability(raw))?;
            Ok(Query::CapabilitySites { capability })
        }
        "implementors" | "concrete-implementors" => {
            let target: String = require_arg(
                "implementors",
                "a JVM or DEX type descriptor such as Lpkg/Type;",
                rest,
            )?;
            Ok(Query::ConcreteImplementors { target })
        }
        _ => Err(ParseError::UnknownVerb(verb.to_owned())),
    }
}

fn no_arg(query: Query, verb: &'static str, rest: &str) -> Result<Query, ParseError> {
    if rest.is_empty() {
        Ok(query)
    } else {
        Err(ParseError::UnexpectedArgument {
            verb,
            got: rest.to_owned(),
        })
    }
}

fn require_arg(verb: &'static str, hint: &'static str, rest: &str) -> Result<String, ParseError> {
    if rest.is_empty() {
        Err(ParseError::MissingArgument { verb, hint })
    } else if rest.len() > MAX_QUERY_ARGUMENT_BYTES {
        Err(ParseError::ArgumentTooLong {
            verb,
            max: MAX_QUERY_ARGUMENT_BYTES,
        })
    } else {
        Ok(rest.to_owned())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parses_each_verb() {
        assert_eq!(parse_query("functions").expect("ok"), Query::Functions);
        assert_eq!(
            parse_query("calls-to read_byte").expect("ok"),
            Query::CallsTo {
                target: "read_byte".to_owned()
            }
        );
        assert_eq!(
            parse_query("xrefs-to sekret").expect("ok"),
            Query::XrefsTo {
                symbol: "sekret".to_owned()
            }
        );
        assert_eq!(
            parse_query("string-decoders").expect("ok"),
            Query::StringDecoders
        );
        assert_eq!(
            parse_query("complexity-over 5").expect("ok"),
            Query::ComplexityOver { threshold: 5 }
        );
        assert_eq!(
            parse_query("capability network").expect("ok"),
            Query::CapabilitySites {
                capability: Capability::Network
            }
        );
        assert_eq!(
            parse_query("implementors Lexample/Root;").expect("ok"),
            Query::ConcreteImplementors {
                target: "Lexample/Root;".to_owned()
            }
        );
    }

    #[test]
    fn rejects_bad_input() {
        assert_eq!(parse_query("   "), Err(ParseError::Empty));
        let oversized_query: String = "a".repeat(MAX_QUERY_BYTES + 1);
        assert_eq!(
            parse_query(&oversized_query),
            Err(ParseError::TooLong {
                max: MAX_QUERY_BYTES
            })
        );
        let oversized_argument: String = "a".repeat(MAX_QUERY_ARGUMENT_BYTES + 1);
        assert_eq!(
            parse_query(&format!("calls-to {oversized_argument}")),
            Err(ParseError::ArgumentTooLong {
                verb: "calls-to",
                max: MAX_QUERY_ARGUMENT_BYTES
            })
        );
        assert!(matches!(
            parse_query("bogus"),
            Err(ParseError::UnknownVerb(_))
        ));
        assert!(matches!(
            parse_query("calls-to"),
            Err(ParseError::MissingArgument { .. })
        ));
        assert!(matches!(
            parse_query("functions extra"),
            Err(ParseError::UnexpectedArgument { .. })
        ));
        assert!(matches!(
            parse_query("complexity-over abc"),
            Err(ParseError::BadThreshold(_))
        ));
        assert!(matches!(
            parse_query("capability telepathy"),
            Err(ParseError::BadCapability(_))
        ));
    }

    #[test]
    fn argument_with_spaces_is_preserved() {
        assert_eq!(
            parse_query("calls-to my func").expect("ok"),
            Query::CallsTo {
                target: "my func".to_owned()
            }
        );
    }
}
