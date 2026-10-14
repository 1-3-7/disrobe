const MAX_SQL_BYTES: usize = 1024 * 1024;
const CONSTRAINT_WORDS: [&str; 5] = ["CONSTRAINT", "PRIMARY", "UNIQUE", "CHECK", "FOREIGN"];

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct TableShape {
    pub(super) columns: Vec<String>,
    pub(super) rowid_alias: Option<usize>,
    pub(super) without_rowid: bool,
}

pub(super) fn table_shape(sql: &str) -> TableShape {
    if sql.len() > MAX_SQL_BYTES {
        return TableShape::default();
    }
    let Some(open) = sql.find('(') else {
        return TableShape::default();
    };
    let Some(close) = matching_paren(sql, open) else {
        return TableShape::default();
    };
    let tail: String = sql[close + 1..].to_ascii_uppercase();
    let without_rowid: bool = tail
        .split(|c: char| c == ',' || c.is_whitespace())
        .collect::<Vec<&str>>()
        .windows(2)
        .any(|pair: &[&str]| pair == ["WITHOUT", "ROWID"]);
    let mut columns: Vec<String> = Vec::new();
    let mut column_types: Vec<String> = Vec::new();
    let mut column_pk: Vec<bool> = Vec::new();
    let mut table_pk: Option<Vec<String>> = None;
    for definition in split_top_level(&sql[open + 1..close]) {
        let tokens: Vec<String> = tokens(definition);
        let Some(first) = tokens.first() else {
            continue;
        };
        let upper: String = first.to_ascii_uppercase();
        if CONSTRAINT_WORDS.contains(&upper.as_str()) && !is_quoted(definition.trim_start()) {
            if let Some(list) = primary_key_list(definition) {
                table_pk = Some(list);
            }
            continue;
        }
        let rest: Vec<String> = tokens[1..]
            .iter()
            .map(|t: &String| t.to_ascii_uppercase())
            .collect();
        let type_name: String = rest
            .iter()
            .take_while(|t: &&String| !is_column_constraint(t))
            .cloned()
            .collect::<Vec<String>>()
            .join(" ");
        let primary: bool = rest
            .windows(2)
            .any(|pair: &[String]| pair[0] == "PRIMARY" && pair[1] == "KEY")
            && !rest
                .windows(3)
                .any(|w: &[String]| w[0] == "PRIMARY" && w[1] == "KEY" && w[2] == "DESC");
        columns.push(unquote(first));
        column_types.push(type_name);
        column_pk.push(primary);
    }
    let rowid_alias: Option<usize> = if without_rowid {
        None
    } else {
        let candidate: Option<usize> = match &table_pk {
            Some(list) if list.len() == 1 => columns
                .iter()
                .position(|name: &String| name.eq_ignore_ascii_case(&list[0])),
            Some(_) => None,
            None => {
                let marked: Vec<usize> = column_pk
                    .iter()
                    .enumerate()
                    .filter(|(_, pk): &(usize, &bool)| **pk)
                    .map(|(index, _): (usize, &bool)| index)
                    .collect();
                (marked.len() == 1).then(|| marked[0])
            }
        };
        candidate.filter(|index: &usize| {
            column_types
                .get(*index)
                .is_some_and(|t: &String| t == "INTEGER")
        })
    };
    TableShape {
        columns,
        rowid_alias,
        without_rowid,
    }
}

fn is_column_constraint(token: &str) -> bool {
    matches!(
        token,
        "CONSTRAINT"
            | "PRIMARY"
            | "NOT"
            | "NULL"
            | "UNIQUE"
            | "CHECK"
            | "DEFAULT"
            | "COLLATE"
            | "REFERENCES"
            | "GENERATED"
            | "AS"
    )
}

fn primary_key_list(definition: &str) -> Option<Vec<String>> {
    let upper: String = definition.to_ascii_uppercase();
    let at: usize = upper.find("PRIMARY")?;
    let open: usize = at + definition[at..].find('(')?;
    let close: usize = matching_paren(definition, open)?;
    Some(
        split_top_level(&definition[open + 1..close])
            .into_iter()
            .filter_map(|part: &str| tokens(part).into_iter().next())
            .map(|name: String| unquote(&name))
            .collect(),
    )
}

fn matching_paren(text: &str, open: usize) -> Option<usize> {
    let mut depth: usize = 0;
    let mut quote: Option<char> = None;
    for (index, c) in text
        .char_indices()
        .skip_while(|(i, _): &(usize, char)| *i < open)
    {
        if let Some(q) = quote {
            if c == closing(q) {
                quote = None;
            }
            continue;
        }
        match c {
            '\'' | '"' | '`' | '[' => quote = Some(c),
            '(' => depth += 1,
            ')' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
    }
    None
}

const fn closing(open: char) -> char {
    if open == '[' { ']' } else { open }
}

fn split_top_level(text: &str) -> Vec<&str> {
    let mut parts: Vec<&str> = Vec::new();
    let mut depth: usize = 0;
    let mut quote: Option<char> = None;
    let mut start: usize = 0;
    for (index, c) in text.char_indices() {
        if let Some(q) = quote {
            if c == closing(q) {
                quote = None;
            }
            continue;
        }
        match c {
            '\'' | '"' | '`' | '[' => quote = Some(c),
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                parts.push(&text[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    parts.push(&text[start..]);
    parts
}

fn tokens(definition: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut chars = definition.trim().char_indices().peekable();
    let text: &str = definition.trim();
    while let Some((start, c)) = chars.next() {
        if c.is_whitespace() {
            continue;
        }
        if matches!(c, '\'' | '"' | '`' | '[') {
            let end_char: char = closing(c);
            let mut end: usize = text.len();
            for (index, next) in chars.by_ref() {
                if next == end_char {
                    end = index + next.len_utf8();
                    break;
                }
            }
            out.push(text[start..end].to_owned());
            continue;
        }
        if c == '(' {
            break;
        }
        let mut end: usize = start + c.len_utf8();
        while let Some(&(index, next)) = chars.peek() {
            if next.is_whitespace() || next == '(' {
                break;
            }
            end = index + next.len_utf8();
            chars.next();
        }
        out.push(text[start..end].to_owned());
    }
    out
}

fn is_quoted(text: &str) -> bool {
    text.starts_with(['"', '`', '[', '\''])
}

fn unquote(token: &str) -> String {
    let trimmed: &str = token.trim();
    let mut chars = trimmed.chars();
    match (chars.next(), trimmed.chars().last()) {
        (Some(open @ ('"' | '`' | '\'')), Some(close)) if close == open && trimmed.len() >= 2 => {
            trimmed[1..trimmed.len() - 1].replace(&format!("{open}{open}"), &open.to_string())
        }
        (Some('['), Some(']')) if trimmed.len() >= 2 => trimmed[1..trimmed.len() - 1].to_owned(),
        _ => trimmed.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn columns_types_and_the_rowid_alias_are_recovered() {
        let shape: TableShape = table_shape(
            "CREATE TABLE \"t x\" (id INTEGER PRIMARY KEY, \"first name\" TEXT NOT NULL, [n] REAL DEFAULT (1.5), CONSTRAINT c CHECK (n > 0))",
        );
        assert_eq!(shape.columns, vec!["id", "first name", "n"]);
        assert_eq!(shape.rowid_alias, Some(0));
        assert!(!shape.without_rowid);
    }

    #[test]
    fn table_level_keys_without_rowid_and_desc_keys_follow_sqlite_rules() {
        assert_eq!(
            table_shape("CREATE TABLE a (k INTEGER, v, PRIMARY KEY (k))").rowid_alias,
            Some(0)
        );
        assert_eq!(
            table_shape("CREATE TABLE a (k INT PRIMARY KEY, v)").rowid_alias,
            None
        );
        assert_eq!(
            table_shape("CREATE TABLE a (k INTEGER PRIMARY KEY DESC, v)").rowid_alias,
            None
        );
        let without: TableShape =
            table_shape("CREATE TABLE w (k TEXT PRIMARY KEY, v) WITHOUT ROWID");
        assert!(without.without_rowid);
        assert_eq!(without.rowid_alias, None);
        assert!(table_shape("CREATE TABLE s AS SELECT 1").columns.is_empty());
    }
}
