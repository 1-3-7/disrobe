use std::collections::BTreeMap;
use std::sync::LazyLock;

use regex::Regex;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct ObfTechnique {
    pub id: String,
    pub category: String,
    pub title: String,
    pub example: String,
}

static TECH_HEADER: LazyLock<Regex> = LazyLock::new(|| {
    crate::regex_util::safe_regex(
        r"(?m)^##\s+(?P<id>[A-Z0-9]+(?:\.[A-Z0-9]+)*)\s+-\s+(?P<title>.+)$",
    )
});

static CATEGORY_HEADER: LazyLock<Regex> =
    LazyLock::new(|| crate::regex_util::safe_regex(r"(?m)^#\s+(?P<cat>.+)$"));

static EXAMPLE_FENCE: LazyLock<Regex> =
    LazyLock::new(|| crate::regex_util::safe_regex(r"(?s)```(?:powershell)?\s*(?P<body>.*?)```"));

#[must_use]
pub fn parse_bible(markdown: &str) -> Vec<ObfTechnique> {
    let mut techs: Vec<ObfTechnique> = Vec::new();
    let mut categories: BTreeMap<usize, String> = BTreeMap::new();
    for cap in CATEGORY_HEADER.captures_iter(markdown) {
        let Some(m): Option<regex::Match<'_>> = cap.name("cat") else {
            continue;
        };
        categories.insert(m.start(), m.as_str().trim().to_owned());
    }
    for cap in TECH_HEADER.captures_iter(markdown) {
        let Some(id): Option<regex::Match<'_>> = cap.name("id") else {
            continue;
        };
        let Some(title): Option<regex::Match<'_>> = cap.name("title") else {
            continue;
        };
        let header_end: usize = title.end();
        let next_header: usize = TECH_HEADER
            .find_at(markdown, header_end + 1)
            .map_or(markdown.len(), |m: regex::Match<'_>| m.start());
        let body: &str = &markdown[header_end..next_header];
        let example: String = EXAMPLE_FENCE
            .captures(body)
            .and_then(|c: regex::Captures<'_>| c.name("body"))
            .map_or(String::new(), |m: regex::Match<'_>| {
                m.as_str().trim().to_owned()
            });
        let category: String = categories
            .range(..id.start())
            .next_back()
            .map(|(_, v): (&usize, &String)| v.clone())
            .unwrap_or_else(|| "Uncategorised".to_owned());
        techs.push(ObfTechnique {
            id: id.as_str().to_owned(),
            category,
            title: title.as_str().trim().to_owned(),
            example,
        });
    }
    techs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_bible() {
        let md: &str = r#"
# Token-Level

## TK.1 - Concatenation

Use `+` between string literals.

```powershell
Invoke-Expression ('Get' + '-Process')
```

## TK.2 - Reordering

Reorder parameters.

```powershell
Get-Process -Name proc -ComputerName host
```

# AST-Level

## AS.1 - GetCommand indirection

Use `$ExecutionContext.InvokeCommand.GetCommand`.

```powershell
& ($ExecutionContext.InvokeCommand.GetCommand('Get-Process','Cmdlet'))
```
"#;
        let techs: Vec<ObfTechnique> = parse_bible(md);
        assert_eq!(techs.len(), 3);
        assert_eq!(techs[0].id, "TK.1");
        assert_eq!(techs[0].category, "Token-Level");
        assert!(techs[0].example.contains("Invoke-Expression"));
        assert_eq!(techs[2].category, "AST-Level");
    }
}
