use std::fmt::Write as _;

const MAX_LOOP_PASSES: usize = 64;

pub(super) fn resugar(body: &str) -> String {
    let mut lines: Vec<String> = body.lines().map(str::to_owned).collect();
    let mut passes: usize = 0;
    while passes < MAX_LOOP_PASSES {
        passes += 1;
        if let Some((start, found)) = (0..lines.len())
            .find_map(|i: usize| counted_loop_at(&lines, i).map(|found: CountedLoop| (i, found)))
        {
            lines = rewrite(lines, start, &found);
            continue;
        }
        if let Some((start, found)) = (0..lines.len())
            .find_map(|i: usize| iterator_loop_at(&lines, i).map(|found: IteratorLoop| (i, found)))
        {
            lines = rewrite_iterator(lines, start, &found);
            continue;
        }
        break;
    }
    let mut out: String = String::new();
    for line in &lines {
        let _ = writeln!(out, "{line}");
    }
    out
}

struct CountedLoop {
    pad: String,
    counter: String,
    bound: String,
    hoisted: Vec<String>,
    body_start: usize,
    end: usize,
}

fn indentation(line: &str) -> &str {
    let trimmed: usize = line.len() - line.trim_start().len();
    &line[..trimmed]
}

fn is_identifier(text: &str) -> bool {
    let mut chars = text.chars();
    chars
        .next()
        .is_some_and(|c: char| c.is_ascii_alphabetic() || c == '_' || c == '$')
        && chars.all(|c: char| c.is_ascii_alphanumeric() || c == '_' || c == '$')
}

fn is_constant_assignment(line: &str) -> Option<&str> {
    let (name, value): (&str, &str) = line.trim().split_once(" = ")?;
    if !is_identifier(name) {
        return None;
    }
    let value: &str = value.strip_suffix(';')?;
    let literal: &str = value
        .strip_prefix("((char) (")
        .and_then(|rest: &str| rest.strip_suffix("))"))
        .or_else(|| {
            value
                .strip_prefix("(char) (")
                .and_then(|rest: &str| rest.strip_suffix(')'))
        })
        .unwrap_or(value);
    let plain: bool = literal.parse::<i64>().is_ok()
        || literal == "null"
        || literal == "true"
        || literal == "false"
        || literal
            .strip_suffix('L')
            .is_some_and(|n: &str| n.parse::<i64>().is_ok())
        || (literal.starts_with('"') && literal.ends_with('"') && literal.len() >= 2);
    plain.then_some(name)
}

fn counted_loop_at(lines: &[String], start: usize) -> Option<CountedLoop> {
    let init: &str = lines.get(start)?;
    let pad: String = indentation(init).to_owned();
    let counter: &str = init.trim().strip_suffix(" = 0;")?;
    if !is_identifier(counter) {
        return None;
    }
    let head: &str = lines.get(start + 1)?;
    if indentation(head) != pad {
        return None;
    }
    let inner_pad: String = format!("{pad}    ");
    let end: usize = block_end(lines, start + 1, &pad)?;
    let (bound, hoisted, body_start): (String, Vec<String>, usize) = match head.trim() {
        "while (true) {" => {
            let mut cursor: usize = start + 2;
            let mut hoisted: Vec<String> = Vec::new();
            while let Some(line) = lines.get(cursor)
                && indentation(line) == inner_pad
                && let Some(name) = is_constant_assignment(line)
            {
                if name == counter
                    || lines[start + 2..end].iter().enumerate().any(
                        |(i, other): (usize, &String)| {
                            i + start + 2 != cursor && mentions_assignment(other, name)
                        },
                    )
                {
                    return None;
                }
                hoisted.push(line.clone());
                cursor += 1;
            }
            let check: &str = lines.get(cursor)?;
            if indentation(check) != inner_pad {
                return None;
            }
            let bound: &str = check
                .trim()
                .strip_prefix("if (")?
                .strip_suffix(") {")?
                .strip_prefix(counter)?
                .strip_prefix(" >= ")?;
            if lines.get(cursor + 1)?.trim() != "break;"
                || lines.get(cursor + 2)? != &format!("{inner_pad}}}")
            {
                return None;
            }
            (bound.to_owned(), hoisted, cursor + 3)
        }
        other => {
            let bound: &str = other
                .strip_prefix("while (")?
                .strip_suffix(") {")?
                .strip_prefix(counter)?
                .strip_prefix(" < ")?;
            (bound.to_owned(), Vec::new(), start + 2)
        }
    };
    if !is_identifier(&bound) && bound.parse::<i64>().is_err() {
        return None;
    }
    let step: &str = lines.get(end.checked_sub(1)?)?;
    if indentation(step) != inner_pad || step.trim() != format!("{counter} = ({counter} + 1);") {
        return None;
    }
    if body_start > end - 1 {
        return None;
    }
    let body: &[String] = &lines[body_start..end - 1];
    if body
        .iter()
        .any(|line: &String| mentions_assignment(line, counter))
        || body.iter().any(|line: &String| {
            let t: &str = line.trim();
            t == "continue;" || t.starts_with("continue ")
        })
    {
        return None;
    }
    Some(CountedLoop {
        pad,
        counter: counter.to_owned(),
        bound,
        hoisted,
        body_start,
        end,
    })
}

fn block_end(lines: &[String], open: usize, pad: &str) -> Option<usize> {
    let closing: String = format!("{pad}}}");
    (open + 1..lines.len()).find(|&i: &usize| lines[i] == closing)
}

fn mentions_assignment(line: &str, name: &str) -> bool {
    let t: &str = line.trim();
    t.starts_with(&format!("{name} = "))
        || t.starts_with(&format!("{name}++"))
        || t.starts_with(&format!("{name}--"))
}

fn mentions(line: &str, name: &str) -> bool {
    let bytes: &[u8] = line.as_bytes();
    let mut from: usize = 0;
    while let Some(at) = line[from..].find(name) {
        let begin: usize = from + at;
        let finish: usize = begin + name.len();
        let before_ok: bool = begin == 0 || !is_word_byte(bytes[begin - 1]);
        let after_ok: bool = finish >= bytes.len() || !is_word_byte(bytes[finish]);
        if before_ok && after_ok {
            return true;
        }
        from = finish;
    }
    false
}

const fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'$'
}

fn rewrite(lines: Vec<String>, start: usize, found: &CountedLoop) -> Vec<String> {
    let CountedLoop {
        pad,
        counter,
        bound,
        hoisted,
        body_start,
        end,
    } = found;
    let body: Vec<String> = lines[*body_start..end - 1].to_vec();
    let element: Option<(String, String)> = body.first().and_then(|line: &String| {
        let (element, source): (&str, &str) = line.trim().split_once(" = ")?;
        let array: &str = source.strip_suffix(&format!("[{counter}];"))?;
        (is_identifier(element) && is_identifier(array))
            .then(|| (element.to_owned(), array.to_owned()))
    });
    let length_line: Option<usize> = element.as_ref().and_then(|(_, array): &(String, String)| {
        start
            .checked_sub(1)
            .filter(|&i: &usize| lines[i].trim() == format!("{bound} = {array}.length;"))
    });
    let body_after_element: Vec<String> = element.as_ref().map_or_else(
        || body.iter().skip(1).cloned().collect(),
        |(element, array): &(String, String)| {
            let indexed: String = format!("{array}[{counter}]");
            body.iter()
                .skip(1)
                .map(|line: &String| line.replace(&indexed, element))
                .collect()
        },
    );
    let element_stable: bool =
        element
            .as_ref()
            .is_none_or(|(element, array): &(String, String)| {
                !body_after_element.iter().any(|line: &String| {
                    mentions_assignment(line, element) || mentions_assignment(line, array)
                })
            });
    let counter_used_in_body: bool = body_after_element
        .iter()
        .any(|line: &String| mentions(line, counter));
    let counter_used_after: bool = lines[end + 1..]
        .iter()
        .any(|line: &String| mentions(line, counter));
    let bound_used_elsewhere: bool = lines.iter().enumerate().any(|(i, line): (usize, &String)| {
        let in_loop_head: bool = (start + 1..*body_start).contains(&i);
        let is_length: bool = length_line == Some(i);
        let is_declaration: bool = {
            let t: &str = line.trim();
            t.ends_with(&format!(" {bound};")) && !t.contains('=')
        };
        !in_loop_head && !is_length && !is_declaration && mentions(line, bound)
    });
    let mut rebuilt: Vec<String> = Vec::with_capacity(lines.len());
    if let (Some((element, array)), Some(length_at)) = (&element, length_line)
        && element_stable
        && !counter_used_in_body
        && !counter_used_after
        && !bound_used_elsewhere
        && let Some(ty) = declared_type(&lines, element)
    {
        rebuilt.extend(lines[..length_at].iter().cloned());
        rebuilt.extend(
            hoisted
                .iter()
                .map(|line: &String| format!("{pad}{}", line.trim())),
        );
        rebuilt.push(format!("{pad}for ({ty} {element} : {array}) {{"));
        rebuilt.extend(body_after_element.iter().cloned());
        rebuilt.push(format!("{pad}}}"));
        rebuilt.extend(lines[end + 1..].iter().cloned());
        return drop_declaration(rebuilt, element);
    }
    rebuilt.extend(lines[..start].iter().cloned());
    rebuilt.extend(
        hoisted
            .iter()
            .map(|line: &String| format!("{pad}{}", line.trim())),
    );
    rebuilt.push(format!(
        "{pad}for ({counter} = 0; {counter} < {bound}; {counter}++) {{"
    ));
    rebuilt.extend(body);
    rebuilt.push(format!("{pad}}}"));
    rebuilt.extend(lines[end + 1..].iter().cloned());
    rebuilt
}

fn declared_type(lines: &[String], name: &str) -> Option<String> {
    lines.iter().find_map(|line: &String| {
        let t: &str = line.trim();
        let head: &str = t.strip_suffix(&format!(" {name};"))?;
        (!head.contains(' ') && !head.contains('=')).then(|| head.to_owned())
    })
}

fn drop_declaration(mut lines: Vec<String>, name: &str) -> Vec<String> {
    let suffix: String = format!(" {name};");
    if let Some(at) = lines.iter().position(|line: &String| {
        let t: &str = line.trim();
        t.ends_with(&suffix) && !t.contains('=') && t.split(' ').count() == 2
    }) {
        lines.remove(at);
    }
    lines
}

const MAX_ITERATOR_DISTANCE: usize = 8;

struct IteratorLoop {
    pad: String,
    iterator: String,
    collection: String,
    element: String,
    element_type: Option<String>,
    iterator_line: usize,
    end: usize,
}

fn iterator_loop_at(lines: &[String], start: usize) -> Option<IteratorLoop> {
    let head: &str = lines.get(start)?;
    let pad: String = indentation(head).to_owned();
    let iterator: &str = head
        .trim()
        .strip_prefix("while (")?
        .strip_suffix(".hasNext()) {")?;
    if !is_identifier(iterator) {
        return None;
    }
    let inner_pad: String = format!("{pad}    ");
    let end: usize = block_end(lines, start, &pad)?;
    let first: &str = lines.get(start + 1)?;
    if indentation(first) != inner_pad {
        return None;
    }
    let (element, source): (&str, &str) = first.trim().split_once(" = ")?;
    if !is_identifier(element) {
        return None;
    }
    let source: &str = source.strip_suffix(';')?;
    let call: String = format!("{iterator}.next()");
    let element_type: Option<String> = if source == call {
        None
    } else {
        let inner: &str = source
            .strip_prefix("((")?
            .strip_suffix(')')?
            .strip_suffix(&call)?
            .strip_suffix(") ")?;
        Some(inner.to_owned())
    };
    let iterator_line: usize = (start.saturating_sub(MAX_ITERATOR_DISTANCE)..start)
        .rev()
        .take_while(|&i: &usize| indentation(&lines[i]) == pad && !lines[i].trim().ends_with('{'))
        .find(|&i: &usize| {
            lines[i]
                .trim()
                .strip_prefix(&format!("{iterator} = "))
                .and_then(|rest: &str| rest.strip_suffix(".iterator();"))
                .is_some_and(is_identifier)
        })?;
    let collection: String = lines[iterator_line]
        .trim()
        .strip_prefix(&format!("{iterator} = "))?
        .strip_suffix(".iterator();")?
        .to_owned();
    let between_touches: bool = lines[iterator_line + 1..start]
        .iter()
        .any(|line: &String| mentions(line, iterator) || mentions(line, element));
    let body_touches: bool = lines[start + 2..end]
        .iter()
        .any(|line: &String| mentions(line, iterator));
    let after_touches: bool = lines[end + 1..]
        .iter()
        .any(|line: &String| mentions(line, iterator));
    let before_touches: bool = lines[..iterator_line]
        .iter()
        .any(|line: &String| !is_declaration_of(line, iterator) && mentions(line, iterator));
    if between_touches || body_touches || after_touches || before_touches {
        return None;
    }
    Some(IteratorLoop {
        pad,
        iterator: iterator.to_owned(),
        collection,
        element: element.to_owned(),
        element_type,
        iterator_line,
        end,
    })
}

fn is_declaration_of(line: &str, name: &str) -> bool {
    let t: &str = line.trim();
    t.ends_with(&format!(" {name};")) && !t.contains('=') && t.split(' ').count() == 2
}

fn rewrite_iterator(lines: Vec<String>, start: usize, found: &IteratorLoop) -> Vec<String> {
    let IteratorLoop {
        pad,
        iterator,
        collection,
        element,
        element_type,
        iterator_line,
        end,
    } = found;
    let mut rebuilt: Vec<String> = Vec::with_capacity(lines.len());
    rebuilt.extend(lines[..*iterator_line].iter().cloned());
    rebuilt.extend(lines[iterator_line + 1..start].iter().cloned());
    match element_type {
        Some(cast) => {
            rebuilt.push(format!("{pad}for (Object {iterator} : {collection}) {{"));
            rebuilt.push(format!("{pad}    {element} = (({cast}) {iterator});"));
            rebuilt.extend(lines[start + 2..*end].iter().cloned());
            rebuilt.push(format!("{pad}}}"));
            rebuilt.extend(lines[end + 1..].iter().cloned());
            drop_declaration(rebuilt, iterator)
        }
        None => {
            let Some(ty) = declared_type(&lines, element) else {
                return lines;
            };
            rebuilt.push(format!("{pad}for ({ty} {element} : {collection}) {{"));
            rebuilt.extend(lines[start + 2..*end].iter().cloned());
            rebuilt.push(format!("{pad}}}"));
            rebuilt.extend(lines[end + 1..].iter().cloned());
            let rebuilt: Vec<String> = drop_declaration(rebuilt, element);
            drop_declaration(rebuilt, iterator)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::resugar;

    fn lines(text: &[&str]) -> String {
        text.iter()
            .fold(String::new(), |mut acc: String, line: &&str| {
                acc.push_str(line);
                acc.push('\n');
                acc
            })
    }

    #[test]
    fn a_counted_while_becomes_a_for() {
        let body: String = lines(&[
            "        int i;",
            "        i = 0;",
            "        while (i < n) {",
            "            sum = (sum + i);",
            "            i = (i + 1);",
            "        }",
        ]);
        let expected: String = lines(&[
            "        int i;",
            "        for (i = 0; i < n; i++) {",
            "            sum = (sum + i);",
            "        }",
        ]);
        assert_eq!(resugar(&body), expected);
    }

    #[test]
    fn an_array_walk_becomes_an_enhanced_for_and_hoists_header_constants() {
        let body: String = lines(&[
            "        String[] arr;",
            "        int n;",
            "        int i;",
            "        char sep;",
            "        String item;",
            "        n = arr.length;",
            "        i = 0;",
            "        while (true) {",
            "            sep = (char) (59);",
            "            if (i >= n) {",
            "                break;",
            "            }",
            "            item = arr[i];",
            "            out.append(arr[i]).append(sep);",
            "            i = (i + 1);",
            "        }",
        ]);
        let expected: String = lines(&[
            "        String[] arr;",
            "        int n;",
            "        int i;",
            "        char sep;",
            "        sep = (char) (59);",
            "        for (String item : arr) {",
            "            out.append(item).append(sep);",
            "        }",
        ]);
        assert_eq!(resugar(&body), expected);
    }

    #[test]
    fn a_body_that_continues_or_reassigns_the_counter_keeps_the_while() {
        let body: String = lines(&[
            "        i = 0;",
            "        while (i < n) {",
            "            if (skip) {",
            "                continue;",
            "            }",
            "            i = (i + 1);",
            "        }",
        ]);
        assert_eq!(resugar(&body), body);
        let reassigned: String = lines(&[
            "        i = 0;",
            "        while (i < n) {",
            "            i = (i + 2);",
            "            i = (i + 1);",
            "        }",
        ]);
        assert_eq!(resugar(&reassigned), reassigned);
    }

    #[test]
    fn a_counter_read_after_the_loop_keeps_the_counted_form() {
        let body: String = lines(&[
            "        n = arr.length;",
            "        i = 0;",
            "        while (i < n) {",
            "            item = arr[i];",
            "            use(item);",
            "            i = (i + 1);",
            "        }",
            "        return i;",
        ]);
        let expected: String = lines(&[
            "        n = arr.length;",
            "        for (i = 0; i < n; i++) {",
            "            item = arr[i];",
            "            use(item);",
            "        }",
            "        return i;",
        ]);
        assert_eq!(resugar(&body), expected);
    }

    #[test]
    fn an_iterator_walk_becomes_an_enhanced_for() {
        let body: String = lines(&[
            "        java.util.Iterator var0;",
            "        Object var5;",
            "        double var1;",
            "        var0 = arg0.iterator();",
            "        var1 = 0.0;",
            "        while (var0.hasNext()) {",
            "            var5 = ((EdgeCases.Vector2D) var0.next());",
            "            var1 = (var1 + ((EdgeCases.Vector2D) var5).x);",
            "        }",
            "        return var1;",
        ]);
        let expected: String = lines(&[
            "        Object var5;",
            "        double var1;",
            "        var1 = 0.0;",
            "        for (Object var0 : arg0) {",
            "            var5 = ((EdgeCases.Vector2D) var0);",
            "            var1 = (var1 + ((EdgeCases.Vector2D) var5).x);",
            "        }",
            "        return var1;",
        ]);
        assert_eq!(resugar(&body), expected);
    }

    #[test]
    fn an_iterator_read_twice_keeps_the_while() {
        let body: String = lines(&[
            "        var2 = arg0.iterator();",
            "        while (var2.hasNext()) {",
            "            if (arg1.test(var2.next())) {",
            "                var0 = (var0 + 1);",
            "            }",
            "        }",
        ]);
        assert_eq!(resugar(&body), body);
    }
}
