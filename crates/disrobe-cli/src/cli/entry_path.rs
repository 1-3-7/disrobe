use std::path::{Component, Path, PathBuf};

pub(crate) fn contained_entry_path(out_dir: &Path, raw: &str) -> PathBuf {
    let mut resolved: PathBuf = out_dir.to_path_buf();
    for segment in raw.replace('\\', "/").split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            continue;
        }
        let neutral: String = segment.replace(':', "_");
        if Path::new(&neutral)
            .components()
            .all(|component: Component<'_>| matches!(component, Component::Normal(_)))
        {
            resolved.push(neutral);
        }
    }
    resolved
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn hostile_entry_names_stay_inside_the_output_directory() {
        let out: PathBuf = PathBuf::from("out").join("unpacked");
        for raw in [
            "C:/Windows/System32/evil.class",
            "C:evil.class",
            "\\\\server\\share\\evil.class",
            "../../escape.class",
            "/abs/evil.class",
            "a/b:stream/c.class",
        ] {
            let joined: PathBuf = contained_entry_path(&out, raw);
            assert!(
                joined.starts_with(&out),
                "{raw} resolved to {} outside {}",
                joined.display(),
                out.display()
            );
            assert!(
                joined
                    .strip_prefix(&out)
                    .expect("contained")
                    .components()
                    .all(|component: Component<'_>| matches!(component, Component::Normal(_))),
                "{raw} kept a non-normal component: {}",
                joined.display()
            );
        }
        assert_eq!(
            contained_entry_path(&out, "com/example/Main.class"),
            out.join("com").join("example").join("Main.class")
        );
    }
}
