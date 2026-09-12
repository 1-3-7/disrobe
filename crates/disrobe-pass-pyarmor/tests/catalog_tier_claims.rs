#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[cfg(feature = "chain")]
mod tier {
    use std::path::{Path, PathBuf};

    use disrobe_core::chain::{CatalogEntry, ObfuscatorCatalog, SupportQuality};
    use disrobe_pass_pyarmor::chain_detector::PyarmorDetector;
    use disrobe_pass_pyarmor::{Detection, ProtectionKind, detect_from_wrapper};

    const V8_FIXTURE_FLOOR: usize = 36;

    fn workspace_root() -> PathBuf {
        let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        p.pop();
        p.pop();
        p
    }

    fn mentions_super_mode(text: &str) -> bool {
        let lowered: String = text.to_ascii_lowercase();
        lowered.contains("super mode")
            || lowered.contains("super-mode")
            || lowered.contains("supermode")
    }

    fn overstated_full_entries(entries: &[&'static dyn CatalogEntry]) -> Vec<String> {
        entries
            .iter()
            .filter(|e: &&&'static dyn CatalogEntry| e.support_quality() == SupportQuality::Full)
            .filter(|e: &&&'static dyn CatalogEntry| {
                mentions_super_mode(e.display_name())
                    || e.aliases().iter().copied().any(mentions_super_mode)
            })
            .map(|e: &&'static dyn CatalogEntry| e.id().to_owned())
            .collect()
    }

    fn ids_at(entries: &[&'static dyn CatalogEntry], quality: SupportQuality) -> Vec<&'static str> {
        let mut ids: Vec<&'static str> = entries
            .iter()
            .filter(|e: &&&'static dyn CatalogEntry| e.support_quality() == quality)
            .map(|e: &&'static dyn CatalogEntry| e.id())
            .collect();
        ids.sort_unstable();
        ids
    }

    fn collect_v8_wrappers(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path: PathBuf = entry.path();
            if path.is_dir() {
                collect_v8_wrappers(&path, out);
                continue;
            }
            let is_wrapper: bool = path
                .file_name()
                .and_then(std::ffi::OsStr::to_str)
                .is_some_and(|n: &str| n.starts_with("chunk"))
                && path
                    .extension()
                    .and_then(std::ffi::OsStr::to_str)
                    .is_some_and(|e: &str| e.eq_ignore_ascii_case("py"));
            if is_wrapper {
                out.push(path);
            }
        }
    }

    #[test]
    fn catalog_tiers_are_the_published_membership() {
        let entries: Vec<&'static dyn CatalogEntry> = PyarmorDetector.catalog();
        assert_eq!(
            ids_at(&entries, SupportQuality::Full),
            ["pyarmor-v8", "pyarmor-v9"],
            "only the versions whose bodies decrypt statically may be rated full"
        );
        assert_eq!(
            ids_at(&entries, SupportQuality::Partial),
            ["pyarmor-v6", "pyarmor-v7"],
            "v6 and v7 carry the super-mode form the unpacker refuses without --allow-dynamic"
        );
        assert_eq!(
            ids_at(&entries, SupportQuality::DetectOnly),
            ["pyarmor-v3", "pyarmor-v4", "pyarmor-v5"],
            "the legacy RSA-wrapped-key tier derives its key at run time"
        );
    }

    #[test]
    fn no_full_tier_entry_advertises_the_refused_super_mode() {
        let entries: Vec<&'static dyn CatalogEntry> = PyarmorDetector.catalog();
        let overstated: Vec<String> = overstated_full_entries(&entries);
        assert!(
            overstated.is_empty(),
            "these entries print [full] while naming super mode, which unpack_v6v7 refuses \
             without --allow-dynamic: {overstated:?}. A reader of `disrobe pyarmor catalog` takes \
             [full] to mean the body comes back."
        );
    }

    #[derive(Debug)]
    struct MutatedEntry;

    impl CatalogEntry for MutatedEntry {
        fn id(&self) -> &'static str {
            "pyarmor-v8"
        }
        fn display_name(&self) -> &'static str {
            "PyArmor v8 (super mode)"
        }
        fn aliases(&self) -> &'static [&'static str] {
            &["pyarmor-supermode"]
        }
        fn support_quality(&self) -> SupportQuality {
            SupportQuality::Full
        }
    }

    static MUTATED: MutatedEntry = MutatedEntry;

    #[test]
    fn overstatement_check_rejects_a_corrupted_catalog() {
        let corrupted: [&'static dyn CatalogEntry; 1] = [&MUTATED];
        assert_eq!(
            overstated_full_entries(&corrupted),
            vec!["pyarmor-v8".to_owned()],
            "the check must flag a full-rated entry that names super mode, otherwise it would \
             have passed over the row this crate used to print"
        );
    }

    #[test]
    fn real_v8_corpus_wrappers_are_not_super_mode() {
        let corpus: PathBuf = workspace_root().join("corpus/python/pyarmor/v8");
        assert!(
            corpus.is_dir(),
            "the committed v8 corpus is the evidence behind the full rating, expected at {}",
            corpus.display()
        );

        let mut wrappers: Vec<PathBuf> = Vec::new();
        collect_v8_wrappers(&corpus, &mut wrappers);
        wrappers.sort_unstable();
        assert!(
            wrappers.len() >= V8_FIXTURE_FLOOR,
            "expected at least {V8_FIXTURE_FLOOR} committed v8 wrappers, found {}",
            wrappers.len()
        );

        for wrapper in &wrappers {
            let text: String = std::fs::read_to_string(wrapper).expect("v8 wrapper is readable");
            let (detection, _payload): (Detection, Vec<u8>) =
                detect_from_wrapper(&text).expect("v8 wrapper carries a payload literal");
            assert_ne!(
                detection.protection,
                ProtectionKind::SuperMode,
                "{}: real v8 builds call __pyarmor__(...) and route to the static AES path; \
                 classifying one as super mode would send it to the refusal in unpack_v6v7",
                wrapper.display()
            );
        }
    }
}
