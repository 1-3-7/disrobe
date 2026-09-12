#[macro_export]
macro_rules! stress_suite {
    (check: $check:path, driven_by: $parent:path) => {
        const _: () = {
            let _ = $parent;
        };

        $crate::stress_suite!(@worker $check);
    };
    (check: $check:path, corpus: $corpus:path, config: $config:path) => {
        $crate::stress_suite!(@worker $check);

        #[test]
        fn stress_isolated() -> ::core::result::Result<(), $crate::StressError> {
            let corpus: ::std::vec::Vec<$crate::CorpusEntry> =
                $crate::CorpusSource::into_entries($corpus())?;
            let config: $crate::StressConfig = $config();
            let sealed: usize = $crate::run_isolated(&corpus, &config, &stress_worker_test())?;
            ::std::println!("disrobe-testkit: {sealed} sealed case(s)");
            ::core::result::Result::Ok(())
        }
    };
    (@worker $check:path) => {
        #[test]
        #[ignore = "stress worker: the parent test runs it through the disrobe-testkit isolation protocol"]
        fn stress_worker() -> ::std::io::Result<()> {
            $crate::worker_main(::core::module_path!(), $check)
        }

        pub(crate) fn stress_worker_test() -> $crate::WorkerTest {
            $crate::WorkerTest::from_module_path(::core::module_path!())
        }
    };
}
