const DECODER_SOURCES: [&str; 3] = [
    include_str!("../src/lang/perl_bytecode.rs"),
    include_str!("../src/lang/r_rds.rs"),
    include_str!("../src/lang/hashlink.rs"),
];

#[test]
fn language_decoders_import_shared_byte_reader() {
    for source in DECODER_SOURCES {
        assert!(source.contains("disrobe_bytes") && source.contains("ByteReader"));
    }
}
