fn main() {
    let bytes = std::fs::read("corpus/beam/erlang/hello.beam").unwrap();
    let raw = disrobe_pass_beam::RawBeam::parse(&bytes).unwrap();
    for c in &raw.raw_chunks {
        let tag = String::from_utf8_lossy(&c.tag);
        println!("Chunk {} len={}", tag, c.data.len());
    }
}
