use anyhow::{bail, Context, Result};
use regex::Regex;
use serde::de::value::{Error as ValueError, MapDeserializer};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Record {
    name: String,
    tag: String,
}

fn record(pairs: Vec<(String, String)>) -> Result<Record> {
    let deserializer: MapDeserializer<'_, _, ValueError> = MapDeserializer::new(pairs.into_iter());
    Record::deserialize(deserializer).context("record fields")
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let pattern: Regex = Regex::new(r"^([a-z]+)=([0-9]+)$").context("pattern")?;
    let mut pairs: Vec<(String, String)> = Vec::new();
    let mut values: Vec<u32> = Vec::new();
    for arg in &args {
        let Some(captures) = pattern.captures(arg) else {
            bail!("argument {arg:?} is not key=value");
        };
        let key: String = captures[1].to_owned();
        let value: u32 = captures[2].parse().context("value")?;
        values.push(value);
        pairs.push((key, captures[2].to_owned()));
    }
    let record: Record = record(pairs)?;
    let woven: u32 = gitdep::weave(&values, record.name.len());
    let scaled: u64 = pathdep::scale(u64::from(woven), record.tag.len());
    println!("{} {} {woven} {scaled}", record.name, record.tag);
    Ok(())
}
