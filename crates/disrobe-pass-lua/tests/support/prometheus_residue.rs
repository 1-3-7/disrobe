use disrobe_pass_lua::obfuscator::ObfuscatorDetection;
use disrobe_pass_lua::prometheus;

pub(crate) fn prometheus_layer_residue(recovered: &str) -> Option<String> {
    let residual: Option<ObfuscatorDetection> = prometheus::detect(recovered.as_bytes());
    if let Some(detection) = residual {
        return Some(format!("a Prometheus layer {detection:?}"));
    }
    recovered
        .trim_start()
        .starts_with("return(function")
        .then(|| "the WrapInFunction wrapper".to_owned())
}

pub(crate) fn assert_no_prometheus_layer(label: &str, recovered: &str) {
    if let Some(residue) = prometheus_layer_residue(recovered) {
        panic!(
            "{label}: the recovered source still carries {residue}, so running it would run \
             protector output; recovery must remove every layer before Lua executes it"
        );
    }
}
