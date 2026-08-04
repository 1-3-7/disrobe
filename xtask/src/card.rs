use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

use eyre::{Result, WrapErr, bail};
use serde::Deserialize;

use crate::datamodel::VerificationDoc;
use crate::fileio::{read_bytes_bounded, read_text_bounded};

const MAX_DATA_JSON_BYTES: u64 = 4 * 1024 * 1024;
const MAX_SVG_BYTES: u64 = 8 * 1024 * 1024;
const MAX_PNG_BYTES: u64 = 8 * 1024 * 1024;
const PNG_SIGNATURE: [u8; 8] = [137, 80, 78, 71, 13, 10, 26, 10];
const CARD_WIDTH: u32 = 1280;
const CARD_HEIGHT: u32 = 640;

#[derive(Debug, Deserialize)]
struct RecoveryDoc {
    groups: Vec<RecoveryGroup>,
}

#[derive(Debug, Deserialize)]
struct RecoveryGroup {
    heading: String,
    bars: Vec<RecoveryBar>,
}

#[derive(Debug, Deserialize)]
struct RecoveryBar {
    label: String,
    #[serde(default)]
    value: Option<f64>,
    #[serde(default)]
    detected: Option<u64>,
}

#[derive(Debug)]
struct CardStats {
    py_pct: f64,
    fmt_count: u64,
    dex_clean: u64,
    rust_loc: usize,
    crate_count: usize,
}

#[derive(Debug)]
struct CardArtifact {
    path: PathBuf,
    expected: Vec<u8>,
    max_bytes: u64,
}

const TEMPLATE: &str = r##"<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="1280" height="640" viewBox="0 0 1280 640" font-family="'JetBrains Mono', ui-monospace, monospace">
  <title>disrobe</title>
  <desc>disrobe: decompile, deobfuscate, and unpack compiled software, deterministically, in a single Rust binary.</desc>
  <defs>
    <linearGradient id="reveal" gradientUnits="userSpaceOnUse" x1="540" y1="0" x2="1208" y2="0">
      <stop offset="0" stop-color="#000000"/>
      <stop offset="0.44" stop-color="#000000"/>
      <stop offset="0.58" stop-color="#808080"/>
      <stop offset="0.72" stop-color="#ffffff"/>
      <stop offset="1" stop-color="#ffffff"/>
    </linearGradient>
    <linearGradient id="reveal-inv" gradientUnits="userSpaceOnUse" x1="540" y1="0" x2="1208" y2="0">
      <stop offset="0" stop-color="#ffffff"/>
      <stop offset="0.44" stop-color="#ffffff"/>
      <stop offset="0.58" stop-color="#808080"/>
      <stop offset="0.72" stop-color="#000000"/>
      <stop offset="1" stop-color="#000000"/>
    </linearGradient>
    <mask id="obfmask" maskUnits="userSpaceOnUse" x="540" y="132" width="668" height="300">
      <rect x="540" y="132" width="668" height="300" fill="url(#reveal)"/>
    </mask>
    <mask id="codemask" maskUnits="userSpaceOnUse" x="540" y="132" width="668" height="300">
      <rect x="540" y="132" width="668" height="300" fill="url(#reveal-inv)"/>
    </mask>
  </defs>

  <rect x="0" y="0" width="1280" height="640" fill="#0a0a0a"/>
  <rect x="0.5" y="0.5" width="1279" height="639" fill="none" stroke="#262626"/>

  <g>
    <circle cx="72" cy="40" r="5.5" fill="#d08c8c" opacity="0.85"/>
    <circle cx="90" cy="40" r="5.5" fill="#c9a98e" opacity="0.85"/>
    <circle cx="108" cy="40" r="5.5" fill="#8fb3d9" opacity="0.85"/>
  </g>
  <text x="1208" y="45" font-size="15" fill="#828282" text-anchor="end" letter-spacing="0.4">LatencyLLC ~ <tspan fill="#8fb3d9">github.com/1-3-7/disrobe</tspan></text>

  <text x="70" y="153.0" font-size="11.5" xml:space="preserve" fill="#ededed">    █████  ███                             █████</text>
  <text x="70" y="164.6" font-size="11.5" xml:space="preserve" fill="#ededed">    ▒▒███  ▒▒▒                             ▒▒███</text>
  <text x="70" y="176.2" font-size="11.5" xml:space="preserve" fill="#ededed">  ███████  ████   █████  ████████   ██████  ▒███████   ██████</text>
  <text x="70" y="187.8" font-size="11.5" xml:space="preserve" fill="#ededed"> ███▒▒███ ▒▒███  ███▒▒  ▒▒███▒▒███ ███▒▒███ ▒███▒▒███ ███▒▒███</text>
  <text x="70" y="199.4" font-size="11.5" xml:space="preserve" fill="#ededed">▒███ ▒███  ▒███ ▒▒█████  ▒███ ▒▒▒ ▒███ ▒███ ▒███ ▒███▒███████</text>
  <text x="70" y="211.0" font-size="11.5" xml:space="preserve" fill="#ededed">▒███ ▒███  ▒███  ▒▒▒▒███ ▒███     ▒███ ▒███ ▒███ ▒███▒███▒▒▒ </text>
  <text x="70" y="222.6" font-size="11.5" xml:space="preserve" fill="#ededed">▒▒████████ █████ ██████  █████    ▒▒██████  ████████ ▒▒██████ </text>
  <text x="70" y="234.2" font-size="11.5" xml:space="preserve" fill="#ededed"> ▒▒▒▒▒▒▒▒ ▒▒▒▒▒ ▒▒▒▒▒▒  ▒▒▒▒▒      ▒▒▒▒▒▒  ▒▒▒▒▒▒▒▒   ▒▒▒▒▒▒  </text>
  <rect x="70" y="262" width="417" height="3" fill="#8fb3d9"/>
  <text x="70" y="312" font-size="22" fill="#a1a1a1" letter-spacing="0.1">strip the obfuscation,</text>
  <text x="70" y="343" font-size="22" fill="#a1a1a1" letter-spacing="0.1">read the source.</text>
  <text x="70" y="388" font-size="15" fill="#828282" font-family="Inter, ui-sans-serif, sans-serif">deobfuscate, decompile, and unpack</text>
  <text x="70" y="409" font-size="15" fill="#828282" font-family="Inter, ui-sans-serif, sans-serif">compiled software, deterministically.</text>
  <g font-family="Inter, ui-sans-serif, sans-serif">
    <text x="70" y="456" font-size="13" fill="#828282" letter-spacing="0.3">RAW</text>
    <text x="113" y="456" font-size="13" fill="#828282">&#8594;</text>
    <text x="133" y="456" font-size="13" fill="#828282" letter-spacing="0.3">MIR</text>
    <text x="176" y="456" font-size="13" fill="#828282">&#8594;</text>
    <text x="196" y="456" font-size="13" fill="#828282" letter-spacing="0.3">HIR</text>
    <text x="239" y="456" font-size="13" fill="#828282">&#8594;</text>
    <text x="259" y="456" font-size="13" fill="#8fb3d9" letter-spacing="0.3">SOURCE</text>
  </g>

  <rect x="540" y="132" width="668" height="300" rx="9" fill="#161616"/>
  <g mask="url(#codemask)">
  <text x="560" y="159.0" font-size="15.5" font-weight="600" xml:space="preserve"><tspan fill="#9cc2c4">pub</tspan><tspan fill="#ededed"> </tspan><tspan fill="#9cc2c4">fn</tspan><tspan fill="#ededed"> </tspan><tspan fill="#92b4d6">disrobe</tspan><tspan fill="#ededed">&lt;</tspan><tspan fill="#cfc9a8">&#x27;a</tspan><tspan fill="#ededed">, </tspan><tspan fill="#c9a98e">B</tspan><tspan fill="#ededed">, </tspan><tspan fill="#c9a98e">P</tspan><tspan fill="#ededed">&gt;(blob: &amp;</tspan><tspan fill="#cfc9a8">&#x27;a</tspan><tspan fill="#ededed"> </tspan><tspan fill="#c9a98e">B</tspan><tspan fill="#ededed">, pass: </tspan><tspan fill="#c9a98e">P</tspan><tspan fill="#ededed">)</tspan></text>
  <text x="560" y="175.4" font-size="15.5" font-weight="600" xml:space="preserve"><tspan fill="#ededed">    -&gt; </tspan><tspan fill="#c9a98e">Result</tspan><tspan fill="#ededed">&lt;</tspan><tspan fill="#c9a98e">Source</tspan><tspan fill="#ededed">&lt;</tspan><tspan fill="#cfc9a8">&#x27;a</tspan><tspan fill="#ededed">&gt;, </tspan><tspan fill="#c9a98e">Peel</tspan><tspan fill="#ededed">&gt;</tspan></text>
  <text x="560" y="191.8" font-size="15.5" font-weight="600" xml:space="preserve"><tspan fill="#9cc2c4">where</tspan></text>
  <text x="560" y="208.2" font-size="15.5" font-weight="600" xml:space="preserve"><tspan fill="#ededed">    </tspan><tspan fill="#c9a98e">B</tspan><tspan fill="#ededed">: </tspan><tspan fill="#c9a98e">AsRef</tspan><tspan fill="#ededed">&lt;[</tspan><tspan fill="#c9a98e">u8</tspan><tspan fill="#ededed">]&gt; + ?</tspan><tspan fill="#c9a98e">Sized</tspan><tspan fill="#ededed"> + </tspan><tspan fill="#cfc9a8">&#x27;a</tspan><tspan fill="#ededed">,</tspan></text>
  <text x="560" y="224.7" font-size="15.5" font-weight="600" xml:space="preserve"><tspan fill="#ededed">    </tspan><tspan fill="#c9a98e">P</tspan><tspan fill="#ededed">: </tspan><tspan fill="#c9a98e">IntoIterator</tspan><tspan fill="#ededed">&lt;</tspan><tspan fill="#c9a98e">Item</tspan><tspan fill="#ededed"> = </tspan><tspan fill="#c9a98e">Box</tspan><tspan fill="#ededed">&lt;</tspan><tspan fill="#9cc2c4">dyn</tspan><tspan fill="#ededed"> </tspan><tspan fill="#c9a98e">Pass</tspan><tspan fill="#ededed">&lt;</tspan><tspan fill="#cfc9a8">&#x27;a</tspan><tspan fill="#ededed">, </tspan><tspan fill="#c9a98e">Ir</tspan><tspan fill="#ededed"> = </tspan><tspan fill="#c9a98e">Mir</tspan><tspan fill="#ededed">&lt;</tspan><tspan fill="#cfc9a8">&#x27;a</tspan><tspan fill="#ededed">&gt;&gt;&gt;&gt;,</tspan></text>
  <text x="560" y="241.1" font-size="14.5" xml:space="preserve"><tspan fill="#ededed">{</tspan></text>
  <text x="560" y="257.5" font-size="14.5" xml:space="preserve"><tspan fill="#ededed">    </tspan><tspan fill="#9cc2c4">let</tspan><tspan fill="#ededed"> bytes: &amp;</tspan><tspan fill="#cfc9a8">&#x27;a</tspan><tspan fill="#ededed"> [</tspan><tspan fill="#c9a98e">u8</tspan><tspan fill="#ededed">] = blob.</tspan><tspan fill="#92b4d6">as_ref</tspan><tspan fill="#ededed">();</tspan></text>
  <text x="560" y="273.9" font-size="14.5" xml:space="preserve"><tspan fill="#ededed">    </tspan><tspan fill="#9cc2c4">let</tspan><tspan fill="#ededed"> </tspan><tspan fill="#9cc2c4">mut</tspan><tspan fill="#ededed"> mir: </tspan><tspan fill="#c9a98e">Mir</tspan><tspan fill="#ededed">&lt;</tspan><tspan fill="#cfc9a8">&#x27;a</tspan><tspan fill="#ededed">&gt; = </tspan><tspan fill="#92b4d6">lift</tspan><tspan fill="#ededed">::&lt;{ </tspan><tspan fill="#c9a98e">Rung</tspan><tspan fill="#ededed">::</tspan><tspan fill="#c9a98e">Raw</tspan><tspan fill="#ededed"> </tspan><tspan fill="#9cc2c4">as</tspan><tspan fill="#ededed"> </tspan><tspan fill="#c9a98e">u8</tspan><tspan fill="#ededed"> }&gt;(bytes)?;</tspan></text>
  <text x="560" y="290.3" font-size="14.5" xml:space="preserve"><tspan fill="#ededed">    </tspan><tspan fill="#9cc2c4">for</tspan><tspan fill="#ededed"> stage </tspan><tspan fill="#9cc2c4">in</tspan><tspan fill="#ededed"> pass {</tspan></text>
  <text x="560" y="306.7" font-size="14.5" xml:space="preserve"><tspan fill="#ededed">        mir = stage.</tspan><tspan fill="#92b4d6">run</tspan><tspan fill="#ededed">(mir).</tspan><tspan fill="#92b4d6">map_err</tspan><tspan fill="#ededed">(</tspan><tspan fill="#c9a98e">Peel</tspan><tspan fill="#ededed">::</tspan><tspan fill="#c9a98e">Stage</tspan><tspan fill="#ededed">)?;</tspan></text>
  <text x="560" y="323.1" font-size="14.5" xml:space="preserve"><tspan fill="#ededed">    }</tspan></text>
  <text x="560" y="339.5" font-size="14.5" xml:space="preserve"><tspan fill="#ededed">    </tspan><tspan fill="#9cc2c4">let</tspan><tspan fill="#ededed"> hir: </tspan><tspan fill="#c9a98e">Hir</tspan><tspan fill="#ededed">&lt;</tspan><tspan fill="#cfc9a8">&#x27;a</tspan><tspan fill="#ededed">&gt; = mir.</tspan><tspan fill="#92b4d6">descend</tspan><tspan fill="#ededed">::&lt;</tspan><tspan fill="#c9a98e">Hir</tspan><tspan fill="#ededed">&lt;</tspan><tspan fill="#cfc9a8">&#x27;a</tspan><tspan fill="#ededed">&gt;&gt;();</tspan></text>
  <text x="560" y="356.0" font-size="14.5" xml:space="preserve"><tspan fill="#ededed">    </tspan><tspan fill="#9cc2c4">let</tspan><tspan fill="#ededed"> </tspan><tspan fill="#c9a98e">Some</tspan><tspan fill="#ededed">(src): </tspan><tspan fill="#c9a98e">Option</tspan><tspan fill="#ededed">&lt;</tspan><tspan fill="#c9a98e">Source</tspan><tspan fill="#ededed">&lt;</tspan><tspan fill="#cfc9a8">&#x27;a</tspan><tspan fill="#ededed">&gt;&gt; = hir.</tspan><tspan fill="#92b4d6">render</tspan><tspan fill="#ededed">::&lt;</tspan><tspan fill="#c9a98e">Surface</tspan><tspan fill="#ededed">&gt;(bytes) else {</tspan></text>
  <text x="560" y="372.4" font-size="14.5" xml:space="preserve"><tspan fill="#ededed">        </tspan><tspan fill="#9cc2c4">return</tspan><tspan fill="#ededed"> </tspan><tspan fill="#c9a98e">Err</tspan><tspan fill="#ededed">(</tspan><tspan fill="#c9a98e">Peel</tspan><tspan fill="#ededed">::</tspan><tspan fill="#c9a98e">Unverified</tspan><tspan fill="#ededed">);</tspan></text>
  <text x="560" y="388.8" font-size="14.5" xml:space="preserve"><tspan fill="#ededed">    };</tspan></text>
  <text x="560" y="405.2" font-size="14.5" xml:space="preserve"><tspan fill="#ededed">    </tspan><tspan fill="#9cc2c4">match</tspan><tspan fill="#ededed"> !src.text.</tspan><tspan fill="#92b4d6">is_empty</tspan><tspan fill="#ededed">() { </tspan><tspan fill="#9cc2c4">true</tspan><tspan fill="#ededed"> =&gt; </tspan><tspan fill="#c9a98e">Ok</tspan><tspan fill="#ededed">(src), _ =&gt; </tspan><tspan fill="#c9a98e">Err</tspan><tspan fill="#ededed">(</tspan><tspan fill="#c9a98e">Peel</tspan><tspan fill="#ededed">::</tspan><tspan fill="#c9a98e">Unverified</tspan><tspan fill="#ededed">) }</tspan></text>
  <text x="560" y="421.6" font-size="14.5" xml:space="preserve"><tspan fill="#ededed">}</tspan></text>
  </g>
  <g mask="url(#obfmask)">
    <text x="1198" y="159.0" font-size="14.5" text-anchor="end" xml:space="preserve" fill="#333333">:&amp;=~.#]?&gt;▓!?;}?▒[=~&lt;;:▓&amp;!*^*\[.$&lt;&amp;:▓#+=|?▒&amp;$@*&gt;.;]░~+:^!]^}^&gt;+?;+▒:░~░&lt;=&lt;▒▓▓▒▒</text>
    <text x="1198" y="175.4" font-size="14.5" text-anchor="end" xml:space="preserve" fill="#333333">&amp;*&lt;{;!$;&lt;%▓+\#▓:;\?|?*#░!*@}==/][.#$&gt;\!#+░░;/^?~[+░?▒$▓/▓*;#░!&gt;▓{!^&gt;&lt;▒▒=▒▓░▓▓░</text>
    <text x="1198" y="191.8" font-size="14.5" text-anchor="end" xml:space="preserve" fill="#333333">#▓^@~▒~+▓░|^$^!!&lt;[+▓{&gt;░▓%;~▓&lt;;.▒%{%=▓░\?▓|;;░&gt;]?}\~#;~*{:~^!@&amp;&lt;|[░:▒▓▓&amp;▓▒▒▒▒░░</text>
    <text x="1198" y="208.2" font-size="14.5" text-anchor="end" xml:space="preserve" fill="#333333">▓|░]&gt;:▒▓|$▓%!}^^|&amp;~&lt;/]~&lt;{=▓;!/*░|;&amp;[░;$&amp;@&gt;░|&amp;[?▓?&lt;^*@:}#@#::!▒&lt;\{/;▒~▒░░▓+▒▒░░</text>
    <text x="1198" y="224.7" font-size="14.5" text-anchor="end" xml:space="preserve" fill="#333333">$@^||▓.:[\^{}?░=░*!▒!$+;];]&lt;|=|@[▓?&amp;▒^&lt;{▓{#.▒:*&gt;:{/**!}&gt;+▒@?;?={▒*▓.▓:░░▓░▒░▒</text>
    <text x="1198" y="241.1" font-size="14.5" text-anchor="end" xml:space="preserve" fill="#333333">@./@![!}@@;▒^!\*░@;{[/#!/$░&amp;|;;%;▒#░!:!/+░:░?%~+}.?\//}/@!!]*$\:&gt;*[▒░▒▓░░!#%▒░</text>
    <text x="1198" y="257.5" font-size="14.5" text-anchor="end" xml:space="preserve" fill="#333333">]░▒▓▒=/@^;]?@▓{\#![**░+^\:;~▓.+@%░▒▓.$!▓░~;;[▓{~/░\=%;:\?{!#=?%;+~▓▓!|{▓░░&gt;░▒▒</text>
    <text x="1198" y="273.9" font-size="14.5" text-anchor="end" xml:space="preserve" fill="#333333">[░▓{!%;&amp;%?&amp;#}&lt;.;▓?&gt;@]░%*/&amp;&amp;=}{$&gt;@░▓;/#?▓░]\&lt;|{░}▓▒░[:|=;~@|▓?▒$!#\!▓!.▓░*▓░▓░░</text>
    <text x="1198" y="290.3" font-size="14.5" text-anchor="end" xml:space="preserve" fill="#333333">{▒~&amp;+░░▓@/=?;.▓▓&gt;;=]|;▒]▓@!~\▒.!▒@+\░\@]$*?.]%▒▒▒*##▓/{]$#~}▒.^▒[*]&gt;;▓▓░.▓:▓▓▒</text>
    <text x="1198" y="306.7" font-size="14.5" text-anchor="end" xml:space="preserve" fill="#333333">/▓}@*.▓;]:^%?];?/?%;^#!&amp;:=▒^;+&gt;$[~\;;~▓;.!░\}*?}^&gt;▒=*%[▓+?▒:▓!{▓;#▓▓?▒▒░[▓░░▓▒</text>
    <text x="1198" y="323.1" font-size="14.5" text-anchor="end" xml:space="preserve" fill="#333333">&gt;]]░▒░&gt;░&amp;\^&amp;%▓^!}|*@=░/%&lt;\*@:;?!}▓??▒&amp;&gt;;%░@{▒:▒^.^~▓░*+.$▓▓*!!^░/=~.▒▒░▒▒▓▒&lt;▓▒</text>
    <text x="1198" y="339.5" font-size="14.5" text-anchor="end" xml:space="preserve" fill="#333333">|░▓{$~▒&amp;!\%[}%!|&lt;;░░░?]}░&amp;;|/*=&amp;░;&amp;%~░~;%$\&amp;▒$&amp;!▓[@=%░▓!{=;▒░.%=▒{$░░:▓░/▒░▒▒▓</text>
    <text x="1198" y="356.0" font-size="14.5" text-anchor="end" xml:space="preserve" fill="#333333">*.▓@]▓&amp;;!▓*!*▒*\▓=%▓&lt;~!▒|\|}{░!&amp;[|%.░=^$▒▓%;~\;#&lt;&amp;;▒▓!~!.%▒░#▒!*@!&gt;;%&lt;▒░▓*^▓▒▓</text>
    <text x="1198" y="372.4" font-size="14.5" text-anchor="end" xml:space="preserve" fill="#333333">▒].\;░&amp;&amp;▓=*&lt;&amp;!\/=$@=▒];&gt;*▓^/:^%{@?@/&amp;!#^\░▓░?~▒▒;~.$&gt;@*].▓;]░/[?;#.▓/!▓[▓▓░░▒░</text>
    <text x="1198" y="388.8" font-size="14.5" text-anchor="end" xml:space="preserve" fill="#333333">^}]!:+░▒?&gt;~[!▒$!;*&gt;?:{▒?{^&gt;;?▓▓*&gt;&gt;~{^▓@&amp;@▓@;\!!▓▒▒[{▓▒\▓!▒.&lt;:{&lt;~:▒*#;/&lt;▓#▓▒▒+▒</text>
    <text x="1198" y="405.2" font-size="14.5" text-anchor="end" xml:space="preserve" fill="#333333">▓|&gt;@▓]▓=@*░&lt;░]+▓=░@▒!!░}░*░;]=$+▓@!░!~|.░|#:{!!+%?|][}\?*;?%{^*░#.{▓░░▓&lt;#!▓:▓▒</text>
    <text x="1198" y="421.6" font-size="14.5" text-anchor="end" xml:space="preserve" fill="#333333">$?:~}!]&lt;=;:@#/%!|:^/▓▒*!;+&lt;!░~^▒▒/\%+}?/▓▓^[{\&gt;[^*~:$}%/&amp;=[&gt;[░;?$.{▓;▒:▒░░▒░▒▓</text>
  </g>
  <rect x="540.5" y="132.5" width="667" height="299" rx="9" fill="none" stroke="#262626"/>

  <line x1="72" y1="554" x2="1208" y2="554" stroke="#262626"/>
  <text x="72" y="582" font-size="13.5" fill="#a1a1a1" xml:space="preserve" letter-spacing="0.15"><tspan fill="#8fb3d9" font-weight="700">$ </tspan>20+ ecosystems, one static binary<tspan fill="#828282"> &#183; </tspan>0 LLM, deterministic<tspan fill="#828282"> &#183; </tspan>python __PY_PCT__% recompile-verified in CI<tspan fill="#828282"> &#183; </tspan>__FMT_COUNT__ formats, no external unzipper</text>
  <text x="72" y="606" font-size="13.5" fill="#a1a1a1" xml:space="preserve" letter-spacing="0.15"><tspan fill="#8fb3d9" font-weight="700">$ </tspan>Android dex __DEX_CLEAN__ classes JVM-verified<tspan fill="#828282"> &#183; </tspan>WASM re-run under wasmtime<tspan fill="#828282"> &#183; </tspan>Lua IronBrew2 devirt proven by execution<tspan fill="#828282"> &#183; </tspan>__RUST_LOC__ lines of Rust in __CRATE_COUNT__ crates</text>
</svg>
"##;

pub(crate) fn run(root: &Path, check: bool) -> Result<()> {
    let recovery_path: PathBuf = root.join("xtask").join("data").join("recovery.json");
    let verif_path: PathBuf = root.join("xtask").join("data").join("verification.json");
    let svg_targets: [PathBuf; 2] = [
        root.join("docs").join("assets").join("social-card.svg"),
        root.join("docs")
            .join("src")
            .join("assets")
            .join("social-card.svg"),
    ];
    let png_targets: [PathBuf; 2] = [
        root.join("docs").join("assets").join("social-card.png"),
        root.join("docs")
            .join("src")
            .join("assets")
            .join("social-card.png"),
    ];

    let recovery_raw: String = read_text_bounded(&recovery_path, MAX_DATA_JSON_BYTES)
        .wrap_err_with(|| format!("reading {}", recovery_path.display()))?;
    let recovery_doc: RecoveryDoc = serde_json::from_str(&recovery_raw)
        .wrap_err_with(|| format!("parsing {}", recovery_path.display()))?;

    let verif_raw: String = read_text_bounded(&verif_path, MAX_DATA_JSON_BYTES)
        .wrap_err_with(|| format!("reading {}", verif_path.display()))?;
    let verif_doc: VerificationDoc = serde_json::from_str(&verif_raw)
        .wrap_err_with(|| format!("parsing {}", verif_path.display()))?;

    let stats: CardStats = collect_stats(root, &recovery_doc, &verif_doc)?;
    let svg: String = render(&stats);
    let png: Vec<u8> = render_png(root, svg.as_bytes())?;
    let artifacts: Vec<CardArtifact> = vec![
        CardArtifact {
            path: svg_targets[0].clone(),
            expected: svg.as_bytes().to_vec(),
            max_bytes: MAX_SVG_BYTES,
        },
        CardArtifact {
            path: svg_targets[1].clone(),
            expected: svg.into_bytes(),
            max_bytes: MAX_SVG_BYTES,
        },
        CardArtifact {
            path: png_targets[0].clone(),
            expected: png.clone(),
            max_bytes: MAX_PNG_BYTES,
        },
        CardArtifact {
            path: png_targets[1].clone(),
            expected: png,
            max_bytes: MAX_PNG_BYTES,
        },
    ];

    if check {
        let stale: Vec<PathBuf> = stale_artifact_paths(&artifacts)?;
        if !stale.is_empty() {
            let paths: String = stale
                .iter()
                .map(|path: &PathBuf| format!("  {}", path.display()))
                .collect::<Vec<String>>()
                .join("\n");
            bail!(
                "committed social card artifacts are stale; run `cargo run -p xtask -- card`:\n{paths}"
            );
        }
        for artifact in &artifacts {
            println!(
                "xtask card --check: {} matches regeneration",
                artifact.path.display()
            );
        }
    } else {
        for artifact in &artifacts {
            let Some(parent): Option<&Path> = artifact.path.parent() else {
                bail!("{} has no parent directory", artifact.path.display());
            };
            fs::create_dir_all(parent)
                .wrap_err_with(|| format!("creating parent of {}", artifact.path.display()))?;
            fs::write(&artifact.path, &artifact.expected)
                .wrap_err_with(|| format!("writing {}", artifact.path.display()))?;
            println!("xtask card: wrote {}", artifact.path.display());
        }
    }
    Ok(())
}

fn render_png(root: &Path, svg: &[u8]) -> Result<Vec<u8>> {
    let renderer: PathBuf = root
        .join("xtask")
        .join("graphgen")
        .join("render_social_card.mjs");
    if !renderer.is_file() {
        bail!("social-card renderer missing: {}", renderer.display());
    }
    let temp_dir: tempfile::TempDir =
        tempfile::tempdir().wrap_err("creating social-card render directory")?;
    let svg_path: PathBuf = temp_dir.path().join("social-card.svg");
    let png_path: PathBuf = temp_dir.path().join("social-card.png");
    fs::write(&svg_path, svg)
        .wrap_err_with(|| format!("writing temporary card SVG {}", svg_path.display()))?;
    let status: ExitStatus = Command::new("node")
        .arg(&renderer)
        .arg(&svg_path)
        .arg(&png_path)
        .current_dir(root)
        .status()
        .wrap_err(
            "spawning Node.js social-card renderer; install Node.js 24.16.0 and run `corepack enable && pnpm --dir xtask/graphgen install --frozen-lockfile`",
        )?;
    if !status.success() {
        bail!(
            "social-card renderer exited with {status}; run `corepack enable && pnpm --dir xtask/graphgen install --frozen-lockfile` and retry"
        );
    }
    let png: Vec<u8> = read_bytes_bounded(&png_path, MAX_PNG_BYTES)
        .wrap_err_with(|| format!("reading rendered card PNG {}", png_path.display()))?;
    validate_png(&png)?;
    Ok(png)
}

fn validate_png(png: &[u8]) -> Result<()> {
    let signature: &[u8] = png
        .get(..PNG_SIGNATURE.len())
        .ok_or_else(|| eyre::eyre!("social-card renderer produced a truncated PNG"))?;
    if signature != PNG_SIGNATURE {
        bail!("social-card renderer output has an invalid PNG signature");
    }
    let ihdr: &[u8] = png
        .get(8..24)
        .ok_or_else(|| eyre::eyre!("social-card renderer output has a truncated IHDR"))?;
    if ihdr.get(..4) != Some(13_u32.to_be_bytes().as_slice())
        || ihdr.get(4..8) != Some(b"IHDR".as_slice())
    {
        bail!("social-card renderer output does not begin with a canonical IHDR");
    }
    let width_bytes: [u8; 4] = ihdr
        .get(8..12)
        .ok_or_else(|| eyre::eyre!("social-card renderer output has no width"))?
        .try_into()
        .map_err(|_| eyre::eyre!("social-card renderer output has an invalid width"))?;
    let height_bytes: [u8; 4] = ihdr
        .get(12..16)
        .ok_or_else(|| eyre::eyre!("social-card renderer output has no height"))?
        .try_into()
        .map_err(|_| eyre::eyre!("social-card renderer output has an invalid height"))?;
    let width: u32 = u32::from_be_bytes(width_bytes);
    let height: u32 = u32::from_be_bytes(height_bytes);
    if width != CARD_WIDTH || height != CARD_HEIGHT {
        bail!(
            "social-card renderer produced {width}x{height}, expected {CARD_WIDTH}x{CARD_HEIGHT}"
        );
    }
    Ok(())
}

fn stale_artifact_paths(artifacts: &[CardArtifact]) -> Result<Vec<PathBuf>> {
    let mut stale: Vec<PathBuf> = Vec::new();
    for artifact in artifacts {
        let exists: bool = artifact
            .path
            .try_exists()
            .wrap_err_with(|| format!("checking {}", artifact.path.display()))?;
        if !exists {
            stale.push(artifact.path.clone());
            continue;
        }
        let on_disk: Vec<u8> = read_bytes_bounded(&artifact.path, artifact.max_bytes)
            .wrap_err_with(|| format!("reading {}", artifact.path.display()))?;
        if on_disk != artifact.expected {
            stale.push(artifact.path.clone());
        }
    }
    Ok(stale)
}

fn collect_stats(
    root: &Path,
    recovery: &RecoveryDoc,
    verif: &VerificationDoc,
) -> Result<CardStats> {
    let py_pct: f64 = find_value(recovery, "Python bytecode", "200-module pinned corpus")?;
    let fmt_count: u64 = find_detected(recovery, "Detection and extraction breadth", "Containers")?;
    let dex_clean: u64 = find_dex_clean(verif)?;
    let (rust_loc, crate_count): (usize, usize) = count_rust_lines(root)?;
    Ok(CardStats {
        py_pct,
        fmt_count,
        dex_clean,
        rust_loc,
        crate_count,
    })
}

fn find_value(doc: &RecoveryDoc, heading_sub: &str, label: &str) -> Result<f64> {
    for group in &doc.groups {
        if !group.heading.contains(heading_sub) {
            continue;
        }
        for bar in &group.bars {
            if bar.label == label {
                let Some(value): Option<f64> = bar.value else {
                    bail!("bar `{label}` under `{heading_sub}` has no value");
                };
                return Ok(value);
            }
        }
    }
    bail!("no bar `{label}` under heading containing `{heading_sub}`")
}

fn find_detected(doc: &RecoveryDoc, heading_sub: &str, label: &str) -> Result<u64> {
    for group in &doc.groups {
        if !group.heading.contains(heading_sub) {
            continue;
        }
        for bar in &group.bars {
            if bar.label == label {
                let Some(detected): Option<u64> = bar.detected else {
                    bail!("bar `{label}` under `{heading_sub}` has no detected count");
                };
                return Ok(detected);
            }
        }
    }
    bail!("no bar `{label}` under heading containing `{heading_sub}`")
}

fn find_dex_clean(doc: &VerificationDoc) -> Result<u64> {
    for row in &doc.rows {
        if row.ecosystem != "Android DEX" {
            continue;
        }
        let parts: Vec<&str> = row.result.splitn(2, '/').collect();
        let [clean_str, rest]: [&str; 2] = parts.as_slice().try_into().map_err(|_| {
            eyre::eyre!(
                "Android DEX result field has unexpected format: {:?}",
                row.result
            )
        })?;
        let clean: u64 = clean_str
            .trim()
            .parse()
            .map_err(|_| eyre::eyre!("could not parse clean count from {:?}", row.result))?;
        let total_str: &str = rest.split_whitespace().next().unwrap_or("");
        let total: u64 = total_str
            .parse()
            .map_err(|_| eyre::eyre!("could not parse total count from {:?}", row.result))?;
        if clean > total {
            bail!(
                "Android DEX row claims {clean} clean of {total} graded, which cannot be: {:?}",
                row.result
            );
        }
        return Ok(clean);
    }
    bail!("no 'Android DEX' row in verification.json")
}

fn approximate_loc(lines: usize) -> String {
    if lines >= 1_000_000 {
        let tenths: usize = lines / 100_000;
        format!("{}.{}M+", tenths / 10, tenths % 10)
    } else {
        format!("{}k+", lines / 10_000 * 10)
    }
}

fn rust_lines_under(dir: &Path) -> Result<usize> {
    if !dir.is_dir() {
        return Ok(0);
    }
    let mut total: usize = 0;
    let entries = std::fs::read_dir(dir).wrap_err_with(|| format!("reading {}", dir.display()))?;
    for entry in entries {
        let path: PathBuf = entry?.path();
        if path.is_dir() {
            total += rust_lines_under(&path)?;
            continue;
        }
        if path
            .extension()
            .is_some_and(|ext: &std::ffi::OsStr| ext.eq_ignore_ascii_case("rs"))
        {
            let text: String = read_text_bounded(&path, MAX_SVG_BYTES)?;
            total += text.lines().count();
        }
    }
    Ok(total)
}

fn count_rust_lines(root: &Path) -> Result<(usize, usize)> {
    let mut lines: usize = 0;
    let mut crates: usize = 0;
    let crates_dir: PathBuf = root.join("crates");
    let entries = std::fs::read_dir(&crates_dir)
        .wrap_err_with(|| format!("reading {}", crates_dir.display()))?;
    for entry in entries {
        let path: PathBuf = entry?.path();
        if !path.is_dir() || !path.join("Cargo.toml").is_file() {
            continue;
        }
        crates += 1;
        lines += rust_lines_under(&path.join("src"))?;
    }
    Ok((lines, crates))
}

fn render(stats: &CardStats) -> String {
    let py_str: String = format!("{:.2}", stats.py_pct);
    TEMPLATE
        .replace("__PY_PCT__", &py_str)
        .replace("__FMT_COUNT__", &stats.fmt_count.to_string())
        .replace("__DEX_CLEAN__", &stats.dex_clean.to_string())
        .replace("__RUST_LOC__", &approximate_loc(stats.rust_loc))
        .replace("__CRATE_COUNT__", &stats.crate_count.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn card_check_rejects_one_byte_png_mutation() -> Result<()> {
        let manifest_dir: &Path = Path::new(env!("CARGO_MANIFEST_DIR"));
        let Some(root): Option<&Path> = manifest_dir.parent() else {
            bail!("xtask manifest directory has no repository parent");
        };
        let fixture: PathBuf = root.join("docs").join("assets").join("social-card.png");
        let expected: Vec<u8> = read_bytes_bounded(&fixture, MAX_PNG_BYTES)?;
        validate_png(&expected)?;
        let dir: tempfile::TempDir = tempfile::tempdir()?;
        let path: PathBuf = dir.path().join("social-card.png");
        fs::write(&path, &expected)?;
        let artifact: CardArtifact = CardArtifact {
            path: path.clone(),
            expected: expected.clone(),
            max_bytes: MAX_PNG_BYTES,
        };
        assert!(stale_artifact_paths(std::slice::from_ref(&artifact))?.is_empty());

        let mut corrupted: Vec<u8> = expected;
        let Some(last_byte): Option<&mut u8> = corrupted.last_mut() else {
            bail!("tracked social-card PNG is empty");
        };
        *last_byte ^= 1;
        fs::write(&path, corrupted)?;
        assert_eq!(
            stale_artifact_paths(std::slice::from_ref(&artifact))?,
            [path]
        );
        Ok(())
    }
}
