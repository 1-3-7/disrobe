use std::fs;
use std::path::{Path, PathBuf};

use eyre::{Result, WrapErr, bail};
use serde::Deserialize;

use crate::fileio::{read_bytes_bounded, read_text_bounded};

const MAX_DATA_JSON_BYTES: u64 = 4 * 1024 * 1024;
const MAX_SVG_BYTES: u64 = 8 * 1024 * 1024;

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

#[derive(Debug, Deserialize)]
struct VerificationDoc {
    rows: Vec<VerificationRow>,
}

#[derive(Debug, Deserialize)]
struct VerificationRow {
    ecosystem: String,
    result: String,
}

#[derive(Debug)]
struct CardStats {
    py_pct: f64,
    fmt_count: u64,
    dex_clean: u64,
    dex_total: u64,
}

const TEMPLATE: &str = r##"<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="1280" height="640" viewBox="0 0 1280 640" font-family="ui-monospace, 'Cascadia Mono', 'JetBrains Mono', 'Fira Code', SFMono-Regular, Menlo, Consolas, monospace">
  <title>disrobe</title>
  <desc>disrobe: decompile, deobfuscate, and unpack almost anything, deterministically, in a single Rust binary.</desc>
  <defs>
    <linearGradient id="reveal" gradientUnits="userSpaceOnUse" x1="540" y1="0" x2="1208" y2="0">
      <stop offset="0" stop-color="#000000"/>
      <stop offset="0.30" stop-color="#000000"/>
      <stop offset="0.58" stop-color="#8a8a8a"/>
      <stop offset="0.75" stop-color="#ffffff"/>
      <stop offset="1" stop-color="#ffffff"/>
    </linearGradient>
    <linearGradient id="reveal-inv" gradientUnits="userSpaceOnUse" x1="540" y1="0" x2="1208" y2="0">
      <stop offset="0" stop-color="#ffffff"/>
      <stop offset="0.34" stop-color="#ffffff"/>
      <stop offset="0.58" stop-color="#9a9a9a"/>
      <stop offset="0.74" stop-color="#000000"/>
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
  <text x="70" y="388" font-size="15" fill="#828282" font-family="ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif">deobfuscate, decompile, and unpack</text>
  <text x="70" y="409" font-size="15" fill="#828282" font-family="ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif">almost anything, deterministically.</text>
  <g font-family="ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif">
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
  <text x="72" y="606" font-size="13.5" fill="#a1a1a1" xml:space="preserve" letter-spacing="0.15"><tspan fill="#8fb3d9" font-weight="700">$ </tspan>Android __DEX_CLEAN__/__DEX_TOTAL__ dex JVM-verified<tspan fill="#828282"> &#183; </tspan>WASM re-run under wasmtime<tspan fill="#828282"> &#183; </tspan>Lua IronBrew2 devirt proven by execution<tspan fill="#828282"> &#183; </tspan>~637k lines of original Rust</text>
</svg>
"##;

pub(crate) fn run(root: &Path, check: bool) -> Result<()> {
    let recovery_path: PathBuf = root.join("xtask").join("data").join("recovery.json");
    let verif_path: PathBuf = root.join("xtask").join("data").join("verification.json");
    let targets: [PathBuf; 2] = [
        root.join("docs").join("assets").join("social-card.svg"),
        root.join("docs")
            .join("src")
            .join("assets")
            .join("social-card.svg"),
    ];

    let recovery_raw: String = read_text_bounded(&recovery_path, MAX_DATA_JSON_BYTES)
        .wrap_err_with(|| format!("reading {}", recovery_path.display()))?;
    let recovery_doc: RecoveryDoc = serde_json::from_str(&recovery_raw)
        .wrap_err_with(|| format!("parsing {}", recovery_path.display()))?;

    let verif_raw: String = read_text_bounded(&verif_path, MAX_DATA_JSON_BYTES)
        .wrap_err_with(|| format!("reading {}", verif_path.display()))?;
    let verif_doc: VerificationDoc = serde_json::from_str(&verif_raw)
        .wrap_err_with(|| format!("parsing {}", verif_path.display()))?;

    let stats: CardStats = collect_stats(&recovery_doc, &verif_doc)?;
    let svg: String = render(&stats);

    if check {
        for path in &targets {
            match read_bytes_bounded(path, MAX_SVG_BYTES) {
                Ok(on_disk) if on_disk == svg.as_bytes() => {
                    println!(
                        "xtask card --check: {} matches regeneration",
                        path.display()
                    );
                }
                Ok(_) => bail!(
                    "committed social card is stale; run `cargo run -p xtask -- card`:\n  {} differs from regenerated output",
                    path.display()
                ),
                Err(err) => bail!("{} unreadable: {err}", path.display()),
            }
        }
    } else {
        for path in &targets {
            fs::create_dir_all(path.parent().unwrap_or(root))
                .wrap_err_with(|| format!("creating parent of {}", path.display()))?;
            fs::write(path, svg.as_bytes())
                .wrap_err_with(|| format!("writing {}", path.display()))?;
            println!("xtask card: wrote {}", path.display());
        }
    }
    Ok(())
}

fn collect_stats(recovery: &RecoveryDoc, verif: &VerificationDoc) -> Result<CardStats> {
    let py_pct: f64 = find_value(recovery, "Python bytecode", "200-module pinned corpus")?;
    let fmt_count: u64 = find_detected(recovery, "Detection and extraction breadth", "Containers")?;
    let (dex_clean, dex_total): (u64, u64) = find_dex_pair(verif)?;
    Ok(CardStats {
        py_pct,
        fmt_count,
        dex_clean,
        dex_total,
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

fn find_dex_pair(doc: &VerificationDoc) -> Result<(u64, u64)> {
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
        return Ok((clean, total));
    }
    bail!("no 'Android DEX' row in verification.json")
}

fn render(stats: &CardStats) -> String {
    let py_str: String = format!("{:.2}", stats.py_pct);
    TEMPLATE
        .replace("__PY_PCT__", &py_str)
        .replace("__FMT_COUNT__", &stats.fmt_count.to_string())
        .replace("__DEX_CLEAN__", &stats.dex_clean.to_string())
        .replace("__DEX_TOTAL__", &stats.dex_total.to_string())
}
