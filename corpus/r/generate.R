suppressWarnings(suppressMessages(library(methods)))
suppressWarnings(suppressMessages(library(compiler)))

args <- commandArgs(trailingOnly = TRUE)
out_dir <- if (length(args) >= 1L) args[[1L]] else "objects"
dir.create(out_dir, showWarnings = FALSE, recursive = TRUE)
for (stale in list.files(out_dir, full.names = TRUE)) file.remove(stale)

setClass("DisrobePoint",
         representation(x = "numeric", y = "numeric", label = "character"))
setClass("DisrobeNested",
         representation(origin = "DisrobePoint", tags = "character"))

shared_env <- new.env(parent = globalenv())
assign("scale_factor", 3.5, envir = shared_env)
assign("caption", "shared", envir = shared_env)

child_env <- new.env(parent = shared_env)
assign("alpha", 1L, envir = child_env)
assign("beta", "two", envir = child_env)
assign("gamma", c(TRUE, FALSE), envir = child_env)

promise_env <- new.env(parent = globalenv())
delayedAssign("lazy_value", 6 * 7, assign.env = promise_env)

dots_env <- (function(...) environment())(1, "two", TRUE)

capture_ellipsis <- function(...) get("...", envir = environment())

plain_closure <- function(x, y = 2, label = "sum") x + y * 2
compiled_closure <- cmpfun(function(x, y = 2, label = "sum") x + y * 2)
recursive_closure <- cmpfun(function(n) if (n <= 1) 1 else n * Recall(n - 1))

objects <- list(
  nil = NULL,
  symbol = quote(alpha_symbol),
  pairlist = pairlist(first = 1, second = "two", third = TRUE),
  closure = plain_closure,
  closure_compiled = compiled_closure,
  closure_recursive = recursive_closure,
  closure_namespaced = stats::rnorm,
  environment_chain = child_env,
  environment_promise = promise_env,
  environment_dots = dots_env,
  language = quote(outer(inner(x, y + 1), z = "k")),
  language_block = quote({
    a <- 1
    b <- a + 2
    print(b)
  }),
  special_if = `if`,
  builtin_sum = sum,
  logical = c(TRUE, FALSE, NA),
  integer = c(1L, -5L, NA_integer_, 2147483647L),
  double = c(1.5, -2.25, 0, NA, Inf, -Inf, NaN),
  complex = complex(real = c(1, -2.5, 0), imaginary = c(0, 3.25, -1)),
  character = c("Hello, disrobe!", "", "tab\there", "quote\"inside"),
  character_utf8 = c("héllo", "日本語", "✓"),
  raw = as.raw(c(0x00, 0x01, 0x7f, 0xff, 0xde, 0xad, 0xbe, 0xef)),
  list_named = list(greeting = "Hello, disrobe!", numbers = c(1L, 2L, 3L),
                    pi_approx = 3.14159, labels = c("alpha", "beta", "gamma")),
  list_nested = list(name = "disrobe", fn = compiled_closure,
                     exprs = expression(a + b, sqrt(c)),
                     data = list(inner = list(deep = c(1, 2, 3)))),
  list_attributed = structure(list(a = 1L, b = 2L),
                              class = "disrobe_demo",
                              provenance = "generated"),
  matrix_dim = structure(1:6, dim = c(2L, 3L),
                         dimnames = list(c("r1", "r2"), c("c1", "c2", "c3"))),
  factor = factor(c("low", "high", "low", "mid"),
                  levels = c("low", "mid", "high")),
  data_frame = data.frame(id = 1:3, label = c("a", "b", "c"),
                          stringsAsFactors = FALSE),
  expression_vector = expression(a + b, sqrt(c), f(x, y)),
  bytecode = compile(quote(for (i in 1:3) print(i))),
  s4_point = new("DisrobePoint", x = 1, y = 2, label = "demo"),
  s4_nested = new("DisrobeNested",
                  origin = new("DisrobePoint", x = -1, y = 0.5, label = "origin"),
                  tags = c("outer", "inner")),
  altrep_intseq = 1:1000,
  altrep_seq_len = seq_len(64),
  altrep_in_list = list(span = 5:25, note = "compact sequence inside a list"),
  external_pointer = list(ptr = new("externalptr"), note = "runtime address"),
  shared_reference = list(first = shared_env, second = shared_env),
  ellipsis = capture_ellipsis(1, "two", TRUE),
  deep_nesting = local({
    acc <- list(leaf = "bottom")
    for (i in 1:24) acc <- list(level = acc)
    acc
  }),
  empty_vectors = list(chr = character(0), int = integer(0), num = numeric(0),
                       lgl = logical(0), raw = raw(0), cplx = complex(0),
                       lst = list())
)

written <- character(0)

record <- function(path) {
  written <<- c(written, path)
  invisible(path)
}

write_rds <- function(stem, value, version, compress, ascii = FALSE) {
  suffix <- if (identical(compress, FALSE)) "none" else compress
  name <- sprintf("%s.v%d.%s%s.rds", stem, version, suffix,
                  if (ascii) ".ascii" else "")
  path <- file.path(out_dir, name)
  saveRDS(value, path, version = version, compress = compress, ascii = ascii)
  record(name)
}

write_native <- function(stem, value, version) {
  name <- sprintf("%s.v%d.native.bin", stem, version)
  path <- file.path(out_dir, name)
  con <- file(path, "wb")
  on.exit(close(con), add = TRUE)
  serialize(value, con, ascii = FALSE, xdr = FALSE, version = version)
  record(name)
}

write_rda <- function(stem, value, version, compress, ascii = FALSE) {
  suffix <- if (identical(compress, FALSE)) "none" else compress
  name <- sprintf("%s.v%d.%s%s.rda", stem, version, suffix,
                  if (ascii) ".ascii" else "")
  path <- file.path(out_dir, name)
  env <- new.env(parent = emptyenv())
  assign(stem, value, envir = env)
  save(list = stem, file = path, envir = env, version = version,
       compress = compress, ascii = ascii)
  record(name)
}

for (stem in names(objects)) {
  value <- objects[[stem]]
  for (version in c(2L, 3L)) {
    write_rds(stem, value, version = version, compress = FALSE)
    write_rds(stem, value, version = version, compress = FALSE, ascii = TRUE)
    write_native(stem, value, version = version)
  }
}

sweep_stems <- c("list_named", "closure_compiled", "altrep_intseq", "s4_point")
for (stem in sweep_stems) {
  value <- objects[[stem]]
  for (version in c(2L, 3L)) {
    for (compress in list("gzip", "bzip2", "xz")) {
      write_rds(stem, value, version = version, compress = compress)
    }
    write_rda(stem, value, version = version, compress = FALSE)
    write_rda(stem, value, version = version, compress = "gzip")
    write_rda(stem, value, version = version, compress = FALSE, ascii = TRUE)
  }
}

for (stem in c("list_nested", "environment_chain", "bytecode")) {
  write_rda(stem, objects[[stem]], version = 3L, compress = FALSE)
}

manifest <- file.path(out_dir, "..", "MANIFEST.toml")
lines <- c(
  "schema = \"disrobe-corpus-v1\"",
  "category = \"r\"",
  "target_crate = \"disrobe-pass-scriptlang\"",
  sprintf("r_release = \"%s\"", getRversion()),
  sprintf("r_banner = \"%s\"", R.version.string),
  sprintf("r_platform = \"%s\"", R.version$platform),
  "generator = \"corpus/r/generate.R\"",
  "reference = \"corpus/r/describe.R\"",
  "notes = \"\"\"",
  "Every file here was written by the pinned R release named above, by running",
  "  Rscript corpus/r/generate.R objects",
  "from this directory. Nothing in this directory was authored by hand, and no",
  "expected value is stored beside it: describe.R re-reads each file with R at",
  "test time and reports what R sees, which is the reference the reader is",
  "graded against.",
  "\"\"\"",
  ""
)

for (name in written) {
  path <- file.path(out_dir, name)
  lines <- c(lines,
             "[[sample]]",
             sprintf("name = \"objects/%s\"", name),
             sprintf("size_bytes = %d", file.size(path)),
             sprintf("md5 = \"%s\"", unname(tools::md5sum(path))),
             "")
}

writeLines(lines, manifest, sep = "\n")
cat(sprintf("wrote %d objects with %s\n", length(written), R.version.string))
