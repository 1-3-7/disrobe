suppressWarnings(suppressMessages(library(methods)))

args <- commandArgs(trailingOnly = TRUE)
if (length(args) < 1L) {
  stop("usage: Rscript describe.R <serialized-file> [more files...]")
}
if (length(args) == 1L && dir.exists(args[[1L]])) {
  args <- sort(list.files(args[[1L]], full.names = TRUE))
}
for (candidate in args) {
  if (!file.exists(candidate)) {
    stop(sprintf("no such file: %s", candidate))
  }
}

emit <- function(key, ...) {
  fields <- vapply(list(...), function(v) {
    v <- as.character(v)
    v <- gsub("\\", "\\\\", v, fixed = TRUE)
    v <- gsub("\t", "\\t", v, fixed = TRUE)
    v <- gsub("\r", "\\r", v, fixed = TRUE)
    gsub("\n", "\\n", v, fixed = TRUE)
  }, character(1L))
  cat(paste(c(key, fields), collapse = "\t"), "\n", sep = "")
}

strings <- new.env(parent = emptyenv())
symbols <- new.env(parent = emptyenv())
remember <- function(env, value) {
  if (length(value) != 1L || is.na(value) || !nzchar(value)) return(invisible(NULL))
  assign(paste0("k", value), TRUE, envir = env)
  invisible(NULL)
}
add_string <- function(v) remember(strings, v)
add_symbol <- function(v) remember(symbols, v)

is_opaque_env <- function(e) {
  identical(e, globalenv()) || identical(e, baseenv()) || identical(e, emptyenv()) ||
    isNamespace(e) || identical(e, .BaseNamespaceEnv)
}

env_label <- function(e) {
  if (identical(e, globalenv())) return("R_GlobalEnv")
  if (identical(e, emptyenv())) return("R_EmptyEnv")
  if (identical(e, baseenv())) return("base")
  if (isNamespace(e)) return(paste0("namespace:", environmentName(e)))
  name <- environmentName(e)
  if (nzchar(name)) name else "anonymous"
}

flat_deparse <- function(v) {
  paste(deparse(v, width.cutoff = 500L, control = c("keepNA", "niceNames")),
        collapse = "")
}

bytecode_expression <- function(bc) {
  body(eval(call("function", NULL, bc)))
}

MAX_DEPTH <- 64L

collect <- function(x, depth) {
  if (depth > MAX_DEPTH) return(invisible(NULL))
  kind <- typeof(x)
  if (kind == "character") {
    for (s in x) add_string(s)
  } else if (kind == "symbol") {
    add_symbol(as.character(x))
  } else if (kind %in% c("list", "expression")) {
    for (i in seq_along(x)) collect(x[[i]], depth + 1L)
  } else if (kind %in% c("language", "pairlist")) {
    parts <- as.list(x)
    tags <- names(parts)
    if (!is.null(tags)) for (t in tags) add_symbol(t)
    for (nm in seq_along(parts)) {
      if (nzchar(flat_deparse(parts[[nm]]))) collect(parts[[nm]], depth + 1L)
    }
  } else if (kind == "closure") {
    formal_list <- as.list(formals(x))
    for (nm in names(formal_list)) {
      add_symbol(nm)
      if (nzchar(flat_deparse(formal_list[[nm]]))) {
        collect(formal_list[[nm]], depth + 1L)
      }
    }
    collect(body(x), depth + 1L)
  } else if (kind == "bytecode") {
    collect(bytecode_expression(x), depth + 1L)
  } else if (kind == "S4") {
    for (nm in slotNames(x)) {
      add_symbol(nm)
      collect(slot(x, nm), depth + 1L)
    }
  } else if (kind == "environment") {
    if (!is_opaque_env(x)) {
      for (nm in ls(x, all.names = TRUE)) {
        add_symbol(nm)
        if (!bindingIsActive(nm, x)) {
          bound <- tryCatch(get(nm, envir = x, inherits = FALSE),
                            error = function(e) NULL)
          collect(bound, depth + 1L)
        }
      }
    }
  }
  if (!(kind %in% c("environment", "language", "pairlist"))) {
    attrs <- attributes(x)
    if (!is.null(attrs)) {
      for (nm in names(attrs)) {
        add_symbol(nm)
        collect(attrs[[nm]], depth + 1L)
      }
    }
  }
  invisible(NULL)
}

describe_closure <- function(f) {
  formal_list <- as.list(formals(f))
  for (nm in names(formal_list)) {
    rendered <- flat_deparse(formal_list[[nm]])
    emit("formal", nm, if (nzchar(rendered)) rendered else "<none>")
  }
  b <- body(f)
  emit("bodytype", typeof(b))
  emit("body", if (typeof(b) == "bytecode") {
    flat_deparse(bytecode_expression(b))
  } else {
    flat_deparse(b)
  })
}

describe_one <- function(path) {

strings <<- new.env(parent = emptyenv())
symbols <<- new.env(parent = emptyenv())
emit("begin", basename(path))

extension <- tolower(tools::file_ext(path))
if (extension == "rda") {
  container <- "rda"
  holder <- new.env(parent = emptyenv())
  bindings <- load(path, envir = holder)
  if (length(bindings) != 1L) {
    stop(sprintf("describe.R grades one binding per workspace, found %d", length(bindings)))
  }
  emit("container", "rda")
  for (nm in bindings) {
    emit("binding", nm)
    add_symbol(nm)
  }
  value <- get(bindings[[1L]], envir = holder)
  emit("streamroottype", "pairlist")
} else {
  container <- "rds"
  value <- readRDS(path)
  emit("container", "rds")
  emit("streamroottype", typeof(value))
}

emit("rversion", as.character(getRversion()))
emit("file", basename(path))
emit("valuetype", typeof(value))
emit("valuelength", length(value))

value_names <- if (typeof(value) %in% c("language", "pairlist")) {
  NULL
} else {
  attr(value, "names")
}
if (!is.null(value_names)) for (nm in value_names) emit("name", nm)

value_class <- attr(value, "class")
if (!is.null(value_class)) for (cl in value_class) emit("class", cl)

if (typeof(value) == "raw") {
  emit("rawbytes", paste(sprintf("%02x", as.integer(value)), collapse = ""))
}

if (typeof(value) == "complex") {
  for (z in value) emit("complex", flat_deparse(Re(z)), flat_deparse(Im(z)))
}

if (typeof(value) == "closure") describe_closure(value)

if (typeof(value) == "bytecode") {
  emit("bytecodeexpr", flat_deparse(bytecode_expression(value)))
}

if (isS4(value)) {
  emit("s4class", class(value)[[1L]])
  for (nm in setdiff(names(attributes(value)), "class")) emit("s4slot", nm)
}

if (typeof(value) == "environment" && !is_opaque_env(value)) {
  for (nm in ls(value, all.names = TRUE)) emit("envbinding", nm)
  parent <- parent.env(value)
  hops <- 0L
  while (hops < 8L) {
    emit("envparent", env_label(parent))
    if (is_opaque_env(parent)) break
    parent <- parent.env(parent)
    hops <- hops + 1L
  }
}

if (typeof(value) %in% c("integer", "double") && length(value) <= 4096L &&
    is.null(attributes(value))) {
  emit("vectordeparse", flat_deparse(value))
}

collect(value, 0L)

for (key in sort(ls(strings))) emit("string", substring(key, 2L))
for (key in sort(ls(symbols))) emit("symbol", substring(key, 2L))

emit("end", container)
invisible(NULL)
}

for (candidate in args) describe_one(candidate)
