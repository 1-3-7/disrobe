use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ModuleOrigin {
    App,
    Stdlib,
    ThirdParty,
}

impl ModuleOrigin {
    #[must_use]
    pub const fn dir(self) -> &'static str {
        match self {
            Self::App => "app",
            Self::Stdlib => "libs/stdlib",
            Self::ThirdParty => "libs",
        }
    }
}

const STDLIB_TOP: &[&str] = &[
    "__future__",
    "_abc",
    "_aix",
    "_android",
    "_apple",
    "_ast",
    "_asyncio",
    "_bisect",
    "_blake2",
    "_bootlocale",
    "_bz2",
    "_codecs",
    "_collections",
    "_collections_abc",
    "_compat_pickle",
    "_compression",
    "_contextvars",
    "_csv",
    "_ctypes",
    "_curses",
    "_datetime",
    "_decimal",
    "_elementtree",
    "_frozen_importlib",
    "_functools",
    "_hashlib",
    "_heapq",
    "_imp",
    "_io",
    "_json",
    "_locale",
    "_lsprof",
    "_lzma",
    "_markupbase",
    "_md5",
    "_multibytecodec",
    "_multiprocessing",
    "_opcode",
    "_operator",
    "_osx_support",
    "_pickle",
    "_posixsubprocess",
    "_py_abc",
    "_pydatetime",
    "_pydecimal",
    "_pyio",
    "_pylong",
    "_pyrepl",
    "_queue",
    "_random",
    "_sha1",
    "_sha2",
    "_sha3",
    "_signal",
    "_sitebuiltins",
    "_socket",
    "_sqlite3",
    "_sre",
    "_ssl",
    "_stat",
    "_statistics",
    "_string",
    "_strptime",
    "_struct",
    "_symtable",
    "_thread",
    "_threading_local",
    "_tkinter",
    "_tokenize",
    "_tracemalloc",
    "_typing",
    "_warnings",
    "_weakref",
    "_weakrefset",
    "_winapi",
    "_wmi",
    "_zoneinfo",
    "_zstd",
    "abc",
    "aifc",
    "antigravity",
    "argparse",
    "array",
    "ast",
    "asyncio",
    "atexit",
    "base64",
    "bdb",
    "binascii",
    "bisect",
    "builtins",
    "bz2",
    "cProfile",
    "calendar",
    "cgi",
    "cgitb",
    "chunk",
    "cmath",
    "cmd",
    "code",
    "codecs",
    "codeop",
    "collections",
    "colorsys",
    "compileall",
    "concurrent",
    "configparser",
    "contextlib",
    "contextvars",
    "copy",
    "copyreg",
    "crypt",
    "csv",
    "ctypes",
    "curses",
    "dataclasses",
    "datetime",
    "dbm",
    "decimal",
    "difflib",
    "dis",
    "doctest",
    "email",
    "encodings",
    "ensurepip",
    "enum",
    "errno",
    "faulthandler",
    "fcntl",
    "filecmp",
    "fileinput",
    "fnmatch",
    "fractions",
    "ftplib",
    "functools",
    "gc",
    "genericpath",
    "getopt",
    "getpass",
    "gettext",
    "glob",
    "graphlib",
    "gzip",
    "hashlib",
    "heapq",
    "hmac",
    "html",
    "http",
    "idlelib",
    "imaplib",
    "imghdr",
    "importlib",
    "inspect",
    "io",
    "ipaddress",
    "itertools",
    "json",
    "keyword",
    "linecache",
    "locale",
    "logging",
    "lzma",
    "mailbox",
    "marshal",
    "math",
    "mimetypes",
    "mmap",
    "modulefinder",
    "msvcrt",
    "multiprocessing",
    "netrc",
    "nntplib",
    "ntpath",
    "nturl2path",
    "numbers",
    "opcode",
    "operator",
    "optparse",
    "os",
    "pathlib",
    "pdb",
    "pickle",
    "pickletools",
    "pkgutil",
    "platform",
    "plistlib",
    "poplib",
    "posixpath",
    "pprint",
    "profile",
    "pstats",
    "pty",
    "pwd",
    "py_compile",
    "pyclbr",
    "pydoc",
    "pydoc_data",
    "pyexpat",
    "queue",
    "quopri",
    "random",
    "re",
    "reprlib",
    "resource",
    "rlcompleter",
    "runpy",
    "sched",
    "secrets",
    "select",
    "selectors",
    "shelve",
    "shlex",
    "shutil",
    "signal",
    "site",
    "smtplib",
    "sndhdr",
    "socket",
    "socketserver",
    "sqlite3",
    "sre_compile",
    "sre_constants",
    "sre_parse",
    "ssl",
    "stat",
    "statistics",
    "string",
    "stringprep",
    "struct",
    "subprocess",
    "symtable",
    "sys",
    "sysconfig",
    "tabnanny",
    "tarfile",
    "tempfile",
    "termios",
    "textwrap",
    "this",
    "threading",
    "time",
    "timeit",
    "tkinter",
    "token",
    "tokenize",
    "tomllib",
    "trace",
    "traceback",
    "tracemalloc",
    "tty",
    "turtle",
    "turtledemo",
    "types",
    "typing",
    "unicodedata",
    "unittest",
    "urllib",
    "uu",
    "uuid",
    "venv",
    "warnings",
    "wave",
    "weakref",
    "webbrowser",
    "winreg",
    "winsound",
    "wsgiref",
    "xdrlib",
    "xml",
    "xmlrpc",
    "zipapp",
    "zipfile",
    "zipimport",
    "zlib",
    "zoneinfo",
];

const PHELLO: &[&str] = &["__hello__", "__phello__"];

#[must_use]
pub fn classify(module_name: &str, app_packages: &[String]) -> ModuleOrigin {
    let top: &str = module_name.split('.').next().unwrap_or(module_name);
    if app_packages.iter().any(|p: &String| p == top) {
        return ModuleOrigin::App;
    }
    if STDLIB_TOP.contains(&top) || PHELLO.contains(&top) {
        return ModuleOrigin::Stdlib;
    }
    ModuleOrigin::ThirdParty
}

const LIBRARY_PATH_MARKERS: &[&str] = &[
    "site-packages",
    "dist-packages",
    "/lib/python",
    "\\lib\\python",
    "/lib64/python",
    "python3",
    "/usr/lib",
    "/usr/local/lib",
    "<frozen",
    "/nuitka/",
    "\\nuitka\\",
];

/// Whether a recovered `co_filename` is the user's own source rather than a bundled library.
#[must_use]
pub fn filename_is_app_source(filename: &str) -> bool {
    if filename.is_empty() {
        return false;
    }
    let lower: String = filename.to_ascii_lowercase();
    if LIBRARY_PATH_MARKERS
        .iter()
        .any(|m: &&str| lower.contains(m))
    {
        return false;
    }
    let absolute: bool = filename.starts_with('/')
        || filename.starts_with('\\')
        || (filename.len() >= 2 && filename.as_bytes()[1] == b':');
    !absolute
}

/// Classify a module, using its recovered `co_filename` to refine the App/ThirdParty boundary.
#[must_use]
pub fn classify_with_filename(
    module_name: &str,
    filename: Option<&str>,
    app_packages: &[String],
) -> ModuleOrigin {
    let top: &str = module_name.split('.').next().unwrap_or(module_name);
    if STDLIB_TOP.contains(&top) || PHELLO.contains(&top) {
        return ModuleOrigin::Stdlib;
    }
    let library_path: bool = filename.is_some_and(|p: &str| !filename_is_app_source(p));
    if library_path {
        return ModuleOrigin::ThirdParty;
    }
    if module_name == "__main__" {
        return ModuleOrigin::App;
    }
    classify(module_name, app_packages)
}

const KNOWN_THIRD_PARTY_TOP: &[&str] = &[
    "numpy",
    "scipy",
    "pandas",
    "torch",
    "tensorflow",
    "sklearn",
    "cv2",
    "PIL",
    "matplotlib",
    "requests",
    "urllib3",
    "certifi",
    "charset_normalizer",
    "idna",
    "yaml",
    "click",
    "rich",
    "pydantic",
    "pydantic_core",
    "typing_extensions",
    "setuptools",
    "pkg_resources",
    "wheel",
    "pip",
    "attr",
    "attrs",
    "six",
    "dateutil",
    "pytz",
    "cffi",
    "cryptography",
    "nacl",
    "OpenSSL",
    "google",
    "grpc",
    "protobuf",
    "flask",
    "werkzeug",
    "jinja2",
    "markupsafe",
    "click_spinner",
    "aiohttp",
    "anyio",
    "sniffio",
    "httpx",
    "httpcore",
    "h11",
    "websockets",
    "sqlalchemy",
    "psycopg2",
    "pymongo",
    "redis",
    "boto3",
    "botocore",
    "s3transfer",
    "jmespath",
    "tqdm",
    "colorama",
    "packaging",
    "importlib_metadata",
    "zipp",
    "wrapt",
    "psutil",
    "lxml",
    "bs4",
    "soupsieve",
    "regex",
    "tokenizers",
    "transformers",
    "huggingface_hub",
    "safetensors",
    "filelock",
    "fsspec",
    "networkx",
    "sympy",
    "mpmath",
    "joblib",
    "threadpoolctl",
    "numba",
    "llvmlite",
    "numpy_financial",
    "openpyxl",
    "et_xmlfile",
    "xlrd",
    "win32api",
    "win32con",
    "pywintypes",
    "pythoncom",
    "win32com",
    "pkg_resources",
];

/// The user's own top-level packages.
#[must_use]
pub fn infer_app_packages(entry_stem: Option<&str>, module_names: &[String]) -> Vec<String> {
    let stem: Option<String> = entry_stem.map(|s: &str| s.to_ascii_lowercase());
    let mut tops: Vec<String> = module_names
        .iter()
        .filter_map(|name: &String| {
            let top: &str = name.split('.').next().unwrap_or(name);
            let keep: bool = stem.as_ref().map_or_else(
                || app_candidate_without_stem(top),
                |s: &String| stem_matches(s, top),
            );
            keep.then(|| top.to_owned())
        })
        .collect();
    tops.sort_unstable();
    tops.dedup();
    tops
}

fn stem_matches(stem: &str, top: &str) -> bool {
    let lower: String = top.to_ascii_lowercase();
    let matches: bool = stem == lower
        || stem.starts_with(&format!("{lower}-"))
        || stem.starts_with(&format!("{lower}_"));
    matches && !STDLIB_TOP.contains(&top) && !PHELLO.contains(&top)
}

fn app_candidate_without_stem(top: &str) -> bool {
    let plain: bool = !top.is_empty()
        && top
            .chars()
            .next()
            .is_some_and(|c: char| c.is_ascii_alphabetic() || c == '_')
        && top
            .chars()
            .all(|c: char| c.is_ascii_alphanumeric() || c == '_');
    plain
        && top != "__main__"
        && !STDLIB_TOP.contains(&top)
        && !PHELLO.contains(&top)
        && !KNOWN_THIRD_PARTY_TOP.contains(&top)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn classifies_app_stdlib_thirdparty() {
        let app: Vec<String> = vec!["sample_app".to_owned()];
        assert_eq!(classify("sample_app.core", &app), ModuleOrigin::App);
        assert_eq!(classify("_collections_abc", &app), ModuleOrigin::Stdlib);
        assert_eq!(classify("os.path", &app), ModuleOrigin::Stdlib);
        assert_eq!(
            classify("numpy._core._dtype", &app),
            ModuleOrigin::ThirdParty
        );
    }

    #[test]
    fn filename_signal_classifies_app_vs_library() {
        assert!(filename_is_app_source("sample_app\\core.py"));
        assert!(filename_is_app_source("sample_app/__init__.py"));
        assert!(filename_is_app_source("__main__.py"));
        assert!(!filename_is_app_source(
            "C:\\Python313\\Lib\\site-packages\\numpy\\_core.py"
        ));
        assert!(!filename_is_app_source("/usr/lib/python3.13/os.py"));
        assert!(!filename_is_app_source("<frozen importlib._bootstrap>"));
    }

    #[test]
    fn classify_with_filename_routes_app_main_and_thirdparty() {
        let app: Vec<String> = vec!["sample_app".to_owned()];
        assert_eq!(
            classify_with_filename("__main__", Some("__main__.py"), &app),
            ModuleOrigin::App
        );
        assert_eq!(
            classify_with_filename("sample_app.core", Some("sample_app\\core.py"), &app),
            ModuleOrigin::App
        );
        assert_eq!(
            classify_with_filename(
                "numpy._core",
                Some("C:\\Py\\Lib\\site-packages\\numpy\\_core.py"),
                &app
            ),
            ModuleOrigin::ThirdParty
        );
        assert_eq!(
            classify_with_filename("numpy._core", Some("numpy\\_core.py"), &app),
            ModuleOrigin::ThirdParty,
            "nuitka strips the site-packages prefix; numpy must still classify as third-party via the name table, not app"
        );
        assert_eq!(
            classify_with_filename("os", Some("os.py"), &app),
            ModuleOrigin::Stdlib
        );
    }

    #[test]
    fn infers_app_package_from_entry_stem_only() {
        let names: Vec<String> = vec![
            "sample_app".to_owned(),
            "sample_app.core".to_owned(),
            "os".to_owned(),
            "numpy".to_owned(),
            "__main__".to_owned(),
        ];
        let app: Vec<String> = infer_app_packages(Some("sample_app"), &names);
        assert_eq!(app, vec!["sample_app".to_owned()]);
        let hyphen: Vec<String> = infer_app_packages(Some("sample_app-standalone"), &names);
        assert_eq!(hyphen, vec!["sample_app".to_owned()]);
        assert!(infer_app_packages(Some("nonexistent"), &names).is_empty());
    }

    #[test]
    fn infers_app_package_without_stem_excludes_stdlib_and_known_libs() {
        let names: Vec<String> = vec![
            "sample_app".to_owned(),
            "sample_app.core".to_owned(),
            "os".to_owned(),
            "numpy".to_owned(),
            "numpy._core".to_owned(),
            "__main__".to_owned(),
        ];
        let app: Vec<String> = infer_app_packages(None, &names);
        assert_eq!(app, vec!["sample_app".to_owned()]);
    }
}
