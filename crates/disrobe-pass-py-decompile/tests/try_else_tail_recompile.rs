#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod common;

use std::path::PathBuf;

use crate::common::band::{
    BandInterpreter, BandOutcome, band_scratch, recompile_equiv_inline, resolve_band,
};

const TARGET_VERSIONS: &[&str] = &["3.12", "3.14"];
const PRERELEASE: &[&str] = &["3.15"];

fn assert_recompiles(label: &str, program: &str) {
    assert_recompiles_on(label, program, TARGET_VERSIONS, PRERELEASE);
}

fn assert_recompiles_on(
    label: &str,
    program: &str,
    target_versions: &[&'static str],
    prerelease: &[&'static str],
) {
    let band: Vec<BandInterpreter> = resolve_band(target_versions, prerelease);
    if band.is_empty() {
        return;
    }
    let scratch: PathBuf = band_scratch(label);
    let mut checked: usize = 0usize;
    for interp in &band {
        let (outcome, source): (BandOutcome, String) =
            recompile_equiv_inline(interp, program, label, &scratch);
        match outcome {
            BandOutcome::RecompileEquiv => {}
            BandOutcome::SourceTokenMatch => panic!(
                "{label} py{}: token-match, not recompile-equivalent:\n{source}",
                interp.alias
            ),
            BandOutcome::Tolerated(detail) => {
                assert!(
                    interp.is_prerelease,
                    "{label} py{}: Tolerated from a stable interpreter is a real failure: \
                     {detail}\n{source}",
                    interp.alias
                );
            }
            BandOutcome::Failed(reason) => {
                panic!(
                    "{label} py{}: {reason}\n--- recovered:\n{source}",
                    interp.alias
                )
            }
        }
        checked += 1;
    }
    assert!(
        checked > 0,
        "{label}: no interpreter validated the recovery"
    );
}

#[test]
fn try_except_else_with_real_else_body() {
    let program: &str = "\
def f(x):
    try:
        y = compute(x)
    except ValueError:
        return 0
    else:
        record(y)
    return y
";
    assert_recompiles("try_else_real_body", program);
}

#[test]
fn try_except_else_tail_not_swallowed() {
    let program: &str = "\
def f(x):
    try:
        y = compute(x)
    except ValueError:
        return None
    else:
        if guard(y):
            return None
    finalize(x)
    return y
";
    assert_recompiles("try_else_tail", program);
}

#[test]
fn try_body_normal_exit_not_return_none() {
    let program: &str = "\
def f(seq):
    for item in seq:
        try:
            handle(item)
        except KeyError:
            continue
        emit(item)
    return len(seq)
";
    assert_recompiles("try_normal_exit", program);
}

#[test]
fn nested_try_inside_else_entangled() {
    let program: &str = "\
import os, stat
def ismount(path):
    try:
        s1 = os.lstat(path)
    except (OSError, ValueError):
        return False
    else:
        if stat.S_ISLNK(s1.st_mode):
            return False
    path = os.fspath(path)
    if isinstance(path, bytes):
        parent = join(path, b'..')
    else:
        parent = join(path, '..')
    try:
        s2 = os.lstat(parent)
    except OSError:
        parent = realpath(parent)
        try:
            s2 = os.lstat(parent)
        except OSError:
            return False
    return s1.st_dev != s2.st_dev or s1.st_ino == s2.st_ino
";
    assert_recompiles("nested_try_in_else", program);
}

#[test]
fn terminating_handler_no_else_tail_is_sibling_try() {
    let program: &str = "\
cache = {}
def checkcache(filename=None):
    if filename is None:
        filenames = cache.copy().keys()
    else:
        filenames = [filename]
    for filename in filenames:
        entry = cache.get(filename, None)
        if entry is None or len(entry) == 1:
            continue
        size, mtime, lines, fullname = entry
        if mtime is None:
            continue
        try:
            import os
        except ImportError:
            return
        try:
            stat = os.stat(fullname)
        except (OSError, ValueError):
            cache.pop(filename, None)
            continue
        if size != stat.st_size or mtime != stat.st_mtime:
            cache.pop(filename, None)
";
    assert_recompiles("terminating_handler_sibling_try", program);
}

#[test]
fn else_arm_with_after_inlined_return_then() {
    let program: &str = "\
def f(argv):
    if len(argv) == 1:
        show(default_source())
    else:
        fn = argv[1]
        with open(fn) as handle:
            show(parse(handle, fn))
";
    assert_recompiles("else_arm_with_inlined_return", program);
}

#[test]
fn else_arm_try_after_inlined_return_then() {
    let program: &str = "\
def f(argv):
    if len(argv) == 1:
        show(default_source())
    else:
        try:
            fn = argv[1]
            show(parse(fn))
        except OSError as exc:
            raise SystemExit(exc) from exc
";
    assert_recompiles("else_arm_try_inlined_return", program);
}

#[test]
fn both_arms_with_return_keeps_else() {
    let program: &str = "\
class FileLoader:
    def get_data(self, path):
        if isinstance(self, (SourceLoader, SourcelessFileLoader, ExtensionFileLoader)):
            with _io.open_code(str(path)) as file:
                return file.read()
        else:
            with _io.FileIO(path, 'r') as file:
                return file.read()
";
    assert_recompiles_on("both_arms_with_return", program, &["3.14"], &[]);
}

#[test]
fn conditional_then_arm_sibling_stays_sibling() {
    let program: &str = "\
def to_list(self, rowdict):
    if self.extrasaction == 'raise':
        wrong = rowdict.keys() - self.fieldnames
        if wrong:
            raise ValueError('bad: ' + ', '.join([repr(x) for x in wrong]))
    return (rowdict.get(key, self.restval) for key in self.fieldnames)
";
    assert_recompiles("conditional_then_sibling", program);
}

#[test]
fn try_except_else_nested_try_body_not_duplicated() {
    let program: &str = "\
def move(self, target):
    try:
        target = self.with_segments(target)
    except TypeError:
        pass
    else:
        ensure_different_files(self, target)
        try:
            os.replace(self, target)
        except OSError as err:
            if err.errno != EXDEV:
                raise
        else:
            return target.joinpath()
    target = self.copy(target, follow_symlinks=False, preserve_metadata=True)
    self._delete()
    return target
";
    assert_recompiles("try_else_nested_try_no_dup_handler", program);
}

#[test]
fn try_except_else_with_nested_handler_keeps_tail() {
    let program: &str = "\
def ensure_different_files(source, target):
    try:
        source_file_id = source.info._file_id
        target_file_id = target.info._file_id
    except AttributeError:
        if source != target:
            return
    else:
        try:
            if source_file_id() != target_file_id():
                return
        except (OSError, ValueError):
            return
    err = OSError(EINVAL, 'Source and target are the same file')
    err.filename = str(source)
    err.filename2 = str(target)
    raise err
";
    assert_recompiles_on(
        "try_else_nested_handler_keeps_tail",
        program,
        &["3.14"],
        &[],
    );
}

#[test]
fn os_makedirs_keeps_sibling_handlers_separate() {
    let program: &str = "\
def makedirs(name, mode=0o777, exist_ok=False):
    head, tail = path.split(name)
    if not tail:
        head, tail = path.split(head)
    if head and tail and not path.exists(head):
        try:
            makedirs(head, exist_ok=exist_ok)
        except FileExistsError:
            pass
        cdir = curdir
        if isinstance(tail, bytes):
            cdir = bytes(curdir, 'ASCII')
        if tail == cdir:
            return
    try:
        mkdir(name, mode)
    except OSError:
        if not exist_ok or not path.isdir(name):
            raise
";
    assert_recompiles_on("os_makedirs_sibling_handlers", program, &["3.14"], &[]);
}

#[test]
fn modulefinder_safe_import_hook_keeps_else_handler_separate() {
    let program: &str = "\
class ModuleFinder:
    def _safe_import_hook(self, name, caller, fromlist, level=-1):
        if name in self.badmodules:
            self._add_badmodule(name, caller)
            return
        try:
            self.import_hook(name, caller, level=level)
        except ImportError as msg:
            self.msg(2, 'ImportError:', str(msg))
            self._add_badmodule(name, caller)
        except SyntaxError as msg:
            self.msg(2, 'SyntaxError:', str(msg))
            self._add_badmodule(name, caller)
        else:
            if fromlist:
                for sub in fromlist:
                    fullname = name + '.' + sub
                    if fullname in self.badmodules:
                        self._add_badmodule(fullname, caller)
                        continue
                    try:
                        self.import_hook(name, caller, [sub], level=level)
                    except ImportError as msg:
                        self.msg(2, 'ImportError:', str(msg))
                        self._add_badmodule(fullname, caller)
";
    assert_recompiles_on("modulefinder_safe_import_hook", program, &["3.14"], &[]);
}

#[test]
fn pty_fork_keeps_nested_else_handler() {
    let program: &str = "\
def fork():
    try:
        pid, fd = os.forkpty()
    except (AttributeError, OSError):
        pass
    else:
        if pid == CHILD:
            try:
                os.setsid()
            except OSError:
                pass
        return pid, fd
    master_fd, slave_fd = openpty()
    pid = os.fork()
    if pid == CHILD:
        os.close(master_fd)
        os.login_tty(slave_fd)
    else:
        os.close(slave_fd)
    return pid, master_fd
";
    assert_recompiles_on("pty_fork", program, &["3.14"], &[]);
}

#[test]
fn zipimport_get_module_code_keeps_else_handler_separate() {
    let program: &str = "\
def _get_module_code(self, fullname):
    path = _get_module_path(self, fullname)
    import_error = None
    for suffix, isbytecode, ispackage in _zip_searchorder:
        fullpath = path + suffix
        _bootstrap._verbose_message('trying {}{}{}', self.archive, path_sep, fullpath, verbosity=2)
        try:
            toc_entry = self._get_files()[fullpath]
        except KeyError:
            pass
        else:
            modpath = toc_entry[0]
            data = _get_data(self.archive, toc_entry)
            code = None
            if isbytecode:
                try:
                    code = _unmarshal_code(self, modpath, fullpath, fullname, data)
                except ImportError as exc:
                    import_error = exc
            else:
                code = _compile_source(modpath, data)
            if code is None:
                continue
            modpath = toc_entry[0]
            return code, ispackage, modpath
    else:
        if import_error:
            msg = f'module load failed: {import_error}'
            raise ZipImportError(msg, name=fullname) from import_error
        else:
            raise ZipImportError(f\"can't find module {fullname!r}\", name=fullname)
";
    assert_recompiles_on("zipimport_get_module_code", program, &["3.14"], &[]);
}

#[test]
fn asyncio_format_coroutine_keeps_nested_running_fallback() {
    let program: &str = "\
def _format_coroutine(coro):
    def is_running(coro):
        try:
            return coro.cr_running
        except AttributeError:
            try:
                return coro.gi_running
            except AttributeError:
                return False
    return is_running(coro)
";
    assert_recompiles_on(
        "asyncio_format_coroutine_running",
        program,
        &["3.14.5"],
        &[],
    );
}

#[test]
fn email_base64_fallback_keeps_nested_handler_returns() {
    let program: &str = "\
def decode_b(encoded):
    pad_err = len(encoded) % 4
    missing_padding = b'==='[:4-pad_err] if pad_err else b''
    try:
        return (
            base64.b64decode(encoded + missing_padding, validate=True),
            [errors.InvalidBase64PaddingDefect()] if pad_err else [],
        )
    except binascii.Error:
        try:
            return (
                base64.b64decode(encoded, validate=False),
                [errors.InvalidBase64CharactersDefect()],
            )
        except binascii.Error:
            try:
                return (
                    base64.b64decode(encoded + b'==', validate=False),
                    [errors.InvalidBase64CharactersDefect(),
                     errors.InvalidBase64PaddingDefect()],
                )
            except binascii.Error:
                return encoded, [errors.InvalidBase64LengthDefect()]
";
    assert_recompiles_on("email_base64_fallback", program, &["3.14.5"], &[]);
}

#[test]
fn try_except_import_else_nested_try_not_duplicated() {
    let program: &str = "\
def win32_edition():
    try:
        import winreg
    except ImportError:
        pass
    else:
        try:
            cvkey = 'SOFTWARE'
            with winreg.OpenKeyEx(winreg.HKEY_LOCAL_MACHINE, cvkey) as key:
                return winreg.QueryValueEx(key, 'EditionId')[0]
        except OSError:
            pass
    return None
";
    assert_recompiles("try_import_else_nested_try_no_dup", program);
}

#[test]
fn if_then_try_before_import_else_nested_try_not_duplicated() {
    let program: &str = "\
def _win32_ver(version, csd, ptype):
    try:
        version, product_type, ptype, spmajor, spminor = _wmi_query('OS', 'Version', 'ProductType', 'BuildType', 'ServicePackMajorVersion', 'ServicePackMinorVersion')
        is_client = int(product_type) == 1
        if spminor and spminor != '0':
            csd = f'SP{spmajor}.{spminor}'
        else:
            csd = f'SP{spmajor}'
        return version, csd, ptype, is_client
    except OSError:
        pass
    try:
        from sys import getwindowsversion
    except ImportError:
        return version, csd, ptype, True
    winver = getwindowsversion()
    is_client = getattr(winver, 'product_type', 1) == 1
    try:
        version = _syscmd_ver()[2]
        major, minor, build = map(int, version.split('.'))
    except ValueError:
        major, minor, build = winver.platform_version or winver[:3]
        version = '{0}.{1}.{2}'.format(major, minor, build)
    if winver[:2] == (major, minor):
        try:
            csd = 'SP{}'.format(winver.service_pack_major)
        except AttributeError:
            if csd[:13] == 'Service Pack ':
                csd = 'SP' + csd[13:]
    try:
        import winreg
    except ImportError:
        pass
    else:
        try:
            cvkey = r'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion'
            with winreg.OpenKeyEx(winreg.HKEY_LOCAL_MACHINE, cvkey) as key:
                ptype = winreg.QueryValueEx(key, 'CurrentType')[0]
        except OSError:
            pass
    return version, csd, ptype, is_client
";
    assert_recompiles_on(
        "if_then_try_before_import_else_nested_try",
        program,
        &["3.14"],
        &[],
    );
}

#[test]
fn handler_if_else_rejoining_via_backward_exit_keeps_else() {
    let program: &str = "\
def parse_params(value):
    params = []
    while value:
        try:
            token, value = get_one(value)
            params.append(token)
        except ParseError:
            leader = None
            if value[0] in LEADERS:
                leader, value = get_cfws(value)
            if not value:
                params.append(leader)
                return params
            if value[0] == ';':
                if leader is not None:
                    params.append(leader)
                params.append(defect('empty'))
            else:
                token, value = get_invalid(value)
                if leader:
                    token.insert(0, leader)
                params.append(token)
                params.append(defect('invalid'))
        if value and value[0] != ';':
            params.append(invalid(value))
        if value:
            value = value[1:]
    return params
";
    assert_recompiles_on("handler_if_else_backward_exit", program, &["3.14"], &[]);
}

#[test]
fn handler_if_elif_else_rejoining_via_backward_exit() {
    let program: &str = "\
def collect(value):
    out = []
    while value:
        try:
            token, value = one(value)
            out.append(token)
        except ParseError:
            leader = None
            if value[0] in LEADERS:
                leader, value = cfws(value)
                if not value or value[0] == ',':
                    out.append(leader)
                    out.append(defect('nocontent'))
                else:
                    token, value = invalid(value, ',')
                    out.append(token)
                    out.append(defect('bad'))
            elif value[0] == ',':
                out.append(defect('empty'))
            else:
                token, value = invalid(value, ',')
                out.append(token)
                out.append(defect('bad'))
        if value and value[0] != ',':
            token, value = invalid(value, ',')
            out.append(token)
        if value:
            out.append(sep)
            value = value[1:]
    return out
";
    assert_recompiles_on(
        "handler_if_elif_else_backward_exit",
        program,
        &["3.14"],
        &[],
    );
}
