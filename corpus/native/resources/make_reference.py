import ctypes
import ctypes.wintypes as wt
import hashlib
import json
import os
import sys

image = os.path.abspath(sys.argv[1])
out = sys.argv[2]

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
version = ctypes.WinDLL('version', use_last_error=True)
LOAD_LIBRARY_AS_DATAFILE = 0x2
LOAD_LIBRARY_AS_IMAGE_RESOURCE = 0x20

kernel32.LoadLibraryExW.restype = wt.HMODULE
kernel32.LoadLibraryExW.argtypes = [wt.LPCWSTR, wt.HANDLE, wt.DWORD]
kernel32.FindResourceExW.restype = wt.HANDLE
kernel32.FindResourceExW.argtypes = [wt.HMODULE, ctypes.c_void_p, ctypes.c_void_p, wt.WORD]
kernel32.SizeofResource.argtypes = [wt.HMODULE, wt.HANDLE]
kernel32.LoadResource.restype = wt.HANDLE
kernel32.LoadResource.argtypes = [wt.HMODULE, wt.HANDLE]
kernel32.LockResource.restype = ctypes.c_void_p
kernel32.LockResource.argtypes = [wt.HANDLE]
version.GetFileVersionInfoSizeW.argtypes = [wt.LPCWSTR, ctypes.POINTER(wt.DWORD)]
version.GetFileVersionInfoW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.c_void_p]
version.VerQueryValueW.argtypes = [ctypes.c_void_p, wt.LPCWSTR, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wt.UINT)]

module = kernel32.LoadLibraryExW(image, None, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE)
if not module:
    raise ctypes.WinError(ctypes.get_last_error())

TypeProc = ctypes.WINFUNCTYPE(wt.BOOL, wt.HMODULE, ctypes.c_void_p, ctypes.c_void_p)
NameProc = ctypes.WINFUNCTYPE(wt.BOOL, wt.HMODULE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)
LangProc = ctypes.WINFUNCTYPE(wt.BOOL, wt.HMODULE, ctypes.c_void_p, ctypes.c_void_p, wt.WORD, ctypes.c_void_p)
kernel32.EnumResourceTypesW.argtypes = [wt.HMODULE, TypeProc, ctypes.c_void_p]
kernel32.EnumResourceNamesW.argtypes = [wt.HMODULE, ctypes.c_void_p, NameProc, ctypes.c_void_p]
kernel32.EnumResourceLanguagesW.argtypes = [wt.HMODULE, ctypes.c_void_p, ctypes.c_void_p, LangProc, ctypes.c_void_p]


def ident(value):
    if value >> 16 == 0:
        return value
    return ctypes.wstring_at(value)


keepalive = []


def raw(value):
    if isinstance(value, int):
        return ctypes.c_void_p(value)
    buffer = ctypes.create_unicode_buffer(value)
    keepalive.append(buffer)
    return ctypes.c_void_p(ctypes.addressof(buffer))


types = []
kernel32.EnumResourceTypesW(module, TypeProc(lambda _m, t, _p: types.append(ident(t)) or True), None)
tree = []
for rtype in types:
    names = []
    kernel32.EnumResourceNamesW(module, raw(rtype), NameProc(lambda _m, _t, n, _p: names.append(ident(n)) or True), None)
    for name in names:
        languages = []
        kernel32.EnumResourceLanguagesW(module, raw(rtype), raw(name),
                                        LangProc(lambda _m, _t, _n, lang, _p: languages.append(lang) or True), None)
        for language in languages:
            handle = kernel32.FindResourceExW(module, raw(rtype), raw(name), language)
            size = kernel32.SizeofResource(module, handle)
            data = ctypes.string_at(kernel32.LockResource(kernel32.LoadResource(module, handle)), size)
            tree.append({'type': rtype, 'name': name, 'language': language, 'size': size,
                         'sha256': hashlib.sha256(data).hexdigest()})

handle = wt.DWORD()
size = version.GetFileVersionInfoSizeW(image, ctypes.byref(handle))
block = ctypes.create_string_buffer(size)
version.GetFileVersionInfoW(image, 0, size, block)


def query(path):
    pointer = ctypes.c_void_p()
    length = wt.UINT()
    if not version.VerQueryValueW(block, path, ctypes.byref(pointer), ctypes.byref(length)):
        return None, 0
    return pointer.value, length.value


fixed_pointer, _ = query('\\')
fixed = (ctypes.c_uint32 * 13).from_address(fixed_pointer)
split = lambda high, low: f'{high >> 16}.{high & 0xFFFF}.{low >> 16}.{low & 0xFFFF}'
translation_pointer, translation_length = query('\\VarFileInfo\\Translation')
pairs = (ctypes.c_uint16 * (translation_length // 2)).from_address(translation_pointer)
translations = [[pairs[i], pairs[i + 1]] for i in range(0, len(pairs), 2)]
keys = ['CompanyName', 'FileDescription', 'FileVersion', 'InternalName', 'LegalCopyright',
        'OriginalFilename', 'ProductName', 'ProductVersion']
strings = {}
for language, codepage in translations:
    table = f'{language:04x}{codepage:04x}'
    values = {}
    for key in keys:
        pointer, length = query(f'\\StringFileInfo\\{table}\\{key}')
        if pointer:
            values[key] = ctypes.wstring_at(pointer).rstrip('\0')
    strings[table] = values
version_info = {
    'file_version': split(fixed[2], fixed[3]),
    'product_version': split(fixed[4], fixed[5]),
    'flags_mask': fixed[6], 'flags': fixed[7], 'os': fixed[8], 'type': fixed[9], 'subtype': fixed[10],
    'translations': translations, 'strings': strings,
}

kernel32.SetThreadUILanguage.argtypes = [wt.WORD]
user32 = ctypes.WinDLL('user32', use_last_error=True)
user32.LoadStringW.argtypes = [wt.HMODULE, wt.UINT, ctypes.c_void_p, ctypes.c_int]
string_tables = {}
for language in (0x0409, 0x0407):
    kernel32.SetThreadUILanguage(language)
    found = {}
    for identifier in range(0, 128):
        pointer = ctypes.c_void_p()
        length = user32.LoadStringW(module, identifier, ctypes.byref(pointer), 0)
        if length:
            found[str(identifier)] = ctypes.wstring_at(pointer.value, length)
    string_tables[str(language)] = found

with open(out, 'w', encoding='utf-8') as handle_out:
    json.dump({'tree': tree, 'version': version_info, 'strings': string_tables}, handle_out, indent=1,
              ensure_ascii=False)
