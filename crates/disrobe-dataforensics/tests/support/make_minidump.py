import ctypes
import ctypes.wintypes as wt
import json
import msvcrt
import os
import struct
import sys
import threading

if sys.platform != 'win32' or struct.calcsize('P') != 8:
    sys.exit('the minidump generator needs 64-bit CPython on Windows')

out_dir = sys.argv[1]
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
dbghelp = ctypes.WinDLL('dbghelp', use_last_error=True)
psapi = ctypes.WinDLL('psapi', use_last_error=True)
ntdll = ctypes.WinDLL('ntdll')

CONTEXT_SIZE = 1232
EXCEPTION_ACCESS_VIOLATION = 0xC0000005
FAULT_OFFSET = 0x1234
DATA_ADDRESS = 0xDEAD0000
MARKERS = {
    'rax': 0x78, 'rcx': 0x80, 'rdx': 0x88, 'rbx': 0x90, 'rsi': 0xA8, 'rdi': 0xB0,
    'r8': 0xB8, 'r9': 0xC0, 'r10': 0xC8, 'r11': 0xD0, 'r12': 0xD8, 'r13': 0xE0, 'r14': 0xE8, 'r15': 0xF0,
}
MiniDumpNormal = 0x0
MiniDumpWithFullMemoryInfo = 0x800
MiniDumpWithThreadInfo = 0x1000


class EXCEPTION_RECORD(ctypes.Structure):
    _fields_ = [
        ('ExceptionCode', wt.DWORD),
        ('ExceptionFlags', wt.DWORD),
        ('ExceptionRecord', ctypes.c_void_p),
        ('ExceptionAddress', ctypes.c_void_p),
        ('NumberParameters', wt.DWORD),
        ('ExceptionInformation', ctypes.c_uint64 * 15),
    ]


class EXCEPTION_POINTERS(ctypes.Structure):
    _fields_ = [('ExceptionRecord', ctypes.POINTER(EXCEPTION_RECORD)), ('ContextRecord', ctypes.c_void_p)]


class MINIDUMP_EXCEPTION_INFORMATION(ctypes.Structure):
    _pack_ = 4
    _fields_ = [('ThreadId', wt.DWORD), ('ExceptionPointers', ctypes.POINTER(EXCEPTION_POINTERS)), ('ClientPointers', wt.BOOL)]


class MODULEINFO(ctypes.Structure):
    _fields_ = [('lpBaseOfDll', ctypes.c_void_p), ('SizeOfImage', wt.DWORD), ('EntryPoint', ctypes.c_void_p)]


class THREADENTRY32(ctypes.Structure):
    _fields_ = [
        ('dwSize', wt.DWORD), ('cntUsage', wt.DWORD), ('th32ThreadID', wt.DWORD), ('th32OwnerProcessID', wt.DWORD),
        ('tpBasePri', wt.LONG), ('tpDeltaPri', wt.LONG), ('dwFlags', wt.DWORD),
    ]


class RTL_OSVERSIONINFOW(ctypes.Structure):
    _fields_ = [
        ('dwOSVersionInfoSize', wt.ULONG), ('dwMajorVersion', wt.ULONG), ('dwMinorVersion', wt.ULONG),
        ('dwBuildNumber', wt.ULONG), ('dwPlatformId', wt.ULONG), ('szCSDVersion', wt.WCHAR * 128),
    ]


class SYSTEM_INFO(ctypes.Structure):
    _fields_ = [
        ('wProcessorArchitecture', wt.WORD), ('wReserved', wt.WORD), ('dwPageSize', wt.DWORD),
        ('lpMinimumApplicationAddress', ctypes.c_void_p), ('lpMaximumApplicationAddress', ctypes.c_void_p),
        ('dwActiveProcessorMask', ctypes.c_void_p), ('dwNumberOfProcessors', wt.DWORD),
        ('dwProcessorType', wt.DWORD), ('dwAllocationGranularity', wt.DWORD),
        ('wProcessorLevel', wt.WORD), ('wProcessorRevision', wt.WORD),
    ]


class GUID(ctypes.Structure):
    _fields_ = [('Data1', wt.DWORD), ('Data2', wt.WORD), ('Data3', wt.WORD), ('Data4', ctypes.c_ubyte * 8)]


class SYMSRV_INDEX_INFOW(ctypes.Structure):
    _fields_ = [
        ('sizeofstruct', wt.DWORD), ('file', wt.WCHAR * 261), ('stripped', wt.BOOL), ('timestamp', wt.DWORD),
        ('size', wt.DWORD), ('dbgfile', wt.WCHAR * 261), ('pdbfile', wt.WCHAR * 261), ('guid', GUID),
        ('sig', wt.DWORD), ('age', wt.DWORD),
    ]


kernel32.GetCurrentProcess.restype = wt.HANDLE
kernel32.GetCurrentThread.restype = wt.HANDLE
kernel32.SetThreadDescription.argtypes = [wt.HANDLE, wt.LPCWSTR]
kernel32.RtlCaptureContext.argtypes = [ctypes.c_void_p]
kernel32.RtlCaptureContext.restype = None
kernel32.CreateToolhelp32Snapshot.restype = wt.HANDLE
kernel32.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
kernel32.Thread32First.argtypes = [wt.HANDLE, ctypes.POINTER(THREADENTRY32)]
kernel32.Thread32Next.argtypes = [wt.HANDLE, ctypes.POINTER(THREADENTRY32)]
kernel32.CloseHandle.argtypes = [wt.HANDLE]
kernel32.GetProcessTimes.argtypes = [wt.HANDLE] + [ctypes.POINTER(wt.FILETIME)] * 4
kernel32.GetSystemInfo.argtypes = [ctypes.POINTER(SYSTEM_INFO)]
psapi.EnumProcessModulesEx.argtypes = [wt.HANDLE, ctypes.POINTER(wt.HMODULE), wt.DWORD, ctypes.POINTER(wt.DWORD), wt.DWORD]
psapi.GetModuleFileNameExW.argtypes = [wt.HANDLE, wt.HMODULE, wt.LPWSTR, wt.DWORD]
psapi.GetModuleInformation.argtypes = [wt.HANDLE, wt.HMODULE, ctypes.POINTER(MODULEINFO), wt.DWORD]
dbghelp.MiniDumpWriteDump.argtypes = [
    wt.HANDLE, wt.DWORD, wt.HANDLE, wt.DWORD, ctypes.POINTER(MINIDUMP_EXCEPTION_INFORMATION), ctypes.c_void_p, ctypes.c_void_p,
]
dbghelp.MiniDumpWriteDump.restype = wt.BOOL
dbghelp.SymSrvGetFileIndexInfoW.argtypes = [wt.LPCWSTR, ctypes.POINTER(SYMSRV_INDEX_INFOW), wt.DWORD]
dbghelp.SymSrvGetFileIndexInfoW.restype = wt.BOOL
ntdll.RtlGetVersion.argtypes = [ctypes.POINTER(RTL_OSVERSIONINFOW)]

process = kernel32.GetCurrentProcess()
pid = os.getpid()


def modules():
    needed = wt.DWORD()
    handles = (wt.HMODULE * 4096)()
    if not psapi.EnumProcessModulesEx(process, handles, ctypes.sizeof(handles), ctypes.byref(needed), 3):
        raise ctypes.WinError(ctypes.get_last_error())
    out = []
    for handle in handles[: needed.value // ctypes.sizeof(wt.HMODULE)]:
        name = ctypes.create_unicode_buffer(32768)
        psapi.GetModuleFileNameExW(process, handle, name, 32768)
        info = MODULEINFO()
        psapi.GetModuleInformation(process, handle, ctypes.byref(info), ctypes.sizeof(info))
        out.append({'path': name.value, 'base': info.lpBaseOfDll, 'size': info.SizeOfImage})
    return out


def threads():
    snapshot = kernel32.CreateToolhelp32Snapshot(0x4, 0)
    entry = THREADENTRY32()
    entry.dwSize = ctypes.sizeof(entry)
    ids = []
    ok = kernel32.Thread32First(snapshot, ctypes.byref(entry))
    while ok:
        if entry.th32OwnerProcessID == pid:
            ids.append(entry.th32ThreadID)
        ok = kernel32.Thread32Next(snapshot, ctypes.byref(entry))
    kernel32.CloseHandle(snapshot)
    return ids


def pdb_identity(path):
    info = SYMSRV_INDEX_INFOW()
    info.sizeofstruct = ctypes.sizeof(info)
    if not dbghelp.SymSrvGetFileIndexInfoW(path, ctypes.byref(info), 0):
        return None
    guid = info.guid
    text = '%08X%04X%04X%s%X' % (guid.Data1, guid.Data2, guid.Data3, ''.join('%02X' % b for b in guid.Data4), info.age)
    return {'pdb': info.pdbfile, 'id': text, 'timestamp': info.timestamp, 'size': info.size}


ready = threading.Barrier(4)
release = threading.Event()
workers = {}


def worker(name):
    kernel32.SetThreadDescription(kernel32.GetCurrentThread(), name)
    workers[name] = threading.get_native_id()
    ready.wait()
    release.wait()


spawned = [threading.Thread(target=worker, args=(f'disrobe-worker-{index}',)) for index in range(3)]
for thread in spawned:
    thread.start()
ready.wait()

python_dll = sys.dllhandle
python_name = ctypes.create_unicode_buffer(32768)
psapi.GetModuleFileNameExW(process, python_dll, python_name, 32768)
fault_ip = python_dll + FAULT_OFFSET

raw = ctypes.create_string_buffer(CONTEXT_SIZE + 16)
context_address = (ctypes.addressof(raw) + 15) & ~15
kernel32.RtlCaptureContext(context_address)
markers = {}
for index, (name, offset) in enumerate(MARKERS.items()):
    value = 0xA5A5_0000_0000_0000 | ((index + 1) << 32) | (0x1000 + index)
    ctypes.c_uint64.from_address(context_address + offset).value = value
    markers[name] = value
ctypes.c_uint64.from_address(context_address + 0xF8).value = fault_ip
captured_rsp = ctypes.c_uint64.from_address(context_address + 0x98).value

record = EXCEPTION_RECORD()
record.ExceptionCode = EXCEPTION_ACCESS_VIOLATION
record.ExceptionFlags = 0
record.ExceptionAddress = fault_ip
record.NumberParameters = 2
record.ExceptionInformation[0] = 1
record.ExceptionInformation[1] = DATA_ADDRESS
pointers = EXCEPTION_POINTERS(ctypes.pointer(record), context_address)
information = MINIDUMP_EXCEPTION_INFORMATION(kernel32.GetCurrentThreadId(), ctypes.pointer(pointers), False)

modules_before = modules()
threads_before = threads()


def write(name, kind, exception):
    with open(os.path.join(out_dir, name), 'wb') as handle:
        ok = dbghelp.MiniDumpWriteDump(process, pid, msvcrt.get_osfhandle(handle.fileno()), kind,
                                       ctypes.byref(exception) if exception else None, None, None)
        if not ok:
            raise ctypes.WinError(ctypes.get_last_error())


write('exception.dmp', MiniDumpNormal | MiniDumpWithFullMemoryInfo | MiniDumpWithThreadInfo, information)
write('plain.dmp', MiniDumpNormal, None)
modules_after = modules()
release.set()
for thread in spawned:
    thread.join()

version = RTL_OSVERSIONINFOW()
version.dwOSVersionInfoSize = ctypes.sizeof(version)
ntdll.RtlGetVersion(ctypes.byref(version))
system = SYSTEM_INFO()
kernel32.GetSystemInfo(ctypes.byref(system))
creation, exit_time, kernel_time, user_time = (wt.FILETIME() for _ in range(4))
kernel32.GetProcessTimes(process, ctypes.byref(creation), ctypes.byref(exit_time), ctypes.byref(kernel_time), ctypes.byref(user_time))
created = ((creation.dwHighDateTime << 32) | creation.dwLowDateTime) // 10_000_000 - 11_644_473_600

ntdll_path = next(module['path'] for module in modules_before if module['path'].lower().endswith('\\ntdll.dll'))
truth = {
    'pid': pid,
    'start_time_unix': created,
    'main_thread': kernel32.GetCurrentThreadId(),
    'workers': workers,
    'threads_before': threads_before,
    'modules_before': modules_before,
    'modules_after': modules_after,
    'python_dll': {'path': python_name.value, 'base': python_dll},
    'fault': {
        'code': EXCEPTION_ACCESS_VIOLATION,
        'address': fault_ip,
        'offset': FAULT_OFFSET,
        'data_address': DATA_ADDRESS,
        'parameters': [1, DATA_ADDRESS],
    },
    'markers': markers,
    'rsp': captured_rsp,
    'os': {'major': version.dwMajorVersion, 'minor': version.dwMinorVersion, 'build': version.dwBuildNumber,
           'processors': system.dwNumberOfProcessors},
    'pdb': {'python': pdb_identity(python_name.value), 'ntdll': pdb_identity(ntdll_path)},
    'ntdll': ntdll_path,
}
with open(os.path.join(out_dir, 'truth.json'), 'w', encoding='utf-8') as handle:
    json.dump(truth, handle, indent=1)
