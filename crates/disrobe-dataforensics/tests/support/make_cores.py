import json
import os
import struct
import sys

PAGE = 0x1000
PT_LOAD, PT_NOTE = 1, 4
PF_X, PF_W, PF_R = 1, 2, 4
EM_386, EM_PPC64, EM_X86_64, EM_AARCH64, EM_RISCV = 3, 21, 62, 183, 243
NT_PRSTATUS, NT_PRFPREG, NT_PRPSINFO, NT_AUXV = 1, 2, 3, 6
NT_SIGINFO, NT_FILE, NT_X86_XSTATE = 0x53494749, 0x46494C45, 0x202

REGISTERS = {
    EM_X86_64: ['r15', 'r14', 'r13', 'r12', 'rbp', 'rbx', 'r11', 'r10', 'r9', 'r8', 'rax', 'rcx', 'rdx', 'rsi', 'rdi',
                'orig_rax', 'rip', 'cs', 'eflags', 'rsp', 'ss', 'fs_base', 'gs_base', 'ds', 'es', 'fs', 'gs'],
    EM_386: ['ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'eax', 'ds', 'es', 'fs', 'gs', 'orig_eax', 'eip', 'cs', 'eflags',
             'esp', 'ss'],
    EM_AARCH64: [f'x{i}' for i in range(31)] + ['sp', 'pc', 'pstate'],
    EM_RISCV: ['pc', 'ra', 'sp', 'gp', 'tp', 't0', 't1', 't2', 's0', 's1'] + [f'a{i}' for i in range(8)]
              + [f's{i}' for i in range(2, 12)] + ['t3', 't4', 't5', 't6'],
    EM_PPC64: [f'gpr{i}' for i in range(48)],
}
POINTERS = {EM_X86_64: ('rip', 'rsp', 'rbp'), EM_386: ('eip', 'esp', 'ebp'), EM_AARCH64: ('pc', 'sp', 'x29'),
            EM_RISCV: ('pc', 'sp', 's0')}
SIGNALS = {'SIGSEGV': 11, 'SIGBUS': 7, 'SIGFPE': 8, 'SIGABRT': 6}


def pad4(data):
    return data + b'\0' * (-len(data) % 4)


class Core:
    def __init__(self, machine, bits, big):
        self.machine, self.bits, self.big = machine, bits, big
        self.e = '>' if big else '<'
        self.w = 'Q' if bits == 64 else 'I'
        self.wb = bits // 8
        self.mappings = []
        self.threads = []
        self.placed = {}

    def pack(self, fmt, *values):
        return struct.pack(self.e + fmt, *values)

    def words(self, *values):
        return self.pack(self.w * len(values), *values)

    def map(self, start, size, flags, path=None, page=0, captured=False):
        mapping = {'start': start, 'end': start + size, 'flags': flags, 'path': path, 'page': page,
                   'data': bytearray(size) if captured else None}
        self.mappings.append(mapping)
        return mapping

    def poke(self, address, data):
        for mapping in self.mappings:
            if mapping['start'] <= address and address + len(data) <= mapping['end']:
                offset = address - mapping['start']
                mapping['data'][offset:offset + len(data)] = data
                return
        raise ValueError(hex(address))

    def poke_word(self, address, value):
        self.poke(address, self.words(value))

    def image(self, build_id):
        note = self.pack('III', 4, len(build_id), 3) + b'GNU\0' + build_id
        if self.bits == 64:
            header = b'\x7fELF' + bytes([2, 2 if self.big else 1, 1]) + b'\0' * 9
            header += self.pack('HHIQQQIHHHHHH', 3, self.machine, 1, 0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
            phdrs = self.pack('IIQQQQQQ', PT_LOAD, PF_R, 0, 0, 0, PAGE, PAGE, PAGE)
            phdrs += self.pack('IIQQQQQQ', PT_NOTE, PF_R, 0x100, 0x100, 0x100, len(note), len(note), 4)
        else:
            header = b'\x7fELF' + bytes([1, 2 if self.big else 1, 1]) + b'\0' * 9
            header += self.pack('HHIIIIIHHHHHH', 3, self.machine, 1, 0, 52, 0, 0, 52, 32, 2, 0, 0, 0)
            phdrs = self.pack('IIIIIIII', PT_LOAD, 0, 0, 0, PAGE, PAGE, PF_R, PAGE)
            phdrs += self.pack('IIIIIIII', PT_NOTE, 0x100, 0x100, 0x100, len(note), len(note), PF_R, 4)
        page = bytearray(PAGE)
        page[:len(header) + len(phdrs)] = header + phdrs
        page[0x100:0x100 + len(note)] = note
        return bytes(page)

    def prstatus(self, thread, signal):
        names = REGISTERS[self.machine]
        values = [thread['registers'].get(name, 0) for name in names]
        if self.bits == 64:
            head = self.pack('iiih', signal, 0, 0, signal) + b'\0' * 2 + self.pack('QQ', 0, 0)
            head += self.pack('iiii', thread['tid'], thread['ppid'], thread['tid'], thread['ppid'])
            head += b'\0' * 64
        else:
            head = self.pack('iiih', signal, 0, 0, signal) + b'\0' * 2 + self.pack('II', 0, 0)
            head += self.pack('iiii', thread['tid'], thread['ppid'], thread['tid'], thread['ppid'])
            head += b'\0' * 32
        body = head + self.words(*values) + self.pack('i', 1)
        return body + b'\0' * (-len(body) % self.wb)

    def prpsinfo(self, info):
        fname = info['name'].encode().ljust(16, b'\0')
        args = info['args'].encode().ljust(80, b'\0')
        if self.bits == 64:
            return (self.pack('bbbbI', 0, ord('R'), 0, 0, 0) + self.pack('Q', 0)
                    + self.pack('IIiiii', info['uid'], info['gid'], info['pid'], info['ppid'], info['pid'], info['pid'])
                    + fname + args)
        return (self.pack('bbbbI', 0, ord('R'), 0, 0, 0)
                + self.pack('HHiiii', info['uid'], info['gid'], info['pid'], info['ppid'], info['pid'], info['pid'])
                + fname + args)

    def siginfo(self, signo, code, word=None, sender=None):
        head = self.pack('iii', signo, 0, code)
        if self.bits == 64:
            head += b'\0' * 4
        if sender is not None:
            body = self.pack('iI', *sender)
        else:
            body = self.words(word)
        return (head + body).ljust(128, b'\0')

    def nt_file(self):
        files = [m for m in self.mappings if m['path']]
        table = self.words(len(files), PAGE)
        for m in files:
            table += self.words(m['start'], m['end'], m['page'])
        return table + b''.join(m['path'].encode() + b'\0' for m in files)

    def build(self, notes, pn_xnum=False):
        note_bytes = b''
        for owner, kind, desc in notes:
            name = owner.encode() + b'\0'
            note_bytes += self.pack('III', len(name), len(desc), kind) + pad4(name) + pad4(desc)
        loads = sorted(self.mappings, key=lambda m: m['start'])
        count = 1 + len(loads)
        ehsize, phsize = (64, 56) if self.bits == 64 else (52, 32)
        shsize = 64 if self.bits == 64 else 40
        phoff = ehsize
        notes_at = phoff + count * phsize
        cursor = notes_at + len(note_bytes)
        shoff = 0
        if pn_xnum:
            shoff = cursor
            cursor += shsize
        cursor += -cursor % PAGE
        layout = []
        for m in loads:
            size = len(m['data']) if m['data'] is not None else 0
            layout.append((m, cursor, size))
            cursor += size
        ident = b'\x7fELF' + bytes([2 if self.bits == 64 else 1, 2 if self.big else 1, 1]) + b'\0' * 9
        phnum = 0xFFFF if pn_xnum else count
        shnum = 1 if pn_xnum else 0
        if self.bits == 64:
            header = ident + self.pack('HHIQQQIHHHHHH', 4, self.machine, 1, 0, phoff, shoff, 0, ehsize, phsize, phnum,
                                       shsize if pn_xnum else 0, shnum, 0)
            phdrs = self.pack('IIQQQQQQ', PT_NOTE, 0, notes_at, 0, 0, len(note_bytes), 0, 4)
            for m, offset, size in layout:
                phdrs += self.pack('IIQQQQQQ', PT_LOAD, m['flags'], offset, m['start'], 0, size, m['end'] - m['start'],
                                   PAGE)
            section = self.pack('IIQQQQIIQQ', 0, 0, 0, 0, 0, 0, 0, count, 0, 0) if pn_xnum else b''
        else:
            header = ident + self.pack('HHIIIIIHHHHHH', 4, self.machine, 1, 0, phoff, shoff, 0, ehsize, phsize, phnum,
                                       shsize if pn_xnum else 0, shnum, 0)
            phdrs = self.pack('IIIIIIII', PT_NOTE, notes_at, 0, 0, len(note_bytes), 0, 0, 4)
            for m, offset, size in layout:
                phdrs += self.pack('IIIIIIII', PT_LOAD, offset, m['start'], 0, size, m['end'] - m['start'], m['flags'],
                                   PAGE)
            section = self.pack('IIIIIIIIII', 0, 0, 0, 0, 0, 0, 0, count, 0, 0) if pn_xnum else b''
        out = bytearray(header + phdrs + note_bytes + section)
        out += b'\0' * (layout[0][1] - len(out) if layout else 0)
        for m, offset, size in layout:
            assert len(out) == offset
            if m['data'] is not None:
                out += m['data']
        return bytes(out)


def scenario(name, machine, bits, big, signal_name, code, reason, fault_word=None, tkill=False, pn_xnum=False):
    core = Core(machine, bits, big)
    narrow = bits == 32
    exe_base = 0x56555000 if narrow else 0x555555554000
    lib_base = 0xF7D80000 if narrow else 0x7FFFF7D80000
    stack_top = 0xFFFDF000 if narrow else 0x7FFFFFFFF000
    exe = '/usr/bin/crashme'
    lib = '/usr/lib/libc.so.6'
    exe_id = bytes(range(0x10, 0x24)) if not big else bytes(range(0x40, 0x54))
    lib_id = bytes(range(0xA0, 0xB4))
    head = core.map(exe_base, PAGE, PF_R, exe, 0, captured=True)
    head['data'][:] = core.image(exe_id)
    core.map(exe_base + PAGE, 2 * PAGE, PF_R | PF_X, exe, 1)
    core.map(exe_base + 3 * PAGE, PAGE, PF_R, exe, 3)
    core.map(exe_base + 4 * PAGE, PAGE, PF_R | PF_W, exe, 4, captured=True)
    heap = core.map(exe_base + 5 * PAGE, 8 * PAGE, PF_R | PF_W, captured=True)
    libhead = core.map(lib_base, PAGE, PF_R, lib, 0, captured=True)
    libhead['data'][:] = core.image(lib_id)
    core.map(lib_base + 0x28000, 0x195000, PF_R | PF_X, lib, 0x28)
    core.map(lib_base + 0x1BD000, 0x4000, PF_R | PF_W, lib, 0x1BD, captured=True)
    vdso = core.map(lib_base + 0x241000, 2 * PAGE, PF_R | PF_X, captured=True)
    core.map(stack_top - 0x21000, 0x21000, PF_R | PF_W, captured=True)
    thread_stacks = [core.map(lib_base - (i + 1) * 0x20000, 0x10000, PF_R | PF_W, captured=True) for i in range(2)]

    pid, ppid, uid, gid = 4242, 4100, 1000, 1000
    sp = stack_top - 0xC60
    entry = exe_base + PAGE + 0x40
    platform_at, execfn_at, random_at = stack_top - 0x647, stack_top - 0x30, stack_top - 0x660
    platform = {EM_X86_64: 'x86_64', EM_386: 'i686', EM_AARCH64: 'aarch64', EM_RISCV: 'riscv64', EM_PPC64: 'ppc64'}[machine]
    core.poke(platform_at, platform.encode() + b'\0')
    core.poke(execfn_at, exe.encode() + b'\0')
    core.poke(random_at, bytes(range(1, 17)))

    def text(base, offset):
        return base + offset

    placed = {0: [(sp + 3 * core.wb, text(exe_base, 0x1189), exe, 0x1189), (sp + 9 * core.wb, text(lib_base, 0x29D90), lib, 0x29D90)]}
    core.poke_word(sp + 4 * core.wb, exe_base + 3 * PAGE + 0x10)
    core.poke_word(sp + 5 * core.wb, vdso['start'] + 0x500)
    core.poke_word(sp + 6 * core.wb, heap['start'] + 0x40)
    tids = [pid, pid + 1, pid + 2] if machine in (EM_X86_64, EM_AARCH64) else [pid]
    threads = []
    for index, tid in enumerate(tids):
        registers = {}
        names = REGISTERS[machine]
        for position, register in enumerate(names):
            registers[register] = (0x1111_0000 + 0x100 * index + position) if narrow else (0x1111_2222_0000_0000 + (index << 16) + position)
        if machine in POINTERS:
            ip_name, sp_name, fp_name = POINTERS[machine]
            if index == 0:
                ip, thread_sp = text(exe_base, 0x1149), sp
            else:
                thread_stack = thread_stacks[index - 1]
                ip, thread_sp = text(lib_base, 0x11B0C2), thread_stack['start'] + 0x8000
                address = thread_sp + 2 * core.wb
                placed[index] = [(address, text(lib_base, 0x94AC3), lib, 0x94AC3)]
            registers[ip_name] = ip
            registers[sp_name] = thread_sp
            registers[fp_name] = thread_sp + 0x30
        threads.append({'tid': tid, 'ppid': ppid, 'registers': registers})
    for index, words in placed.items():
        for address, value, _, _ in words:
            core.poke_word(address, value)

    signo = SIGNALS[signal_name]
    if tkill:
        siginfo = core.siginfo(signo, -6, sender=(pid, uid))
    else:
        siginfo = core.siginfo(signo, code, word=fault_word)
    auxv = [(3, exe_base + 0x40), (4, 56 if bits == 64 else 32), (5, 13), (6, PAGE), (7, lib_base + 0x300000), (8, 0),
            (9, entry), (11, uid), (12, uid), (13, gid), (14, gid), (15, platform_at), (16, 0x178BFBFF), (17, 100),
            (23, 0), (25, random_at), (26, 2), (31, execfn_at), (0, 0)]
    auxv_bytes = core.words(*[value for pair in auxv for value in pair])
    psinfo = {'name': 'crashme', 'args': '/usr/bin/crashme --fast input.bin ', 'uid': uid, 'gid': gid, 'pid': pid, 'ppid': ppid}
    notes = [('CORE', NT_PRSTATUS, core.prstatus(threads[0], signo)),
             ('CORE', NT_PRPSINFO, core.prpsinfo(psinfo)),
             ('CORE', NT_SIGINFO, siginfo),
             ('CORE', NT_AUXV, auxv_bytes),
             ('CORE', NT_FILE, core.nt_file()),
             ('CORE', NT_PRFPREG, bytes(512))]
    if machine == EM_X86_64:
        notes.append(('LINUX', NT_X86_XSTATE, bytes(832)))
    for thread in threads[1:]:
        notes.append(('CORE', NT_PRSTATUS, core.prstatus(thread, signo)))
        notes.append(('CORE', NT_PRFPREG, bytes(512)))
        if machine == EM_X86_64:
            notes.append(('LINUX', NT_X86_XSTATE, bytes(832)))
    data = core.build(notes, pn_xnum=pn_xnum)

    files = [m for m in core.mappings if m['path']]
    modules = []
    for path in dict.fromkeys(m['path'] for m in files):
        own = [m for m in files if m['path'] == path]
        start, end = min(m['start'] for m in own), max(m['end'] for m in own)
        modules.append({'path': path, 'base': start, 'size': end - start,
                        'build_id': (exe_id if path == exe else lib_id).hex()})
    counts = {}
    for _, kind, _ in notes:
        label = {NT_PRSTATUS: 'NT_PRSTATUS', NT_PRFPREG: 'NT_PRFPREG', NT_PRPSINFO: 'NT_PRPSINFO', NT_AUXV: 'NT_AUXV',
                 NT_SIGINFO: 'NT_SIGINFO', NT_FILE: 'NT_FILE', NT_X86_XSTATE: 'NT_X86_XSTATE'}[kind]
        counts[label] = counts.get(label, 0) + 1

    def locate(address):
        for m in files:
            if m['start'] <= address < m['end']:
                base = next(mod['base'] for mod in modules if mod['path'] == m['path'])
                return {'module': m['path'], 'offset': address - base}
        return None

    decoded = machine in POINTERS
    thread_truth = []
    for index, thread in enumerate(threads):
        entry_truth = {'id': thread['tid'], 'crashed': index == 0}
        if decoded:
            ip_name, sp_name, fp_name = POINTERS[machine]
            entry_truth.update({
                'ip': thread['registers'][ip_name], 'sp': thread['registers'][sp_name],
                'fp': thread['registers'][fp_name], 'location': locate(thread['registers'][ip_name]),
                'registers': [[register, thread['registers'][register]] for register in REGISTERS[machine]],
                'scan': [{'address': a, 'value': v, 'module': m, 'offset': o} for a, v, m, o in placed.get(index, [])],
            })
        thread_truth.append(entry_truth)
    fault = {'signal': signo, 'name': signal_name, 'thread': pid}
    if tkill:
        fault.update({'reason': 'SI_TKILL', 'sender': {'pid': pid, 'uid': uid}})
    else:
        fault['reason'] = reason
        if signal_name in ('SIGSEGV', 'SIGBUS'):
            fault['data_address'] = fault_word
            fault['data_location'] = locate(fault_word)
        else:
            fault['instruction_address'] = fault_word
    if decoded and 'instruction_address' not in fault:
        fault['instruction_address'] = threads[0]['registers'][POINTERS[machine][0]]
    if 'instruction_address' in fault:
        fault['instruction_location'] = locate(fault['instruction_address'])
    truth = {
        'name': name, 'machine': machine, 'bits': bits, 'big_endian': big, 'decoded': decoded,
        'process': {'pid': pid, 'ppid': ppid, 'uid': uid, 'gid': gid, 'name': 'crashme',
                    'command_line': psinfo['args'].strip(), 'executable': exe},
        'threads': thread_truth, 'fault': fault, 'modules': modules, 'notes': counts,
        'auxv': [[key, value] for key, value in auxv if key != 0],
        'strings': {'15': platform, '31': exe},
        'mappings': [[m['start'], m['end'], m['page'], m['path']] for m in files],
        'loads': len(core.mappings),
        'executable': sum(1 for m in core.mappings if m['flags'] & PF_X),
        'captured': sum(len(m['data']) for m in core.mappings if m['data'] is not None),
    }
    return data, truth


def main():
    out = sys.argv[1]
    cases = [
        scenario('x86_64', EM_X86_64, 64, False, 'SIGSEGV', 1, 'SEGV_MAPERR', fault_word=0x10),
        scenario('x86_64_pnxnum', EM_X86_64, 64, False, 'SIGSEGV', 2, 'SEGV_ACCERR', fault_word=0x555555557010, pn_xnum=True),
        scenario('aarch64', EM_AARCH64, 64, False, 'SIGBUS', 1, 'BUS_ADRALN', fault_word=0x555555559001),
        scenario('i386', EM_386, 32, False, 'SIGFPE', 1, 'FPE_INTDIV', fault_word=0x56556149),
        scenario('riscv64', EM_RISCV, 64, False, 'SIGABRT', 0, None, tkill=True),
        scenario('ppc64', EM_PPC64, 64, True, 'SIGSEGV', 2, 'SEGV_ACCERR', fault_word=0x7FFFF7FC0000),
    ]
    truths = {}
    for data, truth in cases:
        with open(os.path.join(out, truth['name'] + '.core'), 'wb') as handle:
            handle.write(data)
        truths[truth['name']] = truth
    with open(os.path.join(out, 'truth.json'), 'w', encoding='utf-8') as handle:
        json.dump(truths, handle, indent=1)


main()
