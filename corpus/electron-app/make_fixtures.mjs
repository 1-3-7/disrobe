import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const here = path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'));
const tools = process.env.ELECTRON_TOOLS;
const llvm = process.env.LLVM_BIN;
if (!tools || !llvm) {
  throw new Error('set ELECTRON_TOOLS to the @electron/asar and @electron/fuses install and LLVM_BIN to the LLVM bin directory');
}
const asar = await import(pathToFileURL(path.join(tools, 'node_modules/@electron/asar/lib/asar.js')).href);
const fuses = await import(pathToFileURL(path.join(tools, 'node_modules/@electron/fuses/dist/index.js')).href);
const { FuseV1Options, FuseVersion } = fuses;

const out = (name) => path.join(here, name);
const archive = out('app.asar');
for (const stale of ['app.asar', 'app.asar.unpacked']) {
  fs.rmSync(out(stale), { recursive: true, force: true });
}
await asar.createPackageWithOptions(path.join(here, 'app'), archive, { unpack: '*.node' });
const raw = asar.getRawHeader(archive);
const headerSha256 = crypto.createHash('sha256').update(raw.headerString).digest('hex');

const build = fs.mkdtempSync(path.join(here, '.build-'));
try {
  fs.writeFileSync(
    path.join(build, 'integrity.json'),
    JSON.stringify([{ file: 'resources\\app.asar', alg: 'SHA256', value: headerSha256 }]),
  );
  fs.writeFileSync(path.join(build, 'integrity.rc'), 'ELECTRONASAR INTEGRITY "integrity.json"\n');
  execFileSync(path.join(llvm, 'llvm-rc'), ['/FO', path.join(build, 'integrity.res'), path.join(build, 'integrity.rc')]);
  execFileSync(path.join(llvm, 'clang'), [
    '--target=x86_64-pc-windows-msvc', '-O1', '-nostdlib', '-fuse-ld=lld',
    '-Wl,/entry:start', '-Wl,/subsystem:console', '-Wl,/Brepro',
    path.join(here, 'src', 'fake_electron.c'), path.join(build, 'integrity.res'),
    '-o', out('fake_electron.exe'),
  ]);
} finally {
  fs.rmSync(build, { recursive: true, force: true });
}

const wire = fs.readFileSync(out('fake_electron.exe'));
const sentinel = Buffer.from('dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX');
const at = wire.indexOf(sentinel);
const wireBytes = wire.subarray(at, at + sentinel.length + 2 + 9);
const slice = (cpu) => {
  const body = Buffer.alloc(0x1000);
  body.writeUInt32LE(0xfeedfacf, 0);
  body.writeUInt32LE(cpu, 4);
  wireBytes.copy(body, 0x200);
  return body;
};
const fat = Buffer.alloc(0x1000);
fat.writeUInt32BE(0xcafebabe, 0);
fat.writeUInt32BE(2, 4);
const slices = [[0x01000007, 3], [0x0100000c, 0]];
slices.forEach(([cpu, sub], index) => {
  const entry = 8 + index * 20;
  fat.writeUInt32BE(cpu, entry);
  fat.writeUInt32BE(sub, entry + 4);
  fat.writeUInt32BE(0x1000 * (index + 1), entry + 8);
  fat.writeUInt32BE(0x1000, entry + 12);
  fat.writeUInt32BE(12, entry + 16);
});
fs.writeFileSync(out('universal.bin'), Buffer.concat([fat, slice(0x01000007), slice(0x0100000c)]));

const variants = {
  'fuses_hardened.exe': {
    [FuseV1Options.RunAsNode]: false,
    [FuseV1Options.EnableCookieEncryption]: true,
    [FuseV1Options.EnableNodeOptionsEnvironmentVariable]: false,
    [FuseV1Options.EnableNodeCliInspectArguments]: false,
    [FuseV1Options.EnableEmbeddedAsarIntegrityValidation]: true,
    [FuseV1Options.OnlyLoadAppFromAsar]: true,
  },
  'fuses_mixed.exe': {
    [FuseV1Options.LoadBrowserProcessSpecificV8Snapshot]: true,
    [FuseV1Options.GrantFileProtocolExtraPrivileges]: false,
    [FuseV1Options.WasmTrapHandlers]: false,
  },
};
for (const [name, config] of Object.entries(variants)) {
  fs.copyFileSync(out('fake_electron.exe'), out(name));
  await fuses.flipFuses(out(name), { version: FuseVersion.V1, ...config });
}
await fuses.flipFuses(out('universal.bin'), { version: FuseVersion.V1, ...variants['fuses_hardened.exe'] });

const reference = { fuses: {}, archive: {} };
for (const name of ['fake_electron.exe', 'fuses_hardened.exe', 'fuses_mixed.exe', 'universal.bin']) {
  reference.fuses[name] = await fuses.getCurrentFuseWire(out(name));
}
const files = {};
for (const entry of asar.listPackage(archive, { isPack: false })) {
  const name = entry.replace(/^[\\/]/, '').split(path.sep).join('/');
  const stat = asar.statFile(archive, entry.replace(/^[\\/]/, ''), false);
  if ('files' in stat) {
    continue;
  }
  files[name] = { size: stat.size, unpacked: Boolean(stat.unpacked), integrity: stat.integrity ?? null };
}
reference.archive = { header_sha256: headerSha256, header_size: raw.headerSize, files };
fs.writeFileSync(out('reference.json'), JSON.stringify(reference, null, 1) + '\n');
