[Setup]
AppName=Disrobe Inno solid break fixture
AppVersion=1.0
DefaultDirName={autopf}\DisrobeInnoSolidBreakFixture
PrivilegesRequired=lowest
Uninstallable=no
Compression=lzma2
SolidCompression=yes
OutputBaseFilename=solid-break

[Files]
Source: "alpha.txt"; DestDir: "{app}\data"
Source: "beta.txt"; DestDir: "{app}\data"; Flags: solidbreak
