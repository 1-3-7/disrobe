#ifndef Codec
  #define Codec "lzma2"
#endif

[Setup]
AppName=Disrobe Inno codec fixture
AppVersion=1.0
DefaultDirName={autopf}\DisrobeInnoCodecFixture
PrivilegesRequired=lowest
Uninstallable=no
Compression={#Codec}
SolidCompression=yes
OutputBaseFilename=codec-{#Codec}

[Files]
Source: "alpha.txt"; DestDir: "{app}\data"
Source: "beta.txt"; DestDir: "{app}\data"
