!ifndef COMPRESSOR
  !error "define COMPRESSOR as zlib, bzip2 or lzma"
!endif
!ifndef OUTFILE
  !error "define OUTFILE as the path of the installer to write"
!endif

Unicode true

!ifdef SOLID
  SetCompressor /SOLID /FINAL ${COMPRESSOR}
!else
  SetCompressor /FINAL ${COMPRESSOR}
!endif

Name "Tide Table Viewer Layers"
OutFile "${OUTFILE}"
InstallDir "$LOCALAPPDATA\TideTableViewerLayers"
RequestExecutionLevel user

Section "core"
  SetOutPath "$INSTDIR"
  File "payload\readme.txt"
  SetOutPath "$INSTDIR\docs"
  File "payload\docs\changes.txt"
  File "/oname=readme.txt" "payload\stations.csv"
  SetOutPath "$INSTDIR\archive"
  File "payload\docs\changes.txt"
SectionEnd

Section "variant"
  SetOutPath "$INSTDIR"
  File "/oname=readme.txt" "payload\stations.csv"
  File "payload\readme.txt"
SectionEnd
