!ifndef COMPRESSOR
  !error "define COMPRESSOR as zlib, bzip2 or lzma"
!endif
!ifndef OUTFILE
  !error "define OUTFILE as the path of the installer to write"
!endif

!ifdef UNICODE_STRINGS
  Unicode true
!else
  Unicode false
!endif

!ifdef SOLID
  SetCompressor /SOLID /FINAL ${COMPRESSOR}
!else
  SetCompressor /FINAL ${COMPRESSOR}
!endif

Name "Tide Table Viewer"
OutFile "${OUTFILE}"
InstallDir "$LOCALAPPDATA\TideTableViewer"
RequestExecutionLevel user

Section
  SetOutPath "$INSTDIR"
  File "payload\empty.txt"
  File "payload\readme.txt"
  SetOutPath "$INSTDIR\data"
  File "payload\stations.csv"
  SetOutPath "$INSTDIR\docs"
  File "payload\docs\changes.txt"
SectionEnd
