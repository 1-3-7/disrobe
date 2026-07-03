# sourceprobe VBA source-recovery fixture

A real macro-bearing Word and Excel document authored on this machine to validate
MS-OVBA decompression of the `dir` and per-module streams back to original VBA source.

## Ground truth

`SourceProbe.bas` is the exact, hand-authored module source (LF line endings). Its
identifier casing is internally consistent, so the VBA engine's first-declaration
case canonicalization is a no-op and the stored module text equals this file
byte-for-byte (after CRLF to LF normalization). Recovered source from either
container must equal this file under that single normalization.

## Containers

- `../sourceprobe.docm` Word macro-enabled document (wdFormatXMLDocumentMacroEnabled = 13)
- `../sourceprobe.xlsm` Excel macro-enabled workbook (xlOpenXMLWorkbookMacroEnabled = 52)

Both embed the single standard module `SourceProbe` (OLE stream `VBA/SourceProbe`).

## Office version

Microsoft Office 16.0 (Word and Excel) on Windows 11.

## Build steps

Authored as a single `.bas`, imported into a fresh document/workbook via the COM
object model, saved in the macro-enabled format. The VBA project object model trust
("Trust access to the VBA project object model") must be enabled for the host app;
for Excel that is `HKCU\Software\Microsoft\Office\16.0\Excel\Security\AccessVBOM = 1`.

Word document:

```powershell
$word = New-Object -ComObject Word.Application
$word.Visible = $false
$doc = $word.Documents.Add()
$doc.VBProject.VBComponents.Import("SourceProbe.bas")
$doc.SaveAs2("sourceprobe.docm", 13)
$doc.Close($false); $word.Quit()
```

Excel workbook:

```powershell
$xl = New-Object -ComObject Excel.Application
$xl.Visible = $false; $xl.DisplayAlerts = $false
$wb = $xl.Workbooks.Add()
$wb.VBProject.VBComponents.Import("SourceProbe.bas")
$wb.SaveAs("sourceprobe.xlsm", 52)
$wb.Close($false); $xl.Quit()
```

## sha256

```
e2cb74279a1aa011df7fe38bd09084ed1ff11338eaf2d62795066386398c2089  sourceprobe.docm
c6a2f63df2c67a0790447707666c109232ba9122905009ca805013aedc049080  sourceprobe.xlsm
0630dc5fc7931f323f334dc8d3d4704ca6bd82de93dffd226196a00402c6432b  sourceprobe/SourceProbe.bas
```

## Cross-check

`python -m oletools.olevba sourceprobe.docm` extracts the same `VBA/SourceProbe`
module text.

The macros are benign (arithmetic, string joins, a recursion, a MsgBox). They are
never enabled or executed; recovery is a static parse of the OLE container only.
