Attribute VB_Name = "EdgeCases"
Option Explicit
Option Base 1
Option Compare Text

Public Const APP_NAME As String = "EdgeCases"
Public Const APP_VERSION As String = "1.0.0"
Public Const PI_LITERAL As Double = 3.14159265358979

Public g_LogLevel As Long
Public g_RunCounter As Long

' region Enums
Public Enum LogLevel
    LogLevelDebug = 0
    LogLevelInfo = 1
    LogLevelWarn = 2
    LogLevelError = 3
    LogLevelFatal = 4
End Enum

Public Enum FileKind
    FileKindUnknown = 0
    FileKindText = 1
    FileKindBinary = 2
    FileKindArchive = 3
    FileKindImage = 4
End Enum

Public Enum HelloMood
    MoodCalm = 0
    MoodExcited = 1
    MoodSuspicious = 2
End Enum
' endregion

' region User-defined types
Public Type Point2D
    X As Double
    Y As Double
End Type

Public Type Rect
    TopLeft As Point2D
    BottomRight As Point2D
End Type

Public Type FileEntry
    Path As String
    SizeBytes As Currency
    Kind As FileKind
    Modified As Date
End Type

Public Type Outcome
    Ok As Boolean
    ErrorCode As Long
    Message As String
End Type
' endregion

' region Module-level arrays / collections
Public g_FileEntries() As FileEntry
Public g_KnownVerbs As Variant
Public g_TagBag As Object  ' Scripting.Dictionary, lazy-init

Public Sub InitGlobals()
    ReDim g_FileEntries(1 To 4)
    g_FileEntries(1).Path = "C:\one.txt"
    g_FileEntries(1).SizeBytes = 1024@
    g_FileEntries(1).Kind = FileKindText
    g_FileEntries(2).Path = "C:\two.bin"
    g_FileEntries(2).SizeBytes = 4096@
    g_FileEntries(2).Kind = FileKindBinary
    g_FileEntries(3).Path = "C:\arch.zip"
    g_FileEntries(3).SizeBytes = 16384@
    g_FileEntries(3).Kind = FileKindArchive
    g_FileEntries(4).Path = "C:\img.png"
    g_FileEntries(4).SizeBytes = 8192@
    g_FileEntries(4).Kind = FileKindImage

    g_KnownVerbs = Array("get", "set", "remove", "list", "find")

    Set g_TagBag = CreateObject("Scripting.Dictionary")
    g_TagBag.CompareMode = vbTextCompare
    g_TagBag.Add "alpha", 1
    g_TagBag.Add "beta", 2
    g_TagBag.Add "gamma", 3
End Sub
' endregion

' region Entry point
Public Sub Main()
    On Error GoTo ErrHandler

    InitGlobals
    g_RunCounter = g_RunCounter + 1

    Dim greeter As GreetingTemplate
    Set greeter = New GreetingTemplate
    greeter.Prefix = "hello"
    greeter.Suffix = "world"
    greeter.Mood = MoodExcited

    Dim rendered As String
    rendered = greeter.Render

    MsgBox rendered, vbInformation, APP_NAME

    LogMessage LogLevelInfo, "rendered: " & rendered

    Dim summary As Outcome
    summary = ProcessAllFiles(g_FileEntries)
    If summary.Ok Then
        LogMessage LogLevelInfo, "processed " & summary.Message
    Else
        LogMessage LogLevelError, "failed code=" & summary.ErrorCode & " " & summary.Message
    End If

    Exit Sub

ErrHandler:
    LogMessage LogLevelError, "Main error " & Err.Number & ": " & Err.Description
End Sub
' endregion

' region Error handling
Public Function SafeDivide(ByVal a As Double, ByVal b As Double, ByRef outResult As Double) As Boolean
    On Error GoTo ErrHandler
    If b = 0 Then
        Err.Raise vbObjectError + 100, "EdgeCases.SafeDivide", "divide by zero"
    End If
    outResult = a / b
    SafeDivide = True
    Exit Function

ErrHandler:
    LogMessage LogLevelWarn, "SafeDivide error: " & Err.Description
    outResult = 0#
    SafeDivide = False
End Function

Public Sub DemoOnErrorResumeNext()
    On Error Resume Next
    Dim s As String
    s = Mid$("short", 100, 5)
    If Err.Number <> 0 Then
        LogMessage LogLevelDebug, "Resume-Next absorbed: " & Err.Description
        Err.Clear
    End If
End Sub

Public Sub DemoOnErrorGoto0()
    On Error Resume Next
    On Error GoTo 0
    Dim x As Double
    x = 1 / 0
End Sub
' endregion

' region Pure helpers
Public Function StrJoin(ByVal sep As String, ParamArray parts() As Variant) As String
    Dim i As Long
    Dim out As String
    For i = LBound(parts) To UBound(parts)
        If i = LBound(parts) Then
            out = CStr(parts(i))
        Else
            out = out & sep & CStr(parts(i))
        End If
    Next i
    StrJoin = out
End Function

Public Function StrReverse2(ByVal s As String) As String
    Dim i As Long
    Dim out As String
    For i = Len(s) To 1 Step -1
        out = out & Mid$(s, i, 1)
    Next i
    StrReverse2 = out
End Function

Public Function PadLeft(ByVal s As String, ByVal width As Long, ByVal padChar As String) As String
    Dim n As Long
    n = width - Len(s)
    If n <= 0 Then
        PadLeft = s
    Else
        PadLeft = String$(n, Left$(padChar, 1)) & s
    End If
End Function

Public Function PadRight(ByVal s As String, ByVal width As Long, ByVal padChar As String) As String
    Dim n As Long
    n = width - Len(s)
    If n <= 0 Then
        PadRight = s
    Else
        PadRight = s & String$(n, Left$(padChar, 1))
    End If
End Function

Public Function ToTitleCase(ByVal s As String) As String
    Dim words() As String
    words = Split(LCase$(s), " ")
    Dim i As Long
    For i = LBound(words) To UBound(words)
        If Len(words(i)) > 0 Then
            words(i) = UCase$(Left$(words(i), 1)) & Mid$(words(i), 2)
        End If
    Next i
    ToTitleCase = Join(words, " ")
End Function
' endregion

' region File entry processing
Public Function ProcessAllFiles(ByRef entries() As FileEntry) As Outcome
    Dim total As Long
    Dim sumSize As Currency
    Dim i As Long

    On Error GoTo ErrHandler

    For i = LBound(entries) To UBound(entries)
        sumSize = sumSize + entries(i).SizeBytes
        Select Case entries(i).Kind
            Case FileKindText
                LogMessage LogLevelDebug, "text: " & entries(i).Path
            Case FileKindBinary
                LogMessage LogLevelDebug, "binary: " & entries(i).Path
            Case FileKindArchive
                LogMessage LogLevelDebug, "archive: " & entries(i).Path
            Case FileKindImage
                LogMessage LogLevelDebug, "image: " & entries(i).Path
            Case Else
                LogMessage LogLevelWarn, "unknown: " & entries(i).Path
        End Select
        total = total + 1
    Next i

    ProcessAllFiles.Ok = True
    ProcessAllFiles.ErrorCode = 0
    ProcessAllFiles.Message = total & " files, " & sumSize & " bytes"
    Exit Function

ErrHandler:
    ProcessAllFiles.Ok = False
    ProcessAllFiles.ErrorCode = Err.Number
    ProcessAllFiles.Message = Err.Description
End Function
' endregion

' region Logging
Public Sub LogMessage(ByVal level As LogLevel, ByVal msg As String)
    If level < g_LogLevel Then Exit Sub
    Dim prefix As String
    Select Case level
        Case LogLevelDebug:  prefix = "DBG"
        Case LogLevelInfo:   prefix = "INF"
        Case LogLevelWarn:   prefix = "WRN"
        Case LogLevelError:  prefix = "ERR"
        Case LogLevelFatal:  prefix = "FAT"
        Case Else:           prefix = "???"
    End Select
    Debug.Print Format$(Now, "yyyy-mm-dd hh:nn:ss"); " "; prefix; " "; msg
End Sub
' endregion

' region Loops / While / Do / Until
Public Function SumDoUntil(ByVal limit As Long) As Long
    Dim i As Long
    Dim total As Long
    i = 1
    Do Until i > limit
        total = total + i
        i = i + 1
    Loop
    SumDoUntil = total
End Function

Public Function ProductDoWhile(ByVal n As Long) As Currency
    Dim p As Currency
    p = 1@
    Dim i As Long
    i = 1
    Do While i <= n
        p = p * i
        i = i + 1
    Loop
    ProductDoWhile = p
End Function

Public Sub WhileWend(ByVal n As Long)
    Dim i As Long
    i = 0
    While i < n
        i = i + 1
    Wend
End Sub

Public Sub ForEachVariant(ByRef arr As Variant)
    Dim v As Variant
    For Each v In arr
        Debug.Print v
    Next v
End Sub
' endregion

' region Property procedures used at module level
Public g_Theme As String

Public Property Get Theme() As String
    Theme = g_Theme
End Property

Public Property Let Theme(ByVal value As String)
    g_Theme = value
End Property

Public g_Owner As Object

Public Property Set Owner(ByVal value As Object)
    Set g_Owner = value
End Property

Public Property Get Owner() As Object
    Set Owner = g_Owner
End Property
' endregion

' region Number / string parsing
Public Function ParseIntSafe(ByVal s As String, ByRef outValue As Long) As Boolean
    On Error GoTo ErrHandler
    outValue = CLng(Trim$(s))
    ParseIntSafe = True
    Exit Function
ErrHandler:
    outValue = 0
    ParseIntSafe = False
End Function

Public Function ParseHex(ByVal s As String) As Long
    Dim trimmed As String
    trimmed = Trim$(s)
    If LCase$(Left$(trimmed, 2)) = "0x" Then
        trimmed = Mid$(trimmed, 3)
    ElseIf Left$(trimmed, 1) = "&" Then
        trimmed = Mid$(trimmed, 3)
    End If
    ParseHex = CLng("&H" & trimmed)
End Function
' endregion

' region Geometry helpers (uses Point2D / Rect)
Public Function MakePoint(ByVal x As Double, ByVal y As Double) As Point2D
    MakePoint.X = x
    MakePoint.Y = y
End Function

Public Function MakeRect(ByVal x1 As Double, ByVal y1 As Double, ByVal x2 As Double, ByVal y2 As Double) As Rect
    MakeRect.TopLeft = MakePoint(x1, y1)
    MakeRect.BottomRight = MakePoint(x2, y2)
End Function

Public Function RectArea(ByRef r As Rect) As Double
    RectArea = Abs(r.BottomRight.X - r.TopLeft.X) * Abs(r.BottomRight.Y - r.TopLeft.Y)
End Function

Public Function PointInRect(ByRef p As Point2D, ByRef r As Rect) As Boolean
    PointInRect = p.X >= r.TopLeft.X And p.X <= r.BottomRight.X _
              And p.Y >= r.TopLeft.Y And p.Y <= r.BottomRight.Y
End Function
' endregion

' region COM late-binding examples
Public Sub WriteTempFile()
    Dim fso As Object
    Set fso = CreateObject("Scripting.FileSystemObject")
    Dim p As String
    p = fso.GetSpecialFolder(2) & "\edge_cases_demo.txt"
    Dim ts As Object
    Set ts = fso.CreateTextFile(p, True, False)
    ts.WriteLine "hello vba"
    ts.WriteLine "second line"
    ts.Close
    fso.DeleteFile p
End Sub

Public Sub UseRegex()
    Dim re As Object
    Set re = CreateObject("VBScript.RegExp")
    re.Pattern = "[a-z]+"
    re.Global = True
    re.IgnoreCase = True
    Dim matches As Object
    Set matches = re.Execute("Hello World 2026")
    Dim m As Variant
    For Each m In matches
        Debug.Print m.Value
    Next m
End Sub

Public Sub ShellRun()
    Dim sh As Object
    Set sh = CreateObject("WScript.Shell")
    Dim rc As Long
    rc = sh.Run("cmd.exe /c echo hello", 0, True)
    Debug.Print "rc="; rc
End Sub
' endregion

' region Dynamic collection ops
Public Function BuildDict(ByVal pairs As Variant) As Object
    Dim d As Object
    Set d = CreateObject("Scripting.Dictionary")
    d.CompareMode = vbTextCompare
    Dim i As Long
    For i = LBound(pairs) To UBound(pairs) Step 2
        d.Add CStr(pairs(i)), pairs(i + 1)
    Next i
    Set BuildDict = d
End Function

Public Function CollectionToString(ByVal c As Collection) As String
    Dim out As String
    Dim i As Long
    For i = 1 To c.Count
        If i > 1 Then out = out & ", "
        out = out & CStr(c.Item(i))
    Next i
    CollectionToString = out
End Function
' endregion

' region Constants and bit-twiddling
Public Function BitSet(ByVal value As Long, ByVal mask As Long) As Long
    BitSet = value Or mask
End Function

Public Function BitClear(ByVal value As Long, ByVal mask As Long) As Long
    BitClear = value And (Not mask)
End Function

Public Function BitToggle(ByVal value As Long, ByVal mask As Long) As Long
    BitToggle = value Xor mask
End Function

Public Function BitIsSet(ByVal value As Long, ByVal mask As Long) As Boolean
    BitIsSet = (value And mask) = mask
End Function
' endregion

' region Variant juggling
Public Function CoerceOrDefault(ByVal v As Variant, ByVal default_ As Variant) As Variant
    If IsEmpty(v) Or IsNull(v) Then
        CoerceOrDefault = default_
    ElseIf VarType(v) = vbString Then
        If Len(Trim$(CStr(v))) = 0 Then
            CoerceOrDefault = default_
        Else
            CoerceOrDefault = v
        End If
    Else
        CoerceOrDefault = v
    End If
End Function

Public Function DescribeVariant(ByVal v As Variant) As String
    DescribeVariant = "VarType=" & VarType(v) & " IsArray=" & IsArray(v) & " IsObject=" & IsObject(v)
End Function
' endregion

' region Workbook-like surface (declared, conditional invoke)
Public Sub LikelyOnDocumentOpen()
    LogMessage LogLevelInfo, "AutoOpen-equivalent fired"
    Main
End Sub

Public Sub Auto_Open()
    LikelyOnDocumentOpen
End Sub

Public Sub AutoExec()
    LikelyOnDocumentOpen
End Sub

Public Sub Document_Open()
    LikelyOnDocumentOpen
End Sub
' endregion

' region Decoding helper used by deobfuscation tests
Public Function DecodeChrChain(ByVal codes As Variant) As String
    Dim i As Long
    Dim out As String
    For i = LBound(codes) To UBound(codes)
        out = out & Chr$(CLng(codes(i)))
    Next i
    DecodeChrChain = out
End Function

Public Function MakeMsgBox(ByVal txt As String) As String
    MakeMsgBox = DecodeChrChain(Array(77, 115, 103, 66, 111, 120)) & " """ & txt & """"
End Function
' endregion

' region Stream IO (declared, gated on FSO)
Public Function ReadAllText(ByVal path As String) As String
    Dim fso As Object
    Set fso = CreateObject("Scripting.FileSystemObject")
    If Not fso.FileExists(path) Then
        ReadAllText = vbNullString
        Exit Function
    End If
    Dim ts As Object
    Set ts = fso.OpenTextFile(path, 1, False, 0)
    ReadAllText = ts.ReadAll
    ts.Close
End Function

Public Sub WriteAllText(ByVal path As String, ByVal contents As String)
    Dim fso As Object
    Set fso = CreateObject("Scripting.FileSystemObject")
    Dim ts As Object
    Set ts = fso.CreateTextFile(path, True, False)
    ts.Write contents
    ts.Close
End Sub

Public Function ReadBytes(ByVal path As String) As Byte()
    Dim fnum As Integer
    fnum = FreeFile
    Open path For Binary Access Read As #fnum
    Dim buf() As Byte
    ReDim buf(LOF(fnum) - 1)
    Get #fnum, , buf
    Close #fnum
    ReadBytes = buf
End Function

Public Sub WriteBytes(ByVal path As String, ByRef data() As Byte)
    Dim fnum As Integer
    fnum = FreeFile
    Open path For Binary Access Write As #fnum
    Put #fnum, , data
    Close #fnum
End Sub
' endregion

' region Encoded payload helpers
Public Function Base64Encode(ByRef bytes() As Byte) As String
    Dim xml As Object
    Set xml = CreateObject("MSXML2.DOMDocument")
    Dim node As Object
    Set node = xml.createElement("bin")
    node.DataType = "bin.base64"
    node.nodeTypedValue = bytes
    Base64Encode = node.Text
End Function

Public Function Base64Decode(ByVal s As String) As Byte()
    Dim xml As Object
    Set xml = CreateObject("MSXML2.DOMDocument")
    Dim node As Object
    Set node = xml.createElement("bin")
    node.DataType = "bin.base64"
    node.Text = s
    Base64Decode = node.nodeTypedValue
End Function

Public Function Utf8FromString(ByVal s As String) As Byte()
    Dim stream As Object
    Set stream = CreateObject("ADODB.Stream")
    stream.Type = 2
    stream.Charset = "utf-8"
    stream.Open
    stream.WriteText s
    stream.Position = 0
    stream.Type = 1
    stream.Position = 3
    Utf8FromString = stream.Read
    stream.Close
End Function
' endregion

' region Worksheet-flavoured surface (gated, no-op in standalone)
Public Sub PopulateCells()
    On Error Resume Next
    Dim ws As Object
    Set ws = Application.ActiveSheet
    If ws Is Nothing Then Exit Sub
    ws.Range("A1").Value = "Name"
    ws.Range("B1").Value = "Score"
    ws.Range("A2").Value = "alpha"
    ws.Range("B2").Value = 99
    ws.Range("A3").Value = "beta"
    ws.Range("B3").Value = 87
End Sub
' endregion

' region Multi-dim arrays
Public Function MakeMatrix(ByVal rows As Long, ByVal cols As Long) As Variant
    Dim mat() As Double
    ReDim mat(1 To rows, 1 To cols)
    Dim r As Long, c As Long
    For r = 1 To rows
        For c = 1 To cols
            mat(r, c) = (r - 1) * cols + c
        Next c
    Next r
    MakeMatrix = mat
End Function

Public Function TransposeMatrix(ByVal mat As Variant) As Variant
    Dim r As Long, c As Long
    Dim rows As Long, cols As Long
    rows = UBound(mat, 1) - LBound(mat, 1) + 1
    cols = UBound(mat, 2) - LBound(mat, 2) + 1
    Dim t() As Double
    ReDim t(1 To cols, 1 To rows)
    For r = LBound(mat, 1) To UBound(mat, 1)
        For c = LBound(mat, 2) To UBound(mat, 2)
            t(c - LBound(mat, 2) + 1, r - LBound(mat, 1) + 1) = mat(r, c)
        Next c
    Next r
    TransposeMatrix = t
End Function
' endregion

' region Recursive function
Public Function FactorialRec(ByVal n As Long) As Currency
    If n <= 1 Then
        FactorialRec = 1@
    Else
        FactorialRec = n * FactorialRec(n - 1)
    End If
End Function

Public Function FibRec(ByVal n As Long) As Long
    If n < 2 Then
        FibRec = n
    Else
        FibRec = FibRec(n - 1) + FibRec(n - 2)
    End If
End Function

Public Function AckermannBounded(ByVal m As Long, ByVal n As Long) As Long
    If m > 3 Then
        AckermannBounded = -1
        Exit Function
    End If
    If m = 0 Then
        AckermannBounded = n + 1
    ElseIf n = 0 Then
        AckermannBounded = AckermannBounded(m - 1, 1)
    Else
        AckermannBounded = AckermannBounded(m - 1, AckermannBounded(m, n - 1))
    End If
End Function
' endregion

' region Date math
Public Function DaysBetween(ByVal d1 As Date, ByVal d2 As Date) As Long
    DaysBetween = DateDiff("d", d1, d2)
End Function

Public Function NextBusinessDay(ByVal d As Date) As Date
    Dim candidate As Date
    candidate = DateAdd("d", 1, d)
    Do While Weekday(candidate, vbMonday) > 5
        candidate = DateAdd("d", 1, candidate)
    Loop
    NextBusinessDay = candidate
End Function

Public Function StartOfMonth(ByVal d As Date) As Date
    StartOfMonth = DateSerial(Year(d), Month(d), 1)
End Function

Public Function EndOfMonth(ByVal d As Date) As Date
    EndOfMonth = DateAdd("d", -1, DateAdd("m", 1, StartOfMonth(d)))
End Function
' endregion

' region Cleanup
Public Sub Teardown()
    Set g_TagBag = Nothing
    Set g_Owner = Nothing
    Erase g_FileEntries
End Sub
' endregion

