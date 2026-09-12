Attribute VB_Name = "SourceProbe"
Option Explicit
Option Base 1

Public Const APP_NAME As String = "SourceProbe"
Public Const MAX_ITEMS As Long = 16

Public Enum Severity
    SeverityLow = 0
    SeverityMedium = 1
    SeverityHigh = 2
End Enum

Public Type Record
    Key As String
    Count As Long
    Weight As Double
End Type

Public g_Counter As Long

Public Sub Main()
    On Error GoTo Handler
    Dim total As Long
    total = Accumulate(10)
    MsgBox "total=" & total, vbInformation, APP_NAME
    Exit Sub
Handler:
    Debug.Print "Main error " & Err.Number & ": " & Err.Description
End Sub

Public Function Accumulate(ByVal upTo As Long) As Long
    Dim i As Long
    Dim sum As Long
    For i = 1 To upTo
        sum = sum + i
    Next i
    Accumulate = sum
End Function

Public Function Classify(ByVal score As Long) As Severity
    Select Case score
        Case Is < 10
            Classify = SeverityLow
        Case Is < 100
            Classify = SeverityMedium
        Case Else
            Classify = SeverityHigh
    End Select
End Function

Public Function BuildRecord(ByVal aKey As String, ByVal aCount As Long) As Record
    BuildRecord.Key = aKey
    BuildRecord.Count = aCount
    BuildRecord.Weight = aCount * 1.5
End Function

Public Function JoinParts(ByVal sep As String, ByRef parts() As String) As String
    Dim i As Long
    Dim out As String
    For i = LBound(parts) To UBound(parts)
        If i > LBound(parts) Then out = out & sep
        out = out & parts(i)
    Next i
    JoinParts = out
End Function

Public Function FactorialRec(ByVal n As Long) As Currency
    If n <= 1 Then
        FactorialRec = 1
    Else
        FactorialRec = n * FactorialRec(n - 1)
    End If
End Function

Public Sub CountUp(ByVal n As Long)
    Dim i As Long
    i = 0
    Do While i < n
        i = i + 1
        g_Counter = g_Counter + 1
    Loop
End Sub
