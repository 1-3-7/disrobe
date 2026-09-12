VERSION 1.0 CLASS
BEGIN
  MultiUse = -1  'True
END
Attribute VB_Name = "GreetingTemplate"
Attribute VB_GlobalNameSpace = False
Attribute VB_Creatable = True
Attribute VB_PredeclaredId = False
Attribute VB_Exposed = True
Option Explicit

Private m_Prefix As String
Private m_Suffix As String
Private m_Mood As Long
Private m_Version As Long

Public Event Rendered(ByVal Output As String)
Public Event MoodChanged(ByVal OldMood As Long, ByVal NewMood As Long)

Private Sub Class_Initialize()
    m_Prefix = "hello"
    m_Suffix = "world"
    m_Mood = 0
    m_Version = 1
End Sub

Private Sub Class_Terminate()
End Sub

Public Property Get Prefix() As String
    Prefix = m_Prefix
End Property

Public Property Let Prefix(ByVal value As String)
    m_Prefix = value
End Property

Public Property Get Suffix() As String
    Suffix = m_Suffix
End Property

Public Property Let Suffix(ByVal value As String)
    m_Suffix = value
End Property

Public Property Get Mood() As Long
    Mood = m_Mood
End Property

Public Property Let Mood(ByVal value As Long)
    If value <> m_Mood Then
        Dim oldVal As Long
        oldVal = m_Mood
        m_Mood = value
        RaiseEvent MoodChanged(oldVal, m_Mood)
    End If
End Property

Public Property Get Version() As Long
    Version = m_Version
End Property

Public Function Render() As String
    Dim sep As String
    Select Case m_Mood
        Case 0
            sep = " "
        Case 1
            sep = "! "
        Case 2
            sep = "... "
        Case Else
            sep = " "
    End Select
    Render = m_Prefix & sep & m_Suffix
    RaiseEvent Rendered(Render)
End Function

Public Function ToString() As String
    ToString = Render
End Function
