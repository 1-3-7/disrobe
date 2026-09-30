Dim secret
secret = "s" & Chr(51) & "cr" & Chr(51) & "t"
WScript.Echo "secret is " & secret
MsgBox Len(secret) * 2
