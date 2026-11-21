Option Explicit
Dim http, isRunning, fso, scriptDir, WshShell

isRunning = False
On Error Resume Next
Set http = CreateObject("MSXML2.ServerXMLHTTP.6.0")
http.setTimeouts 2000, 2000, 2000, 2000
http.open "GET", "http://127.0.0.1:8080/api/status", False
http.send
If Err.Number = 0 Then
    If http.Status = 200 Then
        isRunning = True
    End If
End If
Err.Clear
On Error GoTo 0

If Not isRunning Then
    Set fso = CreateObject("Scripting.FileSystemObject")
    scriptDir = fso.GetParentFolderName(WScript.ScriptFullName)
    Set WshShell = CreateObject("WScript.Shell")
    WshShell.CurrentDirectory = scriptDir
    WshShell.Run "wscript.exe """ & scriptDir & "\Start-Home-VPN.vbs""", 0, False
End If
