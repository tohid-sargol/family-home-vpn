Set fso = CreateObject("Scripting.FileSystemObject")
scriptDir = fso.GetParentFolderName(WScript.ScriptFullName)
Set WshShell = CreateObject("WScript.Shell")
WshShell.CurrentDirectory = scriptDir

Dim pythonExe, localPy
pythonExe = "python.exe"

' Check standard python 3.12 / 3.11 / 3.10 install locations
localPy = WshShell.ExpandEnvironmentStrings("%LOCALAPPDATA%") & "\Programs\Python\Python312\python.exe"
If fso.FileExists(localPy) Then
    pythonExe = localPy
Else
    localPy = WshShell.ExpandEnvironmentStrings("%LOCALAPPDATA%") & "\Programs\Python\Python311\python.exe"
    If fso.FileExists(localPy) Then
        pythonExe = localPy
    Else
        localPy = WshShell.ExpandEnvironmentStrings("%LOCALAPPDATA%") & "\Programs\Python\Python310\python.exe"
        If fso.FileExists(localPy) Then
            pythonExe = localPy
        End If
    End If
End If

WshShell.Run """" & pythonExe & """ """ & scriptDir & "\portal.py""", 0, False
