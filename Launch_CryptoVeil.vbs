' Launch_CryptoVeil.vbs — Silent Launcher for CryptoVeil Desktop App
Set oShell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
strPath = fso.GetParentFolderName(WScript.ScriptFullName)

' Check if virtualenv pythonw exists, otherwise use system pythonw
If fso.FileExists(strPath & "\.venv\Scripts\pythonw.exe") Then
    pyExe = """" & strPath & "\.venv\Scripts\pythonw.exe"""
ElseIf fso.FileExists(strPath & "\venv\Scripts\pythonw.exe") Then
    pyExe = """" & strPath & "\venv\Scripts\pythonw.exe"""
Else
    pyExe = "pythonw.exe"
End If

oShell.CurrentDirectory = strPath
oShell.Run pyExe & " """ & strPath & "\desktop_app.py""", 0, False
