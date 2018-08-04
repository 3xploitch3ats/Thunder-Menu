Set objAPP = CreateObject("Shell.Application")
objAPP.ShellExecute "delLogin.bat","wscript.exe" & " RunAsAdministrator",,"runas", 1
