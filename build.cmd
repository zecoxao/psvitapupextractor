@echo off
REM Build psvitapupextractor_gui.exe with the .NET Framework compiler (no SDK needed).
REM unarzl.exe must sit next to the built exe at runtime.
set CSC=C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe
"%CSC%" /nologo /optimize+ /target:winexe /out:"%~dp0psvitapupextractor_gui.exe" ^
  /r:System.dll /r:System.Core.dll /r:System.Windows.Forms.dll /r:System.Drawing.dll ^
  "%~dp0VitaKeys.cs" "%~dp0VitaSce.cs" "%~dp0VitaPup.cs" "%~dp0VitaPupExtractorGui.cs"
echo done (exit %ERRORLEVEL%)  - unarzl.exe must be next to the exe
