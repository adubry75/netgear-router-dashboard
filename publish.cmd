@echo off
cd /d "%~dp0"
dotnet publish -c Release -r win-x64 --self-contained -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o publish
echo.
echo Done! Your exe is in the publish folder.
pause
