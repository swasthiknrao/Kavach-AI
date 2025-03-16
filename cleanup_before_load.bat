@echo off
echo Cleaning up __pycache__ directories...
for /d /r . %%d in (__pycache__) do @if exist "%%d" rd /s /q "%%d"
echo Done! You can now load the extension.
pause 