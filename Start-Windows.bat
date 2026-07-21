@echo off
REM ChromIQ i1iO probe - Windows launcher. Double-click this file.
REM Pure ASCII on purpose: the console codepage mangles anything else.

cd /d "%~dp0"
cls
echo.
echo   ChromIQ - i1iO information collector (Windows)
echo.

REM Windows ships a fake "python.exe" that just opens the Microsoft Store, so
REM test that each candidate can really run code instead of trusting "where".
REM Labels rather than IF-blocks: %errorlevel% inside parentheses needs
REM delayed expansion and silently misbehaves without it.

py -3 -c "print()" >nul 2>&1
if %errorlevel%==0 goto usepy

python -c "print()" >nul 2>&1
if %errorlevel%==0 goto usepython

goto nopython

:usepy
py -3 chromiq_io_probe.py
goto done

:usepython
python chromiq_io_probe.py
goto done

:nopython
echo   Python 3 does not seem to be installed.
echo.
echo   Please install it from:
echo.
echo       https://www.python.org/downloads/
echo.
echo   IMPORTANT: on the first screen of the installer, tick the box that
echo   says "Add python.exe to PATH" before clicking Install. Then
echo   double-click this file again.
echo.
pause
exit /b 1

:done
echo.
pause
