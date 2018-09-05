@echo off
CLS
ECHO *********************************************
ECHO *                                           *
ECHO *                adbtools2                  *
ECHO *                                           *
ECHO *    Compiling .py python file in .exe      *
ECHO *                                           *
ECHO *********************************************

ECHO.
ECHO.
ECHO    ****  Press any key to continue   ****
ECHO    **** or CTRL+C to break the batch ****
PAUSE >NUL

REM for %%x in (confedit confbin2xml confxml2bin pkcrypt) do (
REM ref - https://pythonhosted.org/PyInstaller/usage.html
REM 
REM --clear
REM    clear the cache
REM  --log-level LEVEL
REM    Amount of detail in build-time console messages. 
REM    LEVEL may be one of DEBUG, INFO, WARN, ERROR, CRITICAL (default: INFO).

SET PYTHON_CMD_LINE=--clean --log-level ERROR --onefile --windowed 

CLS
ECHO *********************************************
ECHO *                                           *
ECHO *                adbtools2                  *
ECHO *                                           *
ECHO *    Compiling .py python file in .exe      *
ECHO *                                           *
ECHO *********************************************
ECHO.

ECHO **** Compiling 'confedit.py' in 'confedit.exe'...
pyinstaller.exe %PYTHON_CMD_LINE% confedit.py
if exist dist\confedit.exe (
ECHO **** Moving 'confedit.exe' from 'dist folder'...
move /Y dist\confedit.exe . >NUL
ECHO.
)

ECHO **** Compiling 'confbin2xml.py' in 'confbin2xml.exe'...
pyinstaller.exe %PYTHON_CMD_LINE% confbin2xml.py
if exist dist\confbin2xml.exe (
ECHO **** Moving 'confbin2xml.exe' from 'dist folder'...
move /Y dist\confbin2xml.exe . >NUL
ECHO.
)

ECHO **** Compiling 'confxml2bin' in 'confxml2bin.exe'...
pyinstaller.exe %PYTHON_CMD_LINE% confxml2bin.py
if exist dist\confxml2bin.exe (
ECHO **** Moving 'confxml2bin.exe' from 'dist folder'...
move /Y dist\confxml2bin.exe . >NUL
ECHO.
)

ECHO **** Compiling 'pkcrypt.py' in 'pkcrypt.exe'...
pyinstaller.exe %PYTHON_CMD_LINE% pkcrypt.py
if exist dist\pkcrypt.exe (
ECHO **** Moving 'pkcrypt.exe' from 'dist folder'...
move /Y dist\pkcrypt.exe . >NUL
ECHO.
)

ECHO.
ECHO **** Removing Python cache folder...
rmdir /s /q __pycache__ >NUL

ECHO.
ECHO.
ECHO      **** Press any key to exit ****
PAUSE >NUL

SET PYTHON_CMD_LINE=

