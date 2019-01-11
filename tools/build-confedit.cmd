@echo off
cls
SET PROGRAM.NAME=confedit
SET FILE.NAME=confedit
SET PYINSTALLER.OPTIONS=--distpath ./ --onefile


ECHO ******************************************
ECHO * %PROGRAM.NAME%
ECHO * Compiling exe file from python sources
ECHO ******************************************


ECHO.
ECHO.
ECHO   #### Press any key to continue ####
ECHO   ####      or CTRL+C to break   ####
pause >NUL


cd..
CLS
ECHO ******************************************
ECHO * %PROGRAM.NAME%
ECHO * Compiling exe file from python sources
ECHO ******************************************
ECHO.

echo ******** Cleaning temporary file...
if exist __pycache__ rmdir /s /q __pycache__
if exist build       rmdir /s /q build
if exist dist        rmdir /s /q dist
if exist %FILE.NAME%.spec del %FILE.NAME%.spec > NUL
if exist %FILE.NAME%.exe  del %FILE.NAME%.exe  > NUL 
ECHO.
ECHO ******** Creating '%FILE.NAME%' installer...
ECHO.
pyinstaller %PYINSTALLER.OPTIONS% %FILE.NAME%.py

if not exist %FILE.NAME%.exe goto no.exe.file

ECHO.
ECHO ******** Compilation OK!
if exist build       rmdir /s /q build
if exist %FILE.NAME%.spec del %FILE.NAME%.spec > NUL
goto end

:no.exe.file
ECHO.
ECHO ******** Compilation error!
ECHO File '%FILE.NAME%.exe' not available!

:end
ECHO.
ECHO.
ECHO   #### Press any key to exit ####
pause >NUL

if exist __pycache__ rmdir /s /q __pycache__
if exist dist        rmdir /s /q dist

SET PROGRAM.NAME=
SET FILE.NAME=
SET PYINSTALLER.OPTIONS=

