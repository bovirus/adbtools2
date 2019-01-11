@ECHO OFF
@echo off
cls
SET PROGRAM.NAME=pkcrypt
SET FILE.NAME=pkcrypt

ECHO ******************************************
ECHO * %PROGRAM.NAME%
ECHO * Cleaning compilation files
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
ECHO * Cleaning compilation files
ECHO ******************************************
ECHO.

cd ..
echo ******** Cleaning temporary file...

if exist __pycache__ rmdir /s /q __pycache__
if exist build       rmdir /s /q build
if exist dist        rmdir /s /q dist

if exist %FILE.NAME%.spec del %FILE.NAME%.spec > NUL
if exist %FILE.NAME%.exe  del %FILE.NAME%.exe  > NUL

ECHO.
ECHO.
ECHO   #### Press any key to exit ####

pause >NUL
