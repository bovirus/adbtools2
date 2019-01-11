@echo off

SET PROGRAM.NAME=adbtools2
SET FILE.NAME=adbtools2
SET XGETTEXT.OPTIONS=--no-wrap --from-code=UTF-8

CLS
ECHO *********************************************
ECHO * %PROGRAM.NAME%
ECHO * Create master language template 
ECHO *********************************************
ECHO.
ECHO.
ECHO     #### Press any key to continue ####
ECHO     ####   Press CTRL+C to break   ####
PAUSE >NUL

CLS
ECHO *********************************************
ECHO * %PROGRAM.NAME%
ECHO * Create master language template 
ECHO *********************************************
ECHO.

ECHO Creating master language template...

xgettext %XGETTEXT.OPTIONS% -f python_files_Windows.txt -o ../locale/%FILE.NAME%.pot  > NUL

ECHO Creating master language template completed!

ECHO.
ECHO.
ECHO    #### Press any key to exit ####
PAUSE > NUL

SET PROGRAM.NAME=
SET FILE.NAME=
SET XGETTEXT.OPTIONS=

