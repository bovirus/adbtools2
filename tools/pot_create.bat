@echo off
CLS
ECHO ***********************************************
ECHO * abdtools2 - Create master language template *
ECHO ***********************************************
ECHO.
ECHO.
ECHO     #### Press any key to continue ####
ECHO     ####   Press CTRL+C to break   ####
PAUSE >NUL
CLS
ECHO ***********************************************
ECHO * abdtools2 - Create master language template *
ECHO ***********************************************
ECHO.
ECHO Creating master language template...
xgettext -f python_files_Windows.txt --from-code=UTF-8 -o ../locale/adbtools2.pot > NUL
ECHO Creating master language template completed!
ECHO.
ECHO.
ECHO    #### Press any key to exit ####
PAUSE > NUL
