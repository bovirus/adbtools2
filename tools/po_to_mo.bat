@ECHO OFF
CLS
ECHO ********************************************
ECHO * adbtools2 - Convert PO files in MO files *
ECHO ********************************************
ECHO.
ECHO.
ECHO      #### Press any key to continue ####
ECHO      ####   Press CTRL+C to break   ####
PAUSE >NUL

CLS
ECHO ********************************************
ECHO * adbtools2 - Convert PO files in MO files *
ECHO ********************************************
ECHO.
ECHO.


for %%x in (it) do (
ECHO **** Country = %%x - Decompiling 'adbtools2.po' in 'adbtools2.mo'....
msgfmt ..\locale\%%x\lc_messages\adbtools2.po -o ..\locale\%%x\lc_messages\adbtools2.mo

ECHO *****************************************************************
)

ECHO.
ECHO.
ECHO      **** Press any key to exit ****

pause >NUl
