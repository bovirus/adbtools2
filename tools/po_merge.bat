@ECHO OFF
SETLOCAL EnableExtensions 

CLS
ECHO ***********************************************************
ECHO * adbtools2 - Update language files using master template *
ECHO ***********************************************************
ECHO.
ECHO.
ECHO            #### Press any key to continue ####
ECHO            ####   Press CTRL+C to break   ####
PAUSE >NUL

CLS
ECHO ***********************************************************
ECHO * adbtools2 - Update language files using master template *
ECHO ***********************************************************
for %%x in (it) do (

ECHO **** Country = %%x - Merging 'adbtools2.po' with 'adbtools2.pot' template....
msgmerge  -U -q -N --backup=none ..\locale\%%x\lc_messages\adbtools2.po ..\locale\adbtools2.pot >NUL
ECHO **** Country = %%x - Cleaning obsolete entries from 'adbtools2.po'....
msgattrib --no-obsolete ..\locale\%%x\lc_messages\adbtools2.po > ..\locale\%%x\lc_messages\adbtools2_new.po
copy ..\locale\%%x\lc_messages\adbtools2_new.po ..\locale\%%x\lc_messages\adbtools2.po >NUL
del ..\locale\%%x\lc_messages\adbtools2_new.po >NUL
ECHO **** Country = %%x - Statistics about 'adbtools2.po'....
msgfmt --statistics ..\locale\%%x\lc_messages\adbtools2.po
ECHO *******************************************************

)

if exist Messages.mo del Messages.mo > NUL

ECHO.
ECHO.
ECHO      #### Press any key to exit #####
PAUSE > NUL
