#!/bin/sh
mydir=`dirname $0`
echo $mydir
cd $mydir
echo -n "my dir: "
pwd
xgettext -f python_files_Linux.txt -o ../locale/adbtools2.pot --from-code=UTF-8
if potool ../locale/adbtools2.pot ../locale/it/LC_MESSAGES/adbtools2.po > ../locale/it/LC_MESSAGES/adbtools2.po.tmp
then
    mv ../locale/it/LC_MESSAGES/adbtools2.po.tmp ../locale/it/LC_MESSAGES/adbtools2.po
    echo "Please edit with poedit the file ../locale/it/LC_MESSAGES/adbtools2.po"
    echo "and compile to ../locale/it/LC_MESSAGES/adbtools2.mo"
else
    echo "ERROR processing pot files with potool"
fi


