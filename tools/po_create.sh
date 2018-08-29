#!/bin/sh
mydir=`dirname $0`
cd $mydir
xgettext -f python_files_Linux.txt -o ../locale/adbtools2.pot --from-code=UTF-8

