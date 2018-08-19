#!/bin/sh
#
# This script will be executed before the new JFFS2 root file system image is
# created
#
# The sequence, to create the new root file system image is the following:
#
#   1. input/root (original root file system) is copied to
#      output/root (new root file system)
#
#   2. patches in root-patch are applied to output/root
#
#   3. files in root-overlay are copied to output/root
#
#   4. this script is executed
#
# This script can be used to embed time stampas in some files or to do
# other processing before the new root file system image si created
# by default it embed a version number and a time stamp i the /etc/banner
# file
#
# the following environment variables are available:
#
#    MK_BASEDIR  contains the base directory for the mod-kit,
#                $MK_BASEDIR/output/root contains the new root file
#                system that can be manipulated before the JFFS2 image
#                is created
#
#    SCRIPTPATH  contains the directory where is the mod-kit-run.sh 
#

#..................................................................
#yet another purposeful solution by  Advanced Digital Broadcast SA
#..................................................................


bannerfile=$MK_BASEDIR/output/root/etc/banner
version=`cat $SCRIPTPATH/../version | awk '{print $1}'`
curdate=`date '+%Y-%m-%d %H:%M:%S'`
tagline=`tail -1 $bannerfile`
echo "# ------ pre-image-script.sh starting"
echo "         MK_BASEDIR:   $MK_BASEDIR"
echo "         SCRIPTPATH:   $SCRIPTPATH"
echo "         version:      $version"
echo "         curdate:      $curdate"
#     ..................................................................
echo "hacked and improved with https://github.com/digiampietro/adbtools2" >> $bannerfile
echo "version $version - $curdate"                                        >> $bannerfile
echo $tagline                                                             >> $bannerfile




