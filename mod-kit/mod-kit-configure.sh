#!/bin/sh
#
# prepare the mod-kit folders layout and does some preliminary check
# This script has been checked ONLY with the firmware
# DVA-5592_A1_WI_20180405.sig with other firmware version probably
# will not function correctly.
#
# in case of different firmware version this script can be used as a
# guide to do a similar job modifying what needs to be modified
#
# --------------------------------------------------------------------------------
MK_BASEDIR=$HOME/mod-kit                    # base dir of the mod-kit files
MKFS_JFFS2=/usr/local/bin/mkfs.jffs2-lzma   # mkfs.jffs2 command with lzma patch
if [ ! -x $MKFS_JFFS2 ]
then
    MKFS_JFFS2=`which mkfs.jffs2`
fi
# --------------------------------------------------------------------------------
#
SCRIPT=`realpath $0`
SCRIPTPATH=`dirname $SCRIPT`
#
#
usage() {
    echo "usage: ./mod-kit-configure.sh [ -d basedir ] [ -j /path/to/mkfs.jffs2 ] <firmware file>"
    echo "   -d basedir (defautl $MK_BASEDIR)"
    echo "   -j /path/to/mkfs.jffs2 (default $MKFS_JFFS2)"
    echo "   -h this help"
    echo
    echo "   example:"
    echo "   ./mod-kit-configure.sh /path/to/DVA-5592_A1_WI_20180405.sig"
    echo
    echo "   This command will prepare the mod-kit folders layout at"
    echo "   $MK_BASEDIR"
}

# ------ check firmware file
check_fwfile() {
    magic_number=`hexdump -s 0 -n 4 -ve '/1 "%c"' $1`
    if [ "$magic_number" != "yIMG" ]
    then
	echo "ERROR: Wrong firmware file (wrong magic number)"
	exit 1
    fi
    
    remote_version=`hexdump -s 48 -n 16 -ve '/1 "%c"' $1`
    if [ "$remote_version" != "DVA-5592_A1_WI_2" ]
    then
	echo "ERROR: Wrong version (expecting DVA-5592_A1_WI_2 got $remote_version)"
	exit 2
    fi

    remote_date=`hexdump -s 64 -n 16 -ve '/1 "%c"' $1`
    if [ "$remote_date" != "2018-04-11 12:42" ]
    then
	echo "ERROR: Wrong release date (expecting 2018-04-11 12:42 got $remote_date)"
	exit 3
    fi
    echo "# ------ firmware file ok"
}

# ------ process arguments
while getopts :d:j:h option
do
    case "${option}"
    in
	d) MK_BASEDIR="${OPTARG}";;
	j) MKFS_JFFS2="${OPTARG}";;
	h) usage
	   exit
	   ;;
	?) echo "ERROR: unexpected option"
	   usage
	   exit
	   ;;
    esac
done

shift $((OPTIND-1))


# ------ check input parameter (presence and firmware file existence)
echo "# ------ check input parameter (presence and firmware file existence)"


if [ "$1" = "" ] 
then
    usage
    exit
fi

FW_PATH=$1

if [ ! -e $FW_PATH ]
then
    echo $FW_PATH does not exists
    exit
fi
FW_FILE=`basename $FW_PATH`

check_fwfile $FW_PATH 

# ------ check mkfs.jffs2 existence and lzma support
echo "# ------ check mkfs.jffs2 existence and lzma support"


$MKFS_JFFS2 -L 2>&1 | grep lzma
ret=$?
if [ ! "$ret" = "0" ]
then
    echo "$MKFS_JFFS2 does not support lzma compression"
    echo "please follow documentation, use -j option "
    echo "to point to a mkfs.jffs2 command"
    echo "with lzma support. Follow documentation to apply"
    echo "the lzma patch to mkfs.jffs2 source"
    exit 1
else
    echo "#        mkfs.jffs2 with lzma support found"
fi


# ------ check for other needed commands
echo "# ------ check for other needed commands"

for i in jefferson dd fakeroot setfacl rsync patch truncate md5sum xxd mkpasswd
do which $i
   ret=$?
   if [ ! "$ret" = "0" ]
   then
       echo "$i not present"
       echo "please install it" 
       if [ "$i" = "jefferson" ]
       then
	   echo "look at https://github.com/sviehb/jefferson"
       fi  
       exit 1
   else
       echo "#        $i found"
   fi
done



# ------ print main variables and create $MK_BASEDIR/conf.sh file
echo "# ------ main variables and create $MK_BASEDIR/conf.sh file"
echo "         MK_BASEDIR    $MK_BASEDIR"
echo "         MKFS_JFFS2    $MKFS_JFFS2"
echo "         FW_FILE       $FW_FILE"
echo "         SCRIPT        $SCRIPT"
echo "         SCRIPTPATH    $SCRIPTPATH"
echo "MK_BASEDIR=\"$MK_BASEDIR\""           > $SCRIPTPATH/conf.sh
echo "MKFS_JFFS2=\"$MKFS_JFFS2\""          >> $SCRIPTPATH/conf.sh
echo "FW_FILE=\"$FW_FILE\""                >> $SCRIPTPATH/conf.sh 
echo

# ------ prepare folder layouts
echo "# ------ preparing folder layout at $MK_BASEDIR"
echo "#        $MK_BASEDIR/input         original firmware file and extracted data will go here"
echo "#        $MK_BASEDIR/input/root    original firmware root file system will go here"
echo "#        $MK_BASEDIR/root-patch    patches to each file will go here"
echo "#        $MK_BASEDIR/root-overlay  files here will be added/will overwrite files in the destination root"
echo "#        $MK_BASEDIR/output        modified firmware and output images will go here"
echo "#        $MK_BASEDIR/output/root   modified root file system will go here"
echo

for i in $MK_BASEDIR/input \
	 $MK_BASEDIR/input/root \
	 $MK_BASEDIR/root-patch \
	 $MK_BASEDIR/root-overlay \
	 $MK_BASEDIR/output \
	 $MK_BASEDIR/output/root
do if [ ! -d $i ]
   then
       echo "#    making dir $i"
       mkdir -p $i
   fi
done

# ------ copy files to mod-kit folder
echo "# ------ copying $FW_PATH --> $MK_BASEDIR/input"
cp $FW_PATH $MK_BASEDIR/input
echo "# ------ copying patch and overlay files to $MK_BASEDIR/root-patch"
rsync --exclude .gitignore -rav $SCRIPTPATH/root-patch/   $MK_BASEDIR/root-patch/
rsync --exclude .gitignore -rav $SCRIPTPATH/root-overlay/ $MK_BASEDIR/root-overlay/
cp $SCRIPTPATH/device-table.txt      $MK_BASEDIR/
cp $SCRIPTPATH/root-permissions.acl  $MK_BASEDIR/
cp $SCRIPTPATH/root-rm-files.txt     $MK_BASEDIR/
