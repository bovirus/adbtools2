#!/bin/sh
#
# this script source conf.sh, on same directory, and then generates an unsigned modified
# firmware from DVA-5592_A1_WI_20180405.sig (currently works only on this firmware)
#
SCRIPT=`realpath $0`
SCRIPTPATH=`dirname $SCRIPT`
ERASESIZE=$((128 * 1024))
. $SCRIPTPATH/conf.sh
FW_NEW_FILE=`echo "$FW_FILE"|sed 's/\.sig$/-mod.sig/'`
if [ "$FW_NEW_FILE" = "$FW_FILE" ]
then
    FW_NEW_FILE="$FW_FILE-mod.sig"
fi

usage () {
    echo "usage: ./mod-kit-configure.sh [ -c ] [ -h ]"
    echo "       -d clean all generated files from a previous run"
    echo "       -h print this help"
}


while getopts :ch option
do
    case "${option}"
    in
	c) OPMODE="CLEAN";;
	h) usage
	   exit
	   ;;
	?) echo "unexpected option"
	   usage
	   exit
	   ;;
    esac
done

shift $((OPTIND-1))

if [ "$1" != "" ]
then
    echo "unexpected argument"
    usage
    exit
fi



# ------ print main variables and create $MK_BASEDIR/conf.sh file
echo "------ main variables and create $MK_BASEDIR/conf.sh file"
echo "       MK_BASEDIR    $MK_BASEDIR"
echo "       MKFS_JFFS2    $MKFS_JFFS2"
echo "       FW_FILE       $FW_FILE"
echo "       SCRIPT        $SCRIPT"
echo "       SCRIPTPATH    $SCRIPTPATH"
echo "       ERASESIZE     $ERASESIZE"
echo "       FW_NEW_FILE   $FW_NEW_FILE"
echo "       OPMODE        $OPMODE"
echo

if [ "$OPMODE" = "CLEAN" ]
then
    echo "# ------ cleanup file generated in a previous run"
    rm -f  $MK_BASEDIR/input/*bin
    rm -f  $MK_BASEDIR/output/*bin
    rm -f  $MK_BASEDIR/output/*log
    rm -f  $MK_BASEDIR/output/*sig
    rm -rf $MK_BASEDIR/input/root/*
    rm -rf $MK_BASEDIR/output/root/*
    echo "#        cleanup done"
    exit
fi


# ------ extract boot and root fs from firmware file
echo "------ extract boot and root fs from firmware file"
dd if=$MK_BASEDIR/input/$FW_FILE bs=256 skip=514 count=94720 of=$MK_BASEDIR/input/boot-root-fs.bin

# ------ split boot and root partitions
echo "# ------ split boot and root partitions"
PSPOS=`grep --byte-offset --only-matching --text YAPS-PartitionSplit $MK_BASEDIR/input/boot-root-fs.bin|awk -F: '{print $1}'`
SPLITPOS=$(($PSPOS+256))
BOOTROOTSIZE=`wc -c $MK_BASEDIR/input/boot-root-fs.bin|awk '{print $1}'`
ROOTEND=$(($BOOTROOTSIZE - $ERASESIZE))
ROOTLEN=$(($ROOTEND - $SPLITPOS))
echo "         SPLITPOS:     $SPLITPOS"
echo "         PSPOS:        $PSPOS"
echo "         BOOTROOTSIZE: $BOOTROOTSIZE"
echo "         ROOTEND:      $ROOTEND"
echo "         ROOTLEN:      $ROOTLEN"

# ------ extract boot partition image
echo "# ------ extract boot partition image"
dd if=$MK_BASEDIR/input/boot-root-fs.bin of=$MK_BASEDIR/input/boot-fs.bin bs=256 count=$(($SPLITPOS / 256))

# ------ extract root partition image, takes some time
echo "# ------ extract root partition image, takes some time"
dd if=$MK_BASEDIR/input/boot-root-fs.bin of=$MK_BASEDIR/input/root-fs.bin bs=256 skip=$(($SPLITPOS / 256)) count=$(($ROOTLEN /256 ))

# ------ extract end of file system marker
echo "# ------ extract end of file system marker"
dd if=$MK_BASEDIR/input/boot-root-fs.bin of=$MK_BASEDIR/input/eofs.bin bs=256 skip=$(($ROOTEND / 256))

# ------ extract root file system with jefferson
echo "# ------ extract root file system with jefferson, it takes some time"
fakeroot jefferson -f -d $MK_BASEDIR/input/root $MK_BASEDIR/input/root-fs.bin

# ------ fix extracted root file system
echo "# ------ fix extracted root file system"
CURRWD=`pwd`
cd $MK_BASEDIR/input/root/fs_2
for i in `find . -maxdepth 1 -type l -print`;do mv $i ../fs_1/sbin/;done
for i in `find . -maxdepth 1 -type f -print`;do mv $i ../fs_1/sbin/;done
mv conf ../fs_1/www/
mv sbin ../fs_1/usr/
mv bin ../fs_1/usr/
mv htdocs ../fs_1/www/
mv lib ../fs_1/usr/
mv nls ../fs_1/www/
mv pages ../fs_1/www/
mv share ../fs_1/usr/
mv yapl ../fs_1/www/
cd $CURRWD
rmdir $MK_BASEDIR/input/root/fs_2
mv $MK_BASEDIR/input/root/fs_1/[a-z]* $MK_BASEDIR/input/root/
rmdir $MK_BASEDIR/input/root/fs_1
cp -p $MK_BASEDIR/input/root/bin/busybox $MK_BASEDIR/input/root/sbin/init
chmod 755 $MK_BASEDIR/input/root/sbin/init

# ------ fix permissions on extracted root file system
echo "# ------ fix permissions on extracted root file system"
cd $MK_BASEDIR/input/root
fakeroot setfacl --restore=$MK_BASEDIR/root-permissions.acl
cd $CURRWD

# ------ copy original root file system to new root file system
echo "# ------ copy original root file system to new root file system"
rsync -rav $MK_BASEDIR/input/root/ $MK_BASEDIR/output/root/

# ------ apply patches to new root file system
for i in `find $MK_BASEDIR/root-patch -name \*.patch -type f`
do echo "          applying $i"
   F=`echo $i|sed 's/root-patch/output\/root/'|sed 's/\.patch$//'`
   echo "          to       $F"
   patch $F $i
done

cd $MK_BASEDIR/output/root
fakeroot setfacl --restore=$MK_BASEDIR/root-permissions.acl
cd $CURRWD

# ------ apply overlay to new root file system
echo "# ------ apply overlay to new root file system"
rsync --exclude=.gitignore -rav $MK_BASEDIR/root-overlay/ $MK_BASEDIR/output/root/



# ------ create new root file system image, step 1 mkfs.jffs2
echo "# ------ create new root file system image, step1 mkfs.jffs2"
$MKFS_JFFS2  -r $MK_BASEDIR/output/root/ -s 4096 -e 131072 \
	     -y 95:lzma -n -o $MK_BASEDIR/output/rootfs-step1.bin \
	     -l -v -D $MK_BASEDIR/device-table.txt -U \
	     2>&1 | tee $MK_BASEDIR/output/mkjffs2-step1.log

# ------ zero pad the new root file system image to same size as original root file system 
echo "# ------ zero pad the new root file system image to same size as original root file system"
NEWROOTSIZE=`wc -c $MK_BASEDIR/output/rootfs-step1.bin|awk '{print $1}'`
PADSIZE=$(($NEWROOTSIZE / $ERASESIZE))
PADSIZE=$(($PADSIZE + 1 ))
PADSIZE=$(($PADSIZE * 1024 * 128 ))
PADSIZE=$(($PADSIZE - $NEWROOTSIZE))
echo "         PADSIZE:    $PADSIZE"
cp $MK_BASEDIR/output/rootfs-step1.bin $MK_BASEDIR/output/rootfs-step2.bin
dd if=/dev/zero of=$MK_BASEDIR/output/rootfs-step2.bin bs=1 count=$PADSIZE seek=$NEWROOTSIZE conv=notrunc
cat $MK_BASEDIR/output/rootfs-step2.bin $MK_BASEDIR/input/eofs.bin  > $MK_BASEDIR/output/rootfs-step3.bin

NEWROOTSIZE=`wc -c $MK_BASEDIR/output/rootfs-step3.bin|awk '{print $1}'`

if [ ! $ROOTLEN -ge $NEWROOTSIZE ]
then
    echo "UNRECOVERABLE PROBLEM: the new root image is larger the the original root image"
    exit 1
fi

PADSIZE=$(($ROOTLEN - $NEWROOTSIZE))

cp $MK_BASEDIR/output/rootfs-step3.bin $MK_BASEDIR/output/root-fs.bin
dd if=/dev/zero of=$MK_BASEDIR/output/root-fs.bin bs=1 count=$PADSIZE seek=$NEWROOTSIZE conv=notrunc

# ------ generate the new boot/root image
echo "# ------ generate the new boot/root image"
cat $MK_BASEDIR/input/boot-fs.bin $MK_BASEDIR/output/root-fs.bin $MK_BASEDIR/input/eofs.bin > $MK_BASEDIR/output/boot-root-fs.bin

# ------ generate the new unsigned firmware image
echo "# ------ generate the new unsigned firmware image"
cp $MK_BASEDIR/input/$FW_FILE  $MK_BASEDIR/output/$FW_NEW_FILE
FWNEWSIZE=`wc -c $MK_BASEDIR/output/$FW_NEW_FILE | awk '{print $1}'`
FWNEWSIZE=$(($FWNEWSIZE - 256))
# ------ truncate signature from unsigned firmware image
truncate -s $FWNEWSIZE $MK_BASEDIR/output/$FW_NEW_FILE

# ------ overwrite the original boot/root file system image with the modified one
echo "# ------ overwrite the original boot/root file system image with the modified one"
dd if=$MK_BASEDIR/output/boot-root-fs.bin of=$MK_BASEDIR/output/$FW_NEW_FILE bs=256 seek=514 count=94720 conv=notrunc

# ------ recalculate checksum in the modified firmware
echo "# ------ recalculate checksum in the modified firmware"
dd if=/dev/zero of=$MK_BASEDIR/output/$FW_NEW_FILE conv=notrunc bs=1 count=16 seek=240
hash=$(md5sum $MK_BASEDIR/output/$FW_NEW_FILE | cut -d " " -f1)
echo -n $hash | xxd -r -p | dd of=$MK_BASEDIR/output/$FW_NEW_FILE conv=notrunc bs=1 count=16 seek=240

# ------ generate xdelta patch file if xdelta3 is installed
XDELTA3=`which xdelta3`
if [ "$XDELTA3" != "" ]
then
    echo "# ------ generate xdelta patch file"
    xdelta3 -9 -e -s  $MK_BASEDIR/input/$FW_FILE $MK_BASEDIR/output/$FW_NEW_FILE $MK_BASEDIR/output/$FW_NEW_FILE.xdelta
fi
