#!/bin/sh
#
# takes a parameter:
#   boot     for start (startup)
#   shutdown for kill  (shutdown)
#   install  for install (to install entware)
#
# On Start
# mount on /opt ext2, ext3 or ext4 file system if available on a USB key first partition
# with device name /dev/sda1 or /dev/sdb1
# then executes "/opt/etc/init.d/rc.unslung start" if exists
#
# On Stop
# executes "/opt/etc/init.d/rc.unslung stop" if exists
# unmount /opt if mounted
#
#
#
action=$1
mntpoint="/opt"
dev="/dev/sda1"
mloaded=""

checkModule()
{
    MODULE="$1"
    if lsmod | grep "$MODULE" > /dev/null ; then
	return 0
    else
	return 1
    fi
}

get_fstype()
{
    ext2attr="ext_attr resize_inode dir_index filetype sparse_super"
    ext3attr="has_journal ext_attr resize_inode dir_index filetype sparse_super"
    ext4attr="has_journal ext_attr resize_inode dir_index filetype extent flex_bg sparse_super large_file huge_file uninit_bg dir_nlink extra_isize"
    fstype="unknown"
    fsfeatures=`tune2fs -l $1 | grep "^Filesystem features:" | awk -F: '{print $2}'`

    for i in $ext2attr
    do  if echo $fsfeatures | grep $i > /dev/null
	then echo "ok" > /dev/null
	else return
	fi
    done
    fstype="ext2"

    for i in $ext3attr
    do  if echo $fsfeatures | grep $i > /dev/null
	then echo "ok" > /dev/null
	else return
	fi
    done
    fstype="ext3"

    for i in $ext4attr
    do  if echo $fsfeatures | grep $i > /dev/null
	then echo "ok" > /dev/null
	else return
	fi
    done
    fstype="ext4"
}


# ------ action = shutdown ------------------------------------------------------
if [ "$action" = "shutdown" ]
then
    if [ -x /opt/etc/init.d/rc.unslung ]
    then
	echo "entware.sh: Stopping /opt/etc/init.d/rc.unslung"
	/opt/etc/init.d/rc.unslung stop
	umount /opt
	ret=$?
	if [ "$ret" = "0" ]
	then
	    echo "entware.sh: succesfully unmounted /opt"
	else
	    echo "entware.sh: ERROR unmounting /opt"
	fi
    else
	echo "entware.sh: nothing to do"
    fi
    exit
fi

# ------ action = unsupported  -------------------------------------------------
if [ "$action" != "boot" ] && [ "$action" != "install" ]
then
    echo "entware.sh: unsupported action: $action"
    echo "entware.sh: only supports boot     "
    echo "entware.sh:               shutdwon "
    echo "entware.sh:               install  (for entware installation)"
    exit
fi

# ------ action = boot or install  --------------------------------------------
get_fstype $dev
if [ "$fstype" = "unknown" ]
then
    dev="/dev/sdb1"
    get_fstype $dev
fi

if [ "$fstype" = "unknown" ]
then
    echo "entware.sh: no ext2, ext3 or ext4 file system found on /dev/sda1, missing USB key?"
    exit
fi

echo "entware.sh: fstype: $fstype"

for m in ext2 mbcache jbd jbd2 ext3 ext4
do  checkModule $m
    if [ "$?" = "1" ]
    then
	echo "entware.sh: insmod $m"
	insmod $m
	mloaded="$m $mloaded"
    else
	echo "entware.sh: module $m already loaded"
    fi
done

mount -t $fstype $dev $mntpoint
ret=$?
if [ "$ret" != "0" ]
then
    echo "entware.sh: Error mounting USB Key at $dev"
    exit
fi

if [ -x /opt/etc/init.d/rc.unslung ]
then    
   echo "entware.sh: Starting /opt/etc/init.d/rc.unslung"
   /opt/etc/init.d/rc.unslung start
else
    echo "entware.sh: /opt/etc/init.d/rc.unslung not found"
    echo "entware.sh: entware software not found on /opt"
    echo "entware.sh: unmounting /opt"
    if [ "$action" = "install" ]
    then
	echo "entware.sh: Entware Installation"
	echo "entware.sh: downloading http://bin.entware.net/armv7sf-k3.2/installer/alternative.sh"
	wget http://bin.entware.net/armv7sf-k3.2/installer/alternative.sh -O /tmp/alternative.sh
	ret=$?
	if [ "$ret" = "0" ]
	then
	    echo "entware.sh: installing entware, executing /tmp/alternative.sh"
	    chmod a+x /tmp/alternative.sh
	    /tmp/alternative.sh
	    exit
	fi
    else 
	umount /opt
	ret=$?
	if [ "$ret" = "0" ]
	then
	    echo "entware.sh: succesfully unmounted /opt"
	else
	    echo "entware.sh: ERROR unmounting /opt"
	fi
	echo "entware.sh: unloading loaded kernel modules"
	for m in $mloaded
	do echo "entware.sh: unloading $m"
	   rmmod $m
	done
    fi   
fi
