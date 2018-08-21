# To do list

In implementing new features I will probably follow the following list in no particular order

- [ ] [mod-kit] create a program to patch an unsigned firmware file with the default root password to change the default password

- [ ] [mod-kit] remove the limitation that the size of the new root file system image must be lesser or equal to the size of the original root file system image

- [ ] [mod-kit] remove the limitation that only the DVA-5592_A1_WI_20180405.sig orginal firmware can be modified

- [ ] [confedit] allows where to store the preference settings: in user's home directory (as it is now) or in the `confedit` program directory

- [ ] [confedit] replace string "BSD GUI visible" with "Restricted WEB GUI Visible"

- [ ] [confedit] in the router info section add "Restricted CLI enabled" and its status

- [ ] [confedit] in the router info section add "Fix dlinkdns -> dlinkddns" and its status

- [ ] [confedit] rearrange the router info section:

   * move "Router Customer ID" after "Model Name"
   * move "Router IP" after "Serial Number"
   * move "Router Netmask" after "Router IP"
   * move "Firmware Upgrade Allowed" after "Restricted CLI commands enabled"
   * move "Firmware Downgrade Allowed" after "Firmware Upgrade Allowed"
