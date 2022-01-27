tput setaf 2;
echo "Below script will audit the system for security misconfiguration based on the CIS Benchmark - Checked for Red Hat Linux version 7"
echo "Note: It may create some warnings.";
echo "Script will not modify anyhing on the system"
echo "Starting script...";

tput sgr0;
sleep 1s
echo "."
sleep 1s
echo "" > Output.txt
echo "" >> Output.txt
echo "Find your output below..." >> Output.txt
     

echo "@@@@@@@@@@@1.Ensure no legacy "+" entries exist in /etc/passwd----------------------------------" >> Output.txt
echo "" >> Output.txt
grep '^\+:' /etc/passwd >> Output.txt
echo "@@@@@@@@@@@1.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@2.Boot Directory Permissions----------------------------------------------------------" >> Output.txt
ls -ld /boot >> Output.txt
echo "@@@@@@@@@@@2.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@3.List Of Installed Packages----------------------------------------------------------" >> Output.txt
yum list installed >> Output.txt
#OR
echo "" >> Output.txt
rpm -qa >> Output.txt
echo "@@@@@@@@@@@3.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@4.List Of Open Ports------------------------------------------------------------------" >> Output.txt
netstat -l >> Output.txt
echo "@@@@@@@@@@@4.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@5.Ensure no legacy "+" entries exist in /etc/shadow----------------------------------" >> Output.txt
echo "" >> Output.txt
grep '^\+:' /etc/shadow >> Output.txt
echo "@@@@@@@@@@@5.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt


echo "@@@@@@@@@@@6.Network Parameters in /etc/sysctl.conf---------------------------------------------" >> Output.txt
echo "More Details" >> Output.txt
echo "Verify if IP frowarding disabled " >> Output.txt
echo "Check if Send Packet Redirect Disabled" >> Output.txt
echo "Verify if ICMP Redirect Acceptance is disabled" >> Output.txt
echo "Verify if Bad Error Message Protection is enabled" >> Output.txt
cat /etc/sysctl.conf >>Output.txt
echo "@@@@@@@@@@@6.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt


echo "@@@@@@@@@@@7.Ensure root is the only UID 0 account----------------------------------------------" >> Output.txt
echo "" >> Output.txt
cat /etc/passwd | awk -F: '($3 == 0) { print $1 }' >> Output.txt
echo "@@@@@@@@@@@7.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@8.Verify if User/Group Owner and Permission set on sensitive files-------------------" >> Output.txt

echo "File permissions /etc/anacrontab:" >> Output.txt
ls -l /etc/anacrontab >> Output.txt
echo "" >> Output.txt

echo "File permissions /etc/crontab:" >> Output.txt
ls -l /etc/crontab >> Output.txt
echo "" >> Output.txt

echo "File permissions /etc/cron.hourly:" >> Output.txt
ls -l /etc/cron.hourly >> Output.txt
echo "" >> Output.txt

echo "File permissions /etc/cron.daily:" >> Output.txt
ls -l /etc/cron.daily >> Output.txt
echo "" >> Output.txt

echo "File permissions /etc/cron.weekly:" >> Output.txt
ls -l /etc/cron.weekly >> Output.txt
echo "" >> Output.txt

echo "File permissions /etc/cron.monthly:" >> Output.txt
ls -l /etc/cron.monthly >> Output.txt
echo "" >> Output.txt

echo "File permissions /var/spool/cron:" >> Output.txt
ls -l /var/spool/cron >> Output.txt
echo "" >> Output.txt

echo "File permissions /etc/passwd:" >> Output.txt
ls -l /etc/passwd >> Output.txt
echo "" >> Output.txt

echo "File permissions /etc/group:" >> Output.txt
ls -l /etc/group >> Output.txt
echo "" >> Output.txt

echo "File permissions /etc/shadow:" >> Output.txt
ls -l /etc/shadow >> Output.txt
echo "" >> Output.txt

echo "File permissions /etc/gshadow:" >> Output.txt
ls -l /etc/gshadow >> Output.txt
echo "" >> Output.txt
echo "@@@@@@@@@@@8.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt


echo "@@@@@@@@@@@9.Ensure no legacy "+" entries exist in /etc/group-----------------------------------" >> Output.txt
echo "" >> Output.txt
grep '^\+:' /etc/group >> Output.txt
echo "@@@@@@@@@@@9.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@10.Verify if Root Login Disabled-----------------------------------------------------" >> Output.txt
sudo grep root /etc/shadow >> Output.txt
echo "@@@@@@@@@@@10.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt


echo "@@@@@@@@@@@11.Ensure no ungrouped files or directories exist-------------------------------------" >> Output.txt
echo "" >> Output.txt
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nogroup >> Output.txt
echo "@@@@@@@@@@@11.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt


echo "@@@@@@@@@@@12.Ensure password fields are not empty-----------------------------------------------" >> Output.txt
echo "" >> Output.txt
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -4000 >> Output.txt
echo "@@@@@@@@@@@12.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@13.System Accounting with auditd (auditd configuration)-------------------------------" >> Output.txt
cat /etc/audit/audit.rules >> Output.txt
echo "@@@@@@@@@@@13.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@14.verify if openssh configured correctly---------------------------------------------" >> Output.txt
cat /etc/pki/tls/openssl.cnf  >> Output.txt
echo "@@@@@@@@@@@14.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@15.Verify if Interactive Boot Disabled------------------------------------------------" >> Output.txt
echo "Verify that prompt set to no" >> Output.txt
#cat /etc/sysconfig/init  >> Output.txt
grep PROMPT /etc/sysconfig/init >> Output.txt
echo "@@@@@@@@@@@15.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@16.Verify if Remote Logging enabled Properly------------------------------------------" >> Output.txt
echo "It is necessory to maintain log for user login through remote session." >> Output.txt
cat /etc/rsyslog.conf  >> Output.txt
echo "@@@@@@@@@@@16.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt


echo "@@@@@@@@@@@17.Ensure no unowned files or directories exist---------------------------------------" >> Output.txt
echo "" >> Output.txt
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser >> Output.txt
echo "" >> Output.txt

echo "Files not owned by group "find / -nogroup":" >> Output.txt
find / -nogroup >> Output.txt
echo "" >> Output.txt


echo "@@@@@@@@@@@17.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@18.Separation Of the operating system files-------------------------------------------" >> Output.txt
echo "Make sure the following filesystems are mounted on separate partitions: /usr, /home,/var and /var/tmp,/tmp." >> Output.txt
df -h  >> Output.txt
echo "@@@@@@@@@@@18.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt


echo "@@@@@@@@@@@19.Verify if Disk Quota is enabled for disk-------------------------------------------" >> Output.txt
echo "4th field shows quota type otherwise it is set to defaults." >> Output.txt
cat /etc/fstab  >> Output.txt
echo "@@@@@@@@@@@19.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@20.Verify if IPV6 is enabled though it is not required--------------------------------" >> Output.txt
ifconfig >> Output.txt
lsmod|grep ipv6 >> Output.txt
echo "@@@@@@@@@@@20.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@21.Check for any unnecessary services and daemons at boot time------------------------" >> Output.txt
echo "SysV services at boot time." >> Output.txt
chkconfig --list | grep '3:on' >> Output.txt

echo "Native or systemd services at run time." >> Output.txt
systemctl list-unit-files >> Output.txt
echo "@@@@@@@@@@@21.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt


echo "@@@@@@@@@@@22.Additional process hardening-------------------------------------------------------" >> Output.txt
echo "1) Restrict core dumps:" >> Output.txt
echo "A) verify if hard core 0 in grep @hard core@ /etc/security/limits.conf /etc/security/limits.d/*" >> Output.txt
echo "@ used instead of double quotes in above comment" >> Output.txt
grep "hard core" /etc/security/limits.conf /etc/security/limits.d/* >> Output.txt
echo "" >> Output.txt

echo "B)verify if fs.suid_dumpable = 0  in @sysctl fs.suid_dumpable@" >> Output.txt
echo "In above comment @ used instead of double quotes for writing the same in file using echo." >> Output.txt
sysctl fs.suid_dumpable >> Output.txt


echo "C) verify if fs.suid_dumpable = 0 in grep @fs\.suid_dumpable@ /etc/sysctl.conf /etc/sysctl.d/*" >> Output.txt
echo "In above comment @ used instead of double quotes for writing the same in file using echo." >> Output.txt
grep "fs\.suid_dumpable" /etc/sysctl.conf /etc/sysctl.d/* >> Output.txt

echo "See the output of below command: i.e. 2)Configure Exec Shield:" >> Output.txt
echo "@@@@@@@@@@@22.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@23.Verify if services below are running(FTP(20/21)telnet(23)Rlogin/Rsh(513))----------" >> Output.txt
echo "Verify if "service telnet status" is set to running" >> Output.txt
service telnet status >> Output.txt
echo "" >> Output.txt

echo "Verify if "service ftp status" is set to running" >> Output.txt
service ftp status >> Output.txt
echo "" >> Output.txt

echo "Verify if "service Rlogin status" is set to running" >> Output.txt
service Rlogin status >> Output.txt
echo "" >> Output.txt

echo "Verify if "service Rsh status" is set to running" >> Output.txt
service Rsh status >> Output.txt
echo "" >> Output.txt


echo "@@@@@@@@@@@23.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt


echo "@@@@@@@@@@@24.Ensure mounting of unneeded filesystems is disabled--------------------------------" >> Output.txt
echo "Removing support for unneeded filesystem types reduces the local attack surface of the server. If this filesystem type is not needed, disable it." >> Output.txt

echo "Run the following commands and verify the output is as indicated:" >> Output.txt
echo "# modprobe -n -v cramfs " >> Output.txt
echo "output for above command mainstall /bin/true Or some error" >> Output.txt
echo "# lsmod | grep cramfs" >> Output.txt
echo "<No Output>" >> Output.txt
 
echo "@@@@@@@@@@@24.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt


echo "@@@@@@@@@@@25.Ensure noexec option set on /tmp partition-----------------------------------------" >> Output.txt
echo "If a /tmp partition exists below command and verify that the noexec option is set on /tmp:." >> Output.txt
mount | grep /tmp >> Output.txt
echo "Output can be: tmpfs on /tmp type tmpfs (rw,nosuid,nodev,noexec,relatime)" >> Output.txt
echo "@@@@@@@@@@@25.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@26.Ensure nodev, noexec, nosuid option set on /var/tmp partition--------------------------" >> Output.txt
echo "If a /var/tmp partition exists run below command and verify that the nodev,noexec, nosuid option is set on /var/tmp." >> Output.txt
mount | grep /var/tmp >> Output.txt
echo "Output can be: tmpfs on /var/tmp type tmpfs (rw,nosuid,nodev,noexec,relatime)" >> Output.txt
echo "@@@@@@@@@@@26.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@27.Ensure nodev, noexec, nosuid option set on /dev/shm partition--------------------------" >> Output.txt
echo "If a /var/tmp partition exists run below command and verify that the nodev, noexec, nosuid option is set on /dev/shm." >> Output.txt
mount | grep /dev/shm >> Output.txt
echo "Output can be: tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev,noexec,relatime)" >> Output.txt
echo "@@@@@@@@@@@27.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt


echo "@@@@@@@@@@@28.Ensure noexec, nosuid, nodev option set on removable media partitions--------------" >> Output.txt
echo "Run below command and verify that the nodev, noexec, nosuid option is set on removable media partitions." >> Output.txt
mount >> Output.txt
echo "@@@@@@@@@@@28.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@29.Verify if automounting is enabled--------------------------------------------------" >> Output.txt
echo "Run the following command and verify result is not "enabled":" >> Output.txt
systemctl is-enabled autofs >> Output.txt
echo "If Output is enabled then it is a finding)" >> Output.txt
echo "@@@@@@@@@@@29.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@30.Ensure gpgcheck is globally activated----------------------------------------------" >> Output.txt
echo "Run the following command and verify gpgcheck is set to ' 1 ':" >> Output.txt
grep ^gpgcheck /etc/yum.conf >> Output.txt
echo "" >> Output.txt
grep ^gpgcheck /etc/yum.repos.d/* >> Output.txt
echo "@@@@@@@@@@@30.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@31.Ensure AIDE is installed-----------------------------------------------------------" >> Output.txt
echo "Ensure AIDE is installed." >> Output.txt
rpm -q aide >> Output.txt
echo "@@@@@@@@@@@31.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@32.Ensure filesystem integrity is regularly checked.----------------------------------" >> Output.txt
echo "Run the following commands to determine if there is a cron job scheduled to run the aide check." >> Output.txt
crontab -u root -l | grep aide >> Output.txt
echo "" >> Output.txt
grep -r aide /etc/cron.* /etc/crontab >> Output.txt
echo "" >> Output.txt
echo "Ensure a cron job in compliance with site policy is returned." >> Output.txt
echo "@@@@@@@@@@@32.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt



echo "@@@@@@@@@@@33.Ensure permissions on bootloader config are configured-----------------------------" >> Output.txt
echo "Run the following commands and verify Uid and Gid are both 0/root and Access does not grant permissions to group or other:" >> Output.txt

stat /boot/grub2/grub.cfg >> Output.txt
echo "Expected output : Access: (0600/-rw-------) Uid: ( 0/ root) Gid: ( 0/ root)" >> Output.txt
echo "" >> Output.txt

stat /boot/grub2/user.cfg >> Output.txt
echo "Expected output : Access: (0600/-rw-------) Uid: ( 0/ root) Gid: ( 0/ root)" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@33.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt



echo "@@@@@@@@@@@34.Ensure bootloader password is set--------------------------------------------------" >> Output.txt
grep "^GRUB2_PASSWORD" /boot/grub2/grub.cfg >> Output.txt
echo "Expected output is : GRUB2_PASSWORD=<encrypted-password>." >> Output.txt
echo "@@@@@@@@@@@34.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt


echo "@@@@@@@@@@@35.Ensure authentication required for single user mode--------------------------------" >> Output.txt
echo "Run the following commands and verify that /sbin/sulogin or /usr/sbin/sulogin is used as shown: in expected output" >> Output.txt
grep /sbin/sulogin /usr/lib/systemd/system/rescue.service >> Output.txt
echo "Expected output is : ExecStart=-/bin/sh -c @/sbin/sulogin; /usr/bin/systemctl --fail --no-block default@ " >> Output.txt
echo "In above comment @ used instead of double quotes for writing the same in file using echo." >> Output.txt
echo "" >> Output.txt

grep /sbin/sulogin /usr/lib/systemd/system/emergency.service >> Output.txt
echo "Expected output is : ExecStart=-/bin/sh -c @/sbin/sulogin; /usr/bin/systemctl --fail --no-block default@ ">> Output.txt
echo "In above comment @ used instead of double quotes for writing the same in file using echo." >> Output.txt
echo "@@@@@@@@@@@35.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@36.Ensure address space layout randomization (ASLR) is enabled------------------------" >> Output.txt
echo "Run the following command and verify output matches:" >> Output.txt
sysctl kernel.randomize_va_space >> Output.txt
echo "Expected output is : kernel.randomize_va_space = 2." >> Output.txt
echo "" >> Output.txt
grep "kernel\.randomize_va_space" /etc/sysctl.conf /etc/sysctl.d/* >> Output.txt
echo "Expected output is : kernel.randomize_va_space = 2." >> Output.txt
echo "@@@@@@@@@@@36.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt


Not verified: 

echo "@@@@@@@@@@@37.Ensure prelink is disabled---------------------------------------------------------" >> Output.txt
echo "Run the following command and verify prelink is not installed:" >> Output.txt
rpm -q prelink >> Output.txt
echo "Expected output is : package prelink is not installed" >> Output.txt
echo "@@@@@@@@@@@37.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@38.Ensure SELinux is not disabled in bootloader configuration-------------------------" >> Output.txt
echo "Run the following command and verify that no linux line has the selinux=0 or enforcing=0 parameters set:" >> Output.txt
grep "^\s*linux" /boot/grub2/grub.cfg >> Output.txt
echo "@@@@@@@@@@@38.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@39.Ensure the SELinux state is enforcing-------------------------" >> Output.txt
echo "Run the following commands and ensure output matches:" >> Output.txt
grep SELINUX=enforcing /etc/selinux/config >> Output.txt
echo "Expected output is : SELINUX=enforcing " >> Output.txt
echo "" >> Output.txt

#grep sestatus >> Output.txt
#echo "Expected output is : SELinux status: enabled Current mode: enforcing Mode from config file: enforcing " >> Output.txt
echo "@@@@@@@@@@@39.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@40.Ensure SETroubleshoot is not installed---------------------------------------------" >> Output.txt
echo "Run the following command and verify setroubleshoot is not installed:" >> Output.txt
rpm -q setroubleshoot >> Output.txt
echo "Expected output is : package setroubleshoot is not installed." >> Output.txt
echo "@@@@@@@@@@@40.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@41.Ensure the MCS Translation Service (mcstrans) is not installed---------------------" >> Output.txt
echo "Run the following command and verify mcstrans is not installed:" >> Output.txt
rpm -q mcstrans >> Output.txt
echo "Expected output is : package mcstrans is not installed." >> Output.txt
echo "@@@@@@@@@@@41.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt


echo "@@@@@@@@@@@42.Ensure message of the day is configured properly-----------------------------------" >> Output.txt
echo "Run the following command and verify that the contents match site policy:" >> Output.txt
cat /etc/motd >> Output.txt
echo "" >> Output.txt

echo "Run the following command and verify no results are returned:" >> Output.txt
egrep '(\\v|\\r|\\m|\\s)' /etc/motd >> Output.txt
echo "@@@@@@@@@@@42.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt


echo "@@@@@@@@@@@43.Ensure permissions on /etc/issue are configured------------------------------------" >> Output.txt
echo "Run the following commands to set permissions on /etc/issue :" >> Output.txt
stat /etc/issue >> Output.txt
echo "@@@@@@@@@@@43.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt


echo "@@@@@@@@@@@44.Ensure GDM login banner is configured------------------------------------" >> Output.txt
echo "Check GDM configuration:" >> Output.txt
cat /etc/dconf/profile/gdm >> Output.txt
echo "" >> Output.txt
echo "verify the banner-message-enable and banner-message-text options are configured in one of the files in the /etc/dconf/db/gdm.d/ directory:" >> Output.txt
cat /etc/dconf/db/gdm.d/01-banner-message >> Output.txt
echo "@@@@@@@@@@@44.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt


echo "@@@@@@@@@@@45.Ensure updates, patches, and additional security software are installed------------" >> Output.txt
echo "" >> Output.txt
yum check-update --security >> Output.txt
echo "" >> Output.txt
#OR
yum updateinfo list security all >> Output.txt
echo "" >> Output.txt
#OR
yum updateinfo list sec >> Output.txt
echo "@@@@@@@@@@@45.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@46.Ensure chargen services are not enabled--------------------------------------------" >> Output.txt
echo "Ensure daytime services are not enabled----------------------------------------------------------" >> Output.txt
echo "Ensure discard services are not enabled----------------------------------------------------------" >> Output.txt
echo "Ensure echo services are not enabled-------------------------------------------------------------" >> Output.txt
echo "Ensure time services are not enabled-------------------------------------------------------------" >> Output.txt
echo "Ensure tftp server is not enabled----------------------------------------------------------------" >> Output.txt

echo "" >> Output.txt
chkconfig --list >> Output.txt
echo "@@@@@@@@@@@46.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@47.Ensure xinetd is not enabled-------------------------------------------------------" >> Output.txt
echo "" >> Output.txt
systemctl is-enabled xinetd >> Output.txt
echo "@@@@@@@@@@@47.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@48.Ensure ntp is configured-----------------------------------------------------------" >> Output.txt
echo "" >> Output.txt
grep "^restrict" /etc/ntp.conf >> Output.txt
echo "" >> Output.txt
grep "^(server|pool)" /etc/ntp.conf >> Output.txt
echo "" >> Output.txt
grep "^OPTIONS" /etc/sysconfig/ntpd >> Output.txt
echo "" >> Output.txt
grep "^ExecStart" /usr/lib/systemd/system/ntpd.service >> Output.txt
echo "" >> Output.txt
echo "@@@@@@@@@@@48.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@49.Ensure chrony is configured--------------------------------------------------------" >> Output.txt
echo "" >> Output.txt
grep "^(server|pool)" /etc/chrony.conf >> Output.txt
echo "" >> Output.txt
grep ^OPTIONS /etc/sysconfig/chronyd >> Output.txt
echo "@@@@@@@@@@@49.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@50.Ensure X Window System is not installed--------------------------------------------" >> Output.txt
echo "" >> Output.txt
rpm -qa xorg-x11* >> Output.txt
echo "@@@@@@@@@@@50.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@51.Ensure Avahi Server is not enabled-------------------------------------------------" >> Output.txt
echo "" >> Output.txt
systemctl is-enabled avahi-daemon >> Output.txt
echo "@@@@@@@@@@@51.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@52.Ensure CUPS is not enabled---------------------------------------------------------" >> Output.txt
echo "" >> Output.txt
systemctl is-enabled cups >> Output.txt
echo "@@@@@@@@@@@52.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@53.Ensure DHCP Server is not enabled--------------------------------------------------" >> Output.txt
echo "" >> Output.txt
systemctl is-enabled dhcpd >> Output.txt
echo "@@@@@@@@@@@53.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@54.Ensure LDAP server is not enabled--------------------------------------------------" >> Output.txt
echo "" >> Output.txt
systemctl is-enabled slapd >> Output.txt
echo "@@@@@@@@@@@54.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@55.Ensure NFS and RPC are not enabled-------------------------------------------------" >> Output.txt
echo "" >> Output.txt
systemctl is-enabled nfs >> Output.txt
echo "" >> Output.txt
systemctl is-enabled nfs-server >> Output.txt
echo "" >> Output.txt
systemctl is-enabled rpcbind >> Output.txt
echo "@@@@@@@@@@@55.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@56.Ensure DNS Server is not enabled---------------------------------------------------" >> Output.txt
echo "" >> Output.txt
systemctl is-enabled named >> Output.txt
echo "@@@@@@@@@@@56.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@57.Ensure FTP Server is not enabled---------------------------------------------------" >> Output.txt
echo "" >> Output.txt
systemctl is-enabled vsftpd >> Output.txt
echo "@@@@@@@@@@@57.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@58.Ensure HTTP server is not enabled--------------------------------------------------" >> Output.txt
echo "" >> Output.txt
systemctl is-enabled httpd >> Output.txt
echo "@@@@@@@@@@@58.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@59.Ensure IMAP and POP3 server is not enabled-----------------------------------------" >> Output.txt
echo "" >> Output.txt
systemctl is-enabled dovecot >> Output.txt
echo "@@@@@@@@@@@59.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@60.Ensure Samba is not enabled--------------------------------------------------------" >> Output.txt
echo "" >> Output.txt
systemctl is-enabled smb >> Output.txt
echo "@@@@@@@@@@@5960.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@61.Ensure HTTP Proxy Server is not enabled----------------------------------------------" >> Output.txt
echo "" >> Output.txt
systemctl is-enabled squid >> Output.txt
echo "@@@@@@@@@@@61.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@62.Ensure SNMP Server is not enabled--------------------------------------------------" >> Output.txt
echo "" >> Output.txt
systemctl is-enabled snmpd >> Output.txt
echo "@@@@@@@@@@@62.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@63.Ensure mail transfer agent is configured for local-only mode-----------------------" >> Output.txt
echo "" >> Output.txt
netstat -an | grep LIST | grep ":25[[:space:]]" >> Output.txt
echo "@@@@@@@@@@@63.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@64.Ensure NIS Server is not enabled---------------------------------------------------" >> Output.txt
echo "" >> Output.txt
systemctl is-enabled ypserv >> Output.txt
echo "@@@@@@@@@@@64.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@65.Ensure rsh server is not enabled---------------------------------------------------" >> Output.txt
echo "" >> Output.txt
systemctl is-enabled rsh.socket >> Output.txt
echo "" >> Output.txt
systemctl is-enabled rlogin.socket >> Output.txt
echo "" >> Output.txt
systemctl is-enabled rexec.socket >> Output.txt
echo "" >> Output.txt
echo "@@@@@@@@@@@65.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@66.Ensure talk server is not enabled--------------------------------------------------" >> Output.txt
echo "" >> Output.txt
systemctl is-enabled ntalk >> Output.txt
echo "@@@@@@@@@@@66.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@67.Ensure telnet server is not enabled------------------------------------" >> Output.txt
echo "" >> Output.txt
systemctl is-enabled telnet.socket >> Output.txt
echo "@@@@@@@@@@@67.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@68.Ensure tftp server is not enabled--------------------------------------------------" >> Output.txt
echo "" >> Output.txt
systemctl is-enabled tftp.socket >> Output.txt
echo "@@@@@@@@@@@68.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@69.Ensure rsync service is not enabled------------------------------------------------" >> Output.txt
echo "" >> Output.txt
systemctl is-enabled rsyncd >> Output.txt
echo "@@@@@@@@@@@69.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@70.Ensure NIS Client is not installed-------------------------------------------------" >> Output.txt
echo "" >> Output.txt
rpm -q ypbind >> Output.txt
echo "@@@@@@@@@@@70.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt



echo "@@@@@@@@@@@71.Ensure rsh client is not installed------------------------------------------------" >> Output.txt
echo "" >> Output.txt
rpm -q rsh >> Output.txt
echo "@@@@@@@@@@@71.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@72.Ensure talk client is not installed------------------------------------------------" >> Output.txt
echo "" >> Output.txt
rpm -q talk >> Output.txt
echo "@@@@@@@@@@@72.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@73.Ensure telnet client is not installed----------------------------------------------" >> Output.txt
echo "" >> Output.txt
rpm -q telnet >> Output.txt
echo "@@@@@@@@@@@73.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@74.Ensure LDAP client is not installed------------------------------------------------" >> Output.txt
echo "" >> Output.txt
rpm -q openldap-clients >> Output.txt
echo "@@@@@@@@@@@74.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@75.Ensure IP forwarding is disabled---------------------------------------------------" >> Output.txt
echo "" >> Output.txt
sysctl net.ipv4.ip_forward >> Output.txt
echo "" >> Output.txt
grep "net\.ipv4\.ip_forward" /etc/sysctl.conf /etc/sysctl.d/* >> Output.txt
echo "@@@@@@@@@@@75.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@76.Ensure packet redirect sending is disabled-----------------------------------------" >> Output.txt
echo "" >> Output.txt
sysctl net.ipv4.conf.all.send_redirects >> Output.txt
echo "" >> Output.txt
sysctl net.ipv4.conf.default.send_redirects >> Output.txt
echo "" >> Output.txt
grep "net\.ipv4\.conf\.all\.send_redirects" /etc/sysctl.conf /etc/sysctl.d/* >> Output.txt
echo "" >> Output.txt
grep "net\.ipv4\.conf\.default\.send_redirects" /etc/sysctl.conf /etc/sysctl.d/* >> Output.txt
echo "" >> Output.txt
echo "@@@@@@@@@@@76.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@77.Ensure source routed packets are not accepted--------------------------------------" >> Output.txt
echo "" >> Output.txt
sysctl net.ipv4.conf.all.accept_source_route >> Output.txt
echo "" >> Output.txt
sysctl net.ipv4.conf.default.accept_source_route >> Output.txt
echo "" >> Output.txt
grep "net\.ipv4\.conf\.all\.accept_source_route" /etc/sysctl.conf >> Output.txt
echo "" >> Output.txt
grep "net\.ipv4\.conf\.default\.accept_source_route" /etc/sysctl.conf /etc/sysctl.d/* >> Output.txt
echo "" >> Output.txt
echo "@@@@@@@@@@@77.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@78.Ensure ICMP redirects are not accepted--------------------------------------------" >> Output.txt
echo "" >> Output.txt
sysctl net.ipv4.conf.all.accept_redirects >> Output.txt
echo "" >> Output.txt
sysctl net.ipv4.conf.default.accept_redirects >> Output.txt
echo "" >> Output.txt
grep "net\.ipv4\.conf\.all\.accept_redirects" /etc/sysctl.conf /etc/sysctl.d/* >> Output.txt
echo "" >> Output.txt
grep "net\.ipv4\.conf\.default\.accept_redirects" /etc/sysctl.conf /etc/sysctl.d/* >> Output.txt
echo "" >> Output.txt
echo "@@@@@@@@@@@78.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@79.Ensure secure ICMP redirects are not accepted--------------------------------------" >> Output.txt
echo "" >> Output.txt
sysctl net.ipv4.conf.all.secure_redirects >> Output.txt
echo "" >> Output.txt
grep "net\.ipv4\.conf\.all\.secure_redirects" /etc/sysctl.conf /etc/sysctl.d/* >> Output.txt
echo "" >> Output.txt
grep "net\.ipv4\.conf\.default\.secure_redirects" /etc/sysctl.conf /etc/sysctl.d/* >> Output.txt
echo "" >> Output.txt
echo "@@@@@@@@@@@79.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@80.Ensure suspicious packets are logged-----------------------------------------------" >> Output.txt
echo "" >> Output.txt
sysctl net.ipv4.conf.all.log_martians >> Output.txt
echo "" >> Output.txt
sysctl net.ipv4.conf.default.log_martians >> Output.txt
echo "" >> Output.txt
grep "net\.ipv4\.conf\.all\.log_martians" /etc/sysctl.conf /etc/sysctl.d/* >> Output.txt
echo "" >> Output.txt
grep "net\.ipv4\.conf\.default\.log_martians" /etc/sysctl.conf /etc/sysctl.d/* >> Output.txt
echo "@@@@@@@@@@@80.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

#81 was repeated
#Now replaced with new one

echo "@@@@@@@@@@@81.Ensure SSH access is limited-------------------------------------------------------" >> Output.txt
echo "" >> Output.txt
grep "^AllowUsers" /etc/ssh/sshd_config >> Output.txt
echo "" >> Output.txt
grep "^AllowGroups" /etc/ssh/sshd_config >> Output.txt
echo "" >> Output.txt
grep "^DenyUsers" /etc/ssh/sshd_config >> Output.txt
echo "" >> Output.txt
grep "^DenyGroups" /etc/ssh/sshd_config >> Output.txt
echo "" >> Output.txt
echo "@@@@@@@@@@@81.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

#82 was repeated
# now placed from 166

echo "@@@@@@@@@@@82.Ensure no world writable files exist-----------------------------------------------" >> Output.txt
echo "" >> Output.txt
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -0002 >> Output.txt
echo "" >> Output.txt
#find <partition> -xdev -type f -perm -0002 >> Output.txt
echo "@@@@@@@@@@@82.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt


echo "@@@@@@@@@@@83.Ensure broadcast ICMP requests are ignored-----------------------------------------" >> Output.txt
echo "" >> Output.txt
sysctl net.ipv4.icmp_echo_ignore_broadcasts >> Output.txt
echo "" >> Output.txt
grep "net\.ipv4\.icmp_echo_ignore_broadcasts" /etc/sysctl.conf /etc/sysctl.d/* >> Output.txt
echo "" >> Output.txt
echo "@@@@@@@@@@@83.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@84.Ensure bogus ICMP responses are ignored--------------------------------------------" >> Output.txt
echo "" >> Output.txt
sysctl net.ipv4.icmp_ignore_bogus_error_responses net.ipv4.icmp_ignore_bogus_error_responses = 1  >> Output.txt
echo "" >> Output.txt
grep "net\.ipv4\.icmp_ignore_bogus_error_responses" /etc/sysctl.conf /etc/sysctl.d/* >> Output.txt
echo "" >> Output.txt
echo "@@@@@@@@@@@84.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@85.Ensure Reverse Path Filtering is enabled-------------------------------------------" >> Output.txt
echo "" >> Output.txt >> Output.txt
sysctl net.ipv4.conf.all.rp_filter >> Output.txt
echo "" >> Output.txt
sysctl net.ipv4.conf.default.rp_filter >> Output.txt
echo "" >> Output.txt
grep "net\.ipv4\.conf\.all\.rp_filter" /etc/sysctl.conf /etc/sysctl.d/* >> Output.txt
echo "" >> Output.txt
grep "net\.ipv4\.conf\.default\.rp_filter" /etc/sysctl.conf /etc/sysctl.d/* >> Output.txt
echo "" >> Output.txt
echo "@@@@@@@@@@@85.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@86.Ensure TCP SYN Cookies is enabled--------------------------------------------------" >> Output.txt
echo "" >> Output.txt
sysctl net.ipv4.tcp_syncookies >> Output.txt
echo "" >> Output.txt
grep "net\.ipv4\.tcp_syncookies" /etc/sysctl.conf /etc/sysctl.d/* >> Output.txt
echo "" >> Output.txt
echo "@@@@@@@@@@@86.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@87.Ensure TCP Wrappers is installed---------------------------------------------------" >> Output.txt
echo "" >> Output.txt
rpm -q tcp_wrappers >> Output.txt
echo "" >> Output.txt
rpm -q tcp_wrappers-libs >> Output.txt
echo "@@@@@@@@@@@87.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@88.Ensure /etc/hosts.allow is configured----------------------------------------------" >> Output.txt
echo "" >> Output.txt
cat /etc/hosts.allow >> Output.txt
echo "@@@@@@@@@@@88.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@89.Ensure /etc/hosts.deny is configured----------------------------------------------" >> Output.txt
echo "" >> Output.txt
cat /etc/hosts.deny >> Output.txt
echo "@@@@@@@@@@@89.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@90.Ensure permissions on /etc/hosts.allow are configured------------------------------" >> Output.txt
echo "" >> Output.txt
stat /etc/hosts.allow >> Output.txt
echo "@@@@@@@@@@@90.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@91.Ensure permissions on /etc/hosts.deny are configured-------------------------------" >> Output.txt
echo "" >> Output.txt
stat /etc/hosts.deny >> Output.txt
echo "@@@@@@@@@@@91.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@92.Ensure iptables is installed-------------------------------------------------------" >> Output.txt
echo "" >> Output.txt
rpm -q iptables >> Output.txt
echo "@@@@@@@@@@@92.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@93.Check if firewall policy enabled and Ensure default deny firewall policy-----------" >> Output.txt
echo "" >> Output.txt
iptables -L >> Output.txt
echo "@@@@@@@@@@@93.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@94.Ensure loopback traffic is configured----------------------------------------------" >> Output.txt
echo "" >> Output.txt
iptables -L INPUT -v -n >> Output.txt
echo "" >> Output.txt
iptables -L OUTPUT -v -n >> Output.txt
echo "@@@@@@@@@@@94.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@95.Ensure firewall rules exist for all open ports------------------------------------" >> Output.txt
echo "" >> Output.txt
netstat -ln >> Output.txt
echo "@@@@@@@@@@@95.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@96.Ensure system is disabled when audit logs are full---------------------------------" >> Output.txt
echo "" >> Output.txt
grep space_left_action /etc/audit/auditd.conf >> Output.txt
echo "" >> Output.txt
grep action_mail_acct /etc/audit/auditd.conf >> Output.txt
echo "" >> Output.txt
grep admin_space_left_action /etc/audit/auditd.conf >> Output.txt
echo "" >> Output.txt
echo "@@@@@@@@@@@96.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@97.Ensure audit logs are not automatically deleted------------------------------------" >> Output.txt
echo "" >> Output.txt
grep max_log_file_action /etc/audit/auditd.conf >> Output.txt
echo "@@@@@@@@@@@97.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@98.Ensure auditd service is enabled---------------------------------------------------" >> Output.txt
echo "" >> Output.txt
systemctl is-enabled auditd >> Output.txt
echo "@@@@@@@@@@@98.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@99.Ensure auditing for processes that start prior to auditd is enabled----------------" >> Output.txt
echo "" >> Output.txt
grep "^\s*linux" /boot/grub2/grub.cfg >> Output.txt
echo "@@@@@@@@@@@99.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@100.Ensure events that modify date and time information are collected----------------" >> Output.txt
echo "" >> Output.txt
grep time-change /etc/audit/audit.rules >> Output.txt
echo "" >> Output.txt
auditctl -l | grep time-change >> Output.txt
echo "" >> Output.txt
grep time-change /etc/audit/audit.rules >> Output.txt
echo "" >> Output.txt
auditctl -l | grep time-change >> Output.txt
echo "" >> Output.txt
echo "@@@@@@@@@@@100.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@101.Ensure events that modify user/group information are collected---------------------" >> Output.txt
echo "" >> Output.txt
grep identity /etc/audit/audit.rules >> Output.txt
echo "" >> Output.txt
auditctl -l | grep identity >> Output.txt
echo "" >> Output.txt
echo "@@@@@@@@@@@101.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@102.Ensure events that modify the system's network environment are collected----------" >> Output.txt
echo "" >> Output.txt
grep system-locale /etc/audit/audit.rules >> Output.txt
echo "" >> Output.txt
auditctl -l | grep system-locale >> Output.txt
echo "" >> Output.txt
echo "@@@@@@@@@@@102.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@103.Ensure events that modify the system's Mandatory Access Controls are collected-----" >> Output.txt
echo "" >> Output.txt
grep MAC-policy /etc/audit/audit.rules >> Output.txt
echo "@@@@@@@@@@@103.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@104.Ensure login and logout events are collected---------------------------------------" >> Output.txt
echo "" >> Output.txt
grep logins /etc/audit/audit.rules >> Output.txt
echo "@@@@@@@@@@@104.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@104.Ensure session initiation information is collected---------------------------------" >> Output.txt
echo "" >> Output.txt
grep session /etc/audit/audit.rules >> Output.txt
echo "" >> Output.txt
auditctl -l | grep session >> Output.txt
echo "" >> Output.txt
grep logins /etc/audit/audit.rules >> Output.txt
echo "" >> Output.txt
auditctl -l | grep logins >> Output.txt
echo "" >> Output.txt
echo "@@@@@@@@@@@104.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@105.Ensure discretionary access control permission modification events are collected---" >> Output.txt
echo "" >> Output.txt
grep perm_mod /etc/audit/audit.rules  >> Output.txt
echo "" >> Output.txt
auditctl -l | grep perm_mod >> Output.txt
echo "" >> Output.txt
echo "@@@@@@@@@@@105.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@106.Ensure unsuccessful unauthorized file access attempts are collected----------------" >> Output.txt
echo "" >> Output.txt
grep access /etc/audit/audit.rules >> Output.txt
echo "" >> Output.txt
auditctl -l | grep access >> Output.txt
echo "" >> Output.txt
grep access /etc/audit/audit.rules >> Output.txt
echo "" >> Output.txt
auditctl -l | grep access >> Output.txt

echo "@@@@@@@@@@@106.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@107.Ensure use of privileged commands is collected-------------------------------------" >> Output.txt
echo "List of disk partition:" >> Output.txt
fdisk -l >> Output.txt
echo "" >> Output.txt
#After getting list of the partition 
#find <partition> -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print \ "-a always,exit -F path=" $1 " -F perm=x -F auid>=1000 -F auid!=4294967295 \ -k privileged" }'>> Output.txt
echo "@@@@@@@@@@@107.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@108.Ensure successful file system mounts are collected---------------------------------" >> Output.txt
echo "" >> Output.txt
grep mounts /etc/audit/audit.rules  >> Output.txt
echo "" >> Output.txt
auditctl -l | grep mounts >> Output.txt
echo "" >> Output.txt
echo "@@@@@@@@@@@108.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@109.Ensure file deletion events by users are collected---------------------------------" >> Output.txt
echo "" >> Output.txt
grep delete /etc/audit/audit.rules  >> Output.txt
echo "" >> Output.txt
auditctl -l | grep delete >> Output.txt
echo "" >> Output.txt
grep delete /etc/audit/audit.rules  >> Output.txt
echo "" >> Output.txt
auditctl -l | grep delete >> Output.txt
echo "@@@@@@@@@@@109.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@110.Ensure changes to system administration scope (sudoers) is collected---------------" >> Output.txt
echo "" >> Output.txt
grep scope /etc/audit/audit.rules >> Output.txt
echo "" >> Output.txt

auditctl -l | grep scope >> Output.txt
echo "" >> Output.txt
echo "@@@@@@@@@@@110.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@111.Ensure system administrator actions (sudolog) are collected------------------------" >> Output.txt
echo "" >> Output.txt
grep actions /etc/audit/audit.rules >> Output.txt
echo "" >> Output.txt

auditctl -l | grep actions >> Output.txt
echo "@@@@@@@@@@@111.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@112.Ensure kernel module loading and unloading is collected----------------------------" >> Output.txt
echo "" >> Output.txt
grep modules /etc/audit/audit.rules >> Output.txt
echo "" >> Output.txt
 
auditctl -l | grep modules >> Output.txt
echo "@@@@@@@@@@@112.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@113.Ensure the audit configuration is immutable----------------------------------------" >> Output.txt
echo "" >> Output.txt
grep "^\s*[^#]" /etc/audit/audit.rules | tail -1 >> Output.txt
echo "@@@@@@@@@@@113.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@114.Ensure rsyslog Service is enabled--------------------------------------------------" >> Output.txt
echo "" >> Output.txt
systemctl is-enabled rsyslog >> Output.txt
echo "@@@@@@@@@@@114.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@115.Ensure logging is configured--------------------------------------------------------" >> Output.txt
echo "" >> Output.txt
ls -l /var/log/ >> Output.txt
echo "" >> Output.txt
cat /etc/syslog-ng/syslog-ng.conf >> Output.txt
echo "@@@@@@@@@@@115.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@116.Ensure rsyslog default file permissions configured---------------------------------" >> Output.txt
echo "" >> Output.txt
grep ^\$FileCreateMode /etc/rsyslog.conf /etc/rsyslog.d/*.conf >> Output.txt
echo "@@@@@@@@@@@116.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@117.Ensure rsyslog is configured to send logs to a remote log host---------------------" >> Output.txt
echo "" >> Output.txt
grep "^*.*[^I][^I]*@" /etc/rsyslog.conf /etc/rsyslog.d/*.conf >> Output.txt
echo "@@@@@@@@@@@117.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@118.Ensure syslog-ng service is enabled------------------------------------------------" >> Output.txt
echo "" >> Output.txt
#if syslog-ng is installed then only we can check for this config
systemctl is-enabled syslog-ng >> Output.txt
echo "@@@@@@@@@@@118.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@119.Ensure syslog-ng default file permissions configured-------------------------------" >> Output.txt
echo "" >> Output.txt
#if syslog-ng is installed then only we can check for this config
grep ^options /etc/syslog-ng/syslog-ng.conf >> Output.txt
echo "@@@@@@@@@@@119.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@120.Ensure rsyslog or syslog-ng is installed-------------------------------------------" >> Output.txt
echo "" >> Output.txt
rpm -q rsyslog >> Output.txt
echo "" >> Output.txt
rpm -q syslog-ng >> Output.txt
echo "@@@@@@@@@@@120.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@121.Ensure permissions on all logfiles are configured----------------------------------" >> Output.txt
echo "" >> Output.txt

find /var/log -type f -ls >> Output.txt
echo "@@@@@@@@@@@121.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@122.Ensure cron daemon is enabled------------------------------------------------------" >> Output.txt
echo "" >> Output.txt
systemctl is-enabled crond >> Output.txt
echo "@@@@@@@@@@@122.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@123.Ensure permissions on /etc/crontab are configured----------------------------------" >> Output.txt
echo "" >> Output.txt
stat /etc/crontab >> Output.txt
echo "@@@@@@@@@@@123.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@124.Ensure permissions on /etc/cron.hourly are configured------------------------------" >> Output.txt
echo "" >> Output.txt
stat /etc/cron.hourly >> Output.txt
echo "@@@@@@@@@@@124.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@125.Ensure permissions on /etc/cron.daily are configured-------------------------------" >> Output.txt
echo "" >> Output.txt
stat /etc/cron.daily >> Output.txt
echo "@@@@@@@@@@@125.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@126.Ensure permissions on /etc/cron.weekly are configured------------------------------" >> Output.txt
echo "" >> Output.txt
stat /etc/cron.weekly >> Output.txt
echo "@@@@@@@@@@@126.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@127.Ensure permissions on /etc/cron.monthly are configured-----------------------------" >> Output.txt
echo "" >> Output.txt
stat /etc/cron.monthly >> Output.txt
echo "@@@@@@@@@@@127.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@128.Ensure permissions on /etc/cron.d are configured-----------------------------------" >> Output.txt
echo "" >> Output.txt
 stat /etc/cron.d>> Output.txt
echo "@@@@@@@@@@@128.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@129.Ensure at/cron is restricted to authorized users-----------------------------------" >> Output.txt
echo "" >> Output.txt
stat /etc/cron.deny >> Output.txt
echo "" >> Output.txt
stat /etc/at.deny >> Output.txt
echo "" >> Output.txt
stat /etc/cron.allow >> Output.txt
echo "" >> Output.txt
stat /etc/at.allow >> Output.txt
echo "" >> Output.txt
echo "@@@@@@@@@@@129.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@130.Ensure permissions on /etc/ssh/sshd_config are configured--------------------------" >> Output.txt
echo "" >> Output.txt
stat /etc/ssh/sshd_config >> Output.txt
echo "@@@@@@@@@@@130.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@131.Ensure SSH Protocol is set to 2----------------------------------------------------" >> Output.txt
echo "" >> Output.txt
grep "^Protocol" /etc/ssh/sshd_config >> Output.txt
echo "@@@@@@@@@@@131.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@132.Ensure SSH LogLevel is set to INFO-------------------------------------------------" >> Output.txt
echo "" >> Output.txt
grep "^LogLevel" /etc/ssh/sshd_config >> Output.txt
echo "@@@@@@@@@@@132.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@133.Ensure SSH X11 forwarding is disabled----------------------------------------------" >> Output.txt
echo "" >> Output.txt
grep "^X11Forwarding" /etc/ssh/sshd_config >> Output.txt
echo "@@@@@@@@@@@133.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@134.Ensure SSH MaxAuthTries is set to 4 or less----------------------------------------" >> Output.txt
echo "" >> Output.txt
grep "^MaxAuthTries" /etc/ssh/sshd_config >> Output.txt
echo "@@@@@@@@@@@134.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@135.Ensure SSH IgnoreRhosts is enabled-------------------------------------------------" >> Output.txt
echo "" >> Output.txt
grep "^IgnoreRhosts" /etc/ssh/sshd_config >> Output.txt
echo "@@@@@@@@@@@135.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@136.Ensure SSH HostbasedAuthentication is disabled-------------------------------------" >> Output.txt
echo "" >> Output.txt
grep "^HostbasedAuthentication" /etc/ssh/sshd_config >> Output.txt
echo "@@@@@@@@@@@136.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@137.Ensure SSH root login is disabled--------------------------------------------------" >> Output.txt
echo "" >> Output.txt
grep "^PermitRootLogin" /etc/ssh/sshd_config >> Output.txt
echo "@@@@@@@@@@@137.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@138.Ensure SSH PermitEmptyPasswords is disabled----------------------------------------" >> Output.txt
echo "" >> Output.txt
grep "^PermitEmptyPasswords" /etc/ssh/sshd_config >> Output.txt
echo "@@@@@@@@@@@138.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@139.Ensure SSH PermitUserEnvironment is disabled---------------------------------------" >> Output.txt
echo "" >> Output.txt
grep PermitUserEnvironment /etc/ssh/sshd_config >> Output.txt
echo "@@@@@@@@@@@139.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@140.Ensure only approved MAC algorithms are used---------------------------------------" >> Output.txt
echo "" >> Output.txt
grep "MACs" /etc/ssh/sshd_config >> Output.txt
echo "@@@@@@@@@@@140.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@141.Ensure SSH Idle Timeout Interval is configured-------------------------------------" >> Output.txt
echo "" >> Output.txt
grep "^ClientAliveInterval" /etc/ssh/sshd_config  >> Output.txt
echo "" >> Output.txt

grep "^ClientAliveCountMax" /etc/ssh/sshd_config >> Output.txt
echo "@@@@@@@@@@@141.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@142.Ensure SSH LoginGraceTime is set to one minute or less-----------------------------" >> Output.txt
grep "^LoginGraceTime" /etc/ssh/sshd_config >> Output.txt
echo "" >> Output.txt
echo "@@@@@@@@@@@142.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@143.Ensure SSH warning banner is configured--------------------------------------------" >> Output.txt
echo "" >> Output.txt
grep "^Banner" /etc/ssh/sshd_config >> Output.txt
echo "@@@@@@@@@@@143.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@144.Ensure password creation requirements are configured-------------------------------" >> Output.txt
echo "" >> Output.txt
grep pam_pwquality.so /etc/pam.d/password-auth 
echo "" >> Output.txt
grep pam_pwquality.so /etc/pam.d/system-auth 
echo "" >> Output.txt
grep ^minlen /etc/security/pwquality.conf 
echo "" >> Output.txt
grep ^dcredit /etc/security/pwquality.conf 
echo "" >> Output.txt
grep ^lcredit /etc/security/pwquality.conf 
echo "" >> Output.txt
grep ^ocredit /etc/security/pwquality.conf 
echo "" >> Output.txt
grep ^ucredit /etc/security/pwquality.conf  >> Output.txt
echo "@@@@@@@@@@@144.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@145.Ensure lockout for failed password attempts is configured--------------------------" >> Output.txt
echo "" >> Output.txt
cat /etc/pam.d/password-auth >> Output.txt
echo "" >> Output.txt
cat /etc/pam.d/system-authcat /etc/pam.d/system-auth >> Output.txt
echo "@@@@@@@@@@@145.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@146.Ensure password reuse is limited---------------------------------------------------" >> Output.txt
echo "" >> Output.txt
egrep '^password\s+sufficient\s+pam_unix.so' /etc/pam.d/password-auth  >> Output.txt
echo "" >> Output.txt
egrep '^password\s+sufficient\s+pam_unix.so' /etc/pam.d/system-auth >> Output.txt
echo "@@@@@@@@@@@146.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@147.Ensure password hashing algorithm is SHA-512---------------------------------------" >> Output.txt
echo "" >> Output.txt
egrep '^password\s+sufficient\s+pam_unix.so' /etc/pam.d/password-auth >> Output.txt
echo "" >> Output.txt
egrep '^password\s+sufficient\s+pam_unix.so' /etc/pam.d/system-auth >> Output.txt
echo "@@@@@@@@@@@147.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@148.Ensure password expiration is 365 days or less----------------" >> Output.txt
echo "" >> Output.txt
grep PASS_MAX_DAYS /etc/login.defs >> Output.txt
echo "" >> Output.txt
egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1 >> Output.txt
echo "@@@@@@@@@@@148.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@149.Ensure minimum days between password changes is 7 or more--------------------------" >> Output.txt
echo "" >> Output.txt
grep PASS_MIN_DAYS /etc/login.defs >> Output.txt
echo "" >> Output.txt
egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1 >> Output.txt
echo "" >> Output.txt
echo "@@@@@@@@@@@149.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@150.Ensure password expiration warning days is 7 or more-------------------------------" >> Output.txt
echo "" >> Output.txt
grep PASS_WARN_AGE /etc/login.defs >> Output.txt
echo "" >> Output.txt

egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1 >> Output.txt
echo "@@@@@@@@@@@150.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@151.Ensure inactive password lock is 30 days or less-----------------------------------" >> Output.txt
echo "" >> Output.txt
useradd -D | grep INACTIVE >> Output.txt
echo "" >> Output.txt
egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1 >> Output.txt
echo "@@@@@@@@@@@151.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@152.Ensure all users last password change date is in the past--------------------------" >> Output.txt
echo "" >> Output.txt
cat /etc/shadow | cut -d: -f1 >> Output.txt
echo "@@@@@@@@@@@152.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@153.Ensure system accounts are non-login-----------------------------------------------" >> Output.txt
echo "" >> Output.txt
egrep -v "^\+" /etc/passwd | awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3<1000 && $7!="/sbin/nologin" && $7!="/bin/false") {print}' >> Output.txt
echo "@@@@@@@@@@@153.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@154.Ensure default group for the root account is GID 0---------------------------------" >> Output.txt
echo "" >> Output.txt
grep "^root:" /etc/passwd | cut -f4 -d: >> Output.txt
echo "@@@@@@@@@@@154.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@155.Ensure default user umask is 027 or more restrictive-------------------------------" >> Output.txt
echo "" >> Output.txt
grep "umask" /etc/bashrc >> Output.txt
echo "" >> Output.txt
grep "umask" /etc/profile /etc/profile.d/*.sh >> Output.txt
echo "@@@@@@@@@@@155.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@156.Ensure default user shell timeout is 900 seconds or less---------------------------" >> Output.txt
echo "" >> Output.txt
grep "^TMOUT" /etc/bashrc >> Output.txt
echo "" >> Output.txt
grep "^TMOUT" /etc/profile >> Output.txt
echo "@@@@@@@@@@@156.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@157.Ensure access to the su command is restricted--------------------------------------" >> Output.txt
echo "" >> Output.txt
grep pam_wheel.so /etc/pam.d/su >> Output.txt
echo "" >> Output.txt
grep wheel /etc/group >> Output.txt
echo "@@@@@@@@@@@157.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@158.Ensure permissions on /etc/passwd are configured-----------------------------------" >> Output.txt
echo "" >> Output.txt
stat /etc/passwd >> Output.txt
echo "@@@@@@@@@@@158.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@159.Ensure permissions on /etc/shadow are configured-----------------------------------" >> Output.txt
echo "" >> Output.txt
stat /etc/shadow >> Output.txt
echo "@@@@@@@@@@@159.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@160.Ensure permissions on /etc/group are configured------------------------------------" >> Output.txt
echo "" >> Output.txt
stat /etc/group >> Output.txt
echo "@@@@@@@@@@@160.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@161.Ensure permissions on /etc/gshadow are configured----------------------------------" >> Output.txt
echo "" >> Output.txt
stat /etc/gshadow >> Output.txt
echo "@@@@@@@@@@@161.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@162.Ensure permissions on /etc/passwd- are configured----------------------------------" >> Output.txt
echo "" >> Output.txt
stat /etc/passwd- >> Output.txt
echo "@@@@@@@@@@@162.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@163.Ensure permissions on /etc/shadow- are configured----------------------------------" >> Output.txt
echo "" >> Output.txt
stat /etc/shadow- >> Output.txt
echo "@@@@@@@@@@@163.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@164.Ensure permissions on /etc/group- are configured----------------" >> Output.txt
echo "" >> Output.txt
stat /etc/group- >> Output.txt
echo "@@@@@@@@@@@164.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@165.Ensure permissions on /etc/gshadow- are configured---------------------------------" >> Output.txt
echo "" >> Output.txt
stat /etc/gshadow- >> Output.txt
echo "@@@@@@@@@@@165.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@166.Ensure separate partition exists for /var/log--------------------------------------" >> Output.txt
echo "" >> Output.txt
mount | grep /var/log >> Output.txt
echo "@@@@@@@@@@@166.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt

echo "@@@@@@@@@@@167.Ensure separate partition exists for /var/log/audit--------------------------------" >> Output.txt
echo "" >> Output.txt
mount | grep /var/log/audit >> Output.txt
echo "@@@@@@@@@@@167.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt


echo "@@@@@@@@@@@168.Ensure nodev option set on /home partition-----------------------------------------" >> Output.txt
echo "" >> Output.txt
mount | grep /home >> Output.txt
echo "@@@@@@@@@@@168.Current Check Completed------------------------------------------------------------" >> Output.txt
echo "" >> Output.txt


echo "."
sleep 4s
tput setaf 2;
echo "Audit Completed"
sleep 4s
echo "Output file generated: Output.txt"
sleep 2s
tput sgr0;

