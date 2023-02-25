#!/bin/bash

# Basic linux enumeration script. Save informations to enumeration folder. Save searchsploit researches to searchsploit folder.

# Documentation: 
# https://book.hacktricks.xyz/linux-hardening/privilege-escalation
# https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/
# https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md


# Found and export different os infos: environment/kernel/mount/cronjobs

# Check Package management installed 
if [ -e $apt ]; then pm="apt"; fi
if [ -e $rpm ]; then pm="rpm"; fi
if [ -e $pacman ]; then pm="pacman"; fi

enum_system()
{
	# global infos
	env 2>/dev/null 1>./enumeration/system/env.txt
	history 2>/dev/null 1>./enumeration/system/history_cmd.txt
	lscpu 2>/dev/null 1>./enumeration/system/cpu.txt
        dmesg 2>/dev/null 1>./enumeration/system/dmesg.txt
	if [ -e $awk ]; then
		echo 'awk available'; echo ' '	
	else 
		echo 'awk unavailable, installing'; 
		if [ "$pm" == "apt" ]; then sudo apt install gawk -y &>/dev/null; fi;		
		if [ "$pm" == "rpm" ]; then sudo rpm -i gawk -y &>/dev/null; fi;		
		if [ "$pm" == "pacman" ]; then sudo pacman -S gawk -y &>/dev/null;fi		
	fi
	echo "'list users: '$(cat /etc/passwd | cut -d: -f1)" 2>/dev/null 1>./enumeration/system/list_users; echo ' ' > ./enumeration/system/list_users.txt; echo "'list superusers: '$(awk -F: '($3 == "0") {print}' /etc/passwd)" 2>/dev/null 1>>./enumeration/system/list_users.txt
	# mount
	mount 2>/dev/null 1>./enumeration/system/mount/mount.txt
	ls /dev 2>/dev/null | grep -i "sd" 1>./enumeration/system/mount/dev.txt
	if [ -e /etc/fstab ]; then echo '/etc/fstab' | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null 1>./enumeration/system/mount/fstab.txt; fi
	grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null 1>./enumeration/system/mount/credentials?.txt
	# cron
	crontab -l 2>/dev/null 1>./enumeration/system/cron/crontab.txt
	ls -al /etc/cron* /etc/at* 2>/dev/null 1>>./enumeration/system/cron/crondir.txt
	cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#" > ./enumeration/system/cron/croninfos.txt
	echo "System enumeration save to 'enumeration/system/'"
}

if [ -e /proc/version ]; then kernel=$(cat /proc/version); else echo "Error, cannot access to /proc/version"; fi
# global system enumeration
enum_globalsystem()
{
        echo "'Hostname: '$(hostname)"
        echo "'ID: '$(id)"
        echo ' '
        echo "'OS infos: '$kernel"
        echo ' '
        echo "'Home directory: '$(ls -la /home/)"
        echo ' '
        echo "'Path: '$PATH"
        echo ' '
	echo "'Packagement management: '$pm"
	echo ' '	
        echo "'Date: '$(date)"
        echo ' '
        echo "'Disk: '$(df -h || lsblk)"
        echo ' '
}

# Found and export sensitive informations
enum_sensitive()
{
        # passwd/hash
	if [ -r /etc/group ]; then echo "'/etc/group: '$(cat /etc/passwd)" > ./enumeration/sensitive/pass.txt; else echo 'Error, cannot access to /etc/group'; fi
        if [ -r /etc/passwd ]; then echo "'/etc/passwd: '$(cat /etc/passwd)" >> ./enumeration/sensitive/pass.txt && echo ' ' >> ./enumeration/sensitive/pass.txt; else echo 'Error, cannot access to /etc/passwd'; fi
        if [ -r /etc/shadow ]; then echo "'/etc/shadow: '$(cat /etc/shadow)" >> ./enumeration/sensitive/pass.txt && echo ' ' >> ./enumeration/sensitive/pass.txt; else echo 'Error, cannot access to /etc/shadow'; fi
        if [ -r /etc/syslog.conf ]; then echo '/etc/syslog.conf' > ./enumeration/sensitive/syslog.txt; else echo 'Error, cannot access to /etc/syslog.conf'; fi
        if [ -r /etc/sudoers ]; then cat /etc/sudoers > ./enumeration/sensitive/sudoers.txt; else echo 'Error, cannot access to /etc/sudoers'; fi
	locate password 2>/dev/null 1>./enumeration/sensitive/locate.txt      
        # etc/var dir
	ls -aRl /etc/ 2>/dev/null | awk '$1 ~ /^.*r.*/' 2>/dev/null 1>./enumeration/sensitive/etc.txt
        ls -aRl /var/ 2>/dev/null | awk '$1 ~ /^.*r.*/' 2>/dev/null 1>./enumeration/sensitive/var.txt
        # ssh
	find / -name authorized_keys 2>/dev/null 1>./enumeration/sensitive/ssh.txt
        find / -name id_rsa 2>/dev/null 1>>./enumeration/sensitive/ssh.txt
        if [ -s ./enumeration/sensitive/ssh.txt ]; then echo 'ssh credentials:        ' | cat - ssh.txt > temp && mv temp ssh.txt; else echo 'Error, no ssh credentials found' 1>>./enumeration/sensitive/ssh.txt; fi
        # history
	if [ -e ~/.bash_history ]; then cat ~/.bash_history 2>/dev/null 1>./enumeration/sensitive/history/bash_history.txt; fi
        if [ -e ~/.nano_history ]; then cat ~/.nano_history 2>/dev/null 1>./enumeration/sensitive/history/nano_history.txt; fi
        if [ -e ~/.atftp_history ]; then cat ~/.atftp_history 2>/dev/null 1>./enumeration/sensitive/history/atftp_history.txt; fi
        if [ -e ~/.mysql_history ]; then cat ~/.mysql_history 2>/dev/null 1>./enumeration/sensitive/history/mysql_history.txt; fi
        if [ -e ~/.php_history ]; then cat ~/.php_history 2>/dev/null 1>./enumeration/sensitive/history/php_history.txt; fi
        if [ -e ~/.viminfo ]; then cat ~/.viminfo 2>/dev/null 1>./enumeration/sensitive/history/viminfo.txt; fi
        if [ -e ~/.zsh_history ]; then cat ~/.zsh_history 2>/dev/null 1>./enumeration/sensitive/history/zsh_history.txt; fi
        # users
	if [ -e ~/.bashrc ]; then cat ~/.bashrc 2>/dev/null 1>./enumeration/sensitive/users/bashrc.txt; fi
        if [ -e ~./profile ]; then cat ~/.profile 2>/dev/null 1>./enumeration/sensitive/users/profile.txt; fi
        if [ -e ~./zshrc ]; then cat ~/.zshrc 2>/dev/null 1>./enumeration/sensitive/users/zshrc.txt; fi
        if [ -e /var/mail/root ]; then cat /var/mail/root 2>/dev/null 1>./enumeration/sensitive/users/mail.txt; fi
        if [ -e /var/spool/mail/root ]; then cat /var/spool/mail/root 2>/dev/null 1>./enumeration/sensitive/users/mail2.txt; fi
	echo "Sensitive informations save to 'enumeration/sensitive/'"
}

# Network enumeration
enum_network()
{
	nmcli -p device show 2>/dev/null 1>./enumeration/network/nmcli.txt
	if [ -e /etc/services ]; then cat /etc/services 2>/dev/null 1>./enumeration/network/services.txt; else echo "Error, cannot access to /etc/services"; fi
        echo "'Ip adress: '$ip address" 2>/dev/null 1>> ./enumeration/network/network.txt 
        echo ' ' >> ./enumeration/network/network.txt; echo ' ' >> ./enumeration/network/network.txt
        if [ -e /etc/resolv.conf ]; then echo "'DNS server: '$(cat /etc/resolv.conf)" 2>/dev/null 1>>./enumeration/network/network.txt; else echo "Error, cannot access to /etc/resolv.conf"; fi
        echo ' ' >> ./enumeration/network/network.txt
        echo "'route: '$route" 2>/dev/null 1>>./enumeration/network/network.txt
        echo ' ' >> ./enumeration/network/network.txt
        echo "'arp: '$arp -e" 2>/dev/null 1>>./enumeration/network/network.txt
        echo ' ' >> ./enumeration/network/network.txt
        echo "'secure sockets: '$(ss -lnptn)" 2>/dev/null 1>>./enumeration/network/network.txt
        echo "Network enumeration save to 'enumeration/network/'"
}


# Binaries and process enumeration
enum_apps_process()
{
	which cron nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl find vim nano bash less more copy | grep / > ./enumeration/app_process/binaries.txt
	ps -ef 2>/dev/null 1>./enumeration/app_process/process.txt
	ps -ef | grep root 1>./enumeration/app_process/process_root.txt
       find / -perm -u=s -type f 2>/dev/null 1>./enumeration/app_process/binaries_suid.txt; find / -perm -4000 -o- -perm -2000 -o- -perm -6000 2>/dev/null 1>>./enumeration/app_process/binaries_suid.txt
       echo "Applications and process enumeration save to 'enumeration/app_process/'"; echo ' '
}

# Searchsploit research
enum_searchsploit()
{
	if [ -e /usr/bin/searchsploit ]; then echo 'searchsploit available'; else echo "Error, searchsploit unavailable, install the 'exploitdb' package"; fi
	sudo=$(sudo -V | grep 'Sudo version' | cut -d\   -f3)
	searchsploit "$kernel" 1>./searchsploit/searchsploit_kernel.txt 2>/dev/null || exit 1
	searchsploit "sudo $sudo" > ./searchsploit/searchsploit_sudo.txt
	echo "Searchsploit researches save to 'searchsploit'"
}

# Check and create enumeration dirs if they are not already available
check_directories()
{
	if [ -e ./enumeration ]; then echo "Directory 'enumeration' already exist"; else mkdir ./enumeration; fi
	if [ -e ./enumeration/network/ ]; then echo "Directory 'enumeration/network' already exist"; else mkdir ./enumeration/network; fi
	if [ -e ./enumeration/sensitive/ ]; then echo "Directory 'enumeration/sensitive' already exist"; else mkdir ./enumeration/sensitive; fi
	mkdir ./enumeration/sensitive/history/
	mkdir ./enumeration/sensitive/users/
	if [ -e ./enumeration/system/ ]; then echo "Directory 'enumeration/system' already exist"; else mkdir ./enumeration/system; fi
	mkdir ./enumeration/system/mount/
	mkdir ./enumeration/system/cron/
	if [ -e ./enumeration/app_process/ ]; then echo "Directory 'enumeration/app_process' already exist"; else mkdir ./enumeration/app_process; fi
	if [ -e ./searchsploit/ ]; then echo "Directory 'searchsploit' already exist"; else mkdir ./searchsploit; fi
}

# Help print message
helpfunc()
{
       echo 'Basic linux enumeration script'
       echo 'Usage : ./basic_linum.sh run'
       echo 'Aim to be helpfull for PrivEsc'
       echo ' '
       echo "Output informations save to 'enumeration' directory"
       echo "Enumeration about : 'system, network, senvitive/credentials, binaries/process'"
       echo "Searchsploit about : 'kernel/sudo' privilege escalation"
       echo ' '
       echo 'Documentation :'
       echo 'https://book.hacktricks.xyz/linux-hardening/privilege-escalation'
       echo 'https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/'
       echo 'https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md'
}

main()
{
	check_directories
	enum_system
	enum_globalsystem > ./enumeration/system/global.txt
	enum_sensitive
	enum_network
	enum_apps_process
	enum_searchsploit
}

if [ "$1" == 'run' ]; then main; else echo 'help for informations'; fi
if [ "$1" == 'help' ]; then helpfunc; fi
