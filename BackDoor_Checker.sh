#!/bin/bash
#By Maxx 2022/7/1

tempFile=`mktemp`
cat <<EOF >>$tempFile
  ____             _    _____                      _____ _               _                    __   ___  
 |  _ \           | |  |  __ \                    / ____| |             | |                  /_ | / _ \ 
 | |_) | __ _  ___| | _| |  | | ___   ___  _ __  | |    | |__   ___  ___| | _____ _ __  __   _| || | | |
 |  _ < / _\` |/ __| |/ / |  | |/ _ \ / _ \| '__| | |    | '_ \ / _ \/ __| |/ / _ \ '__| \ \ / / || | | |
 | |_) | (_| | (__|   <| |__| | (_) | (_) | |    | |____| | | |  __/ (__|   <  __/ |     \ V /| || |_| |
 |____/ \__,_|\___|_|\_\_____/ \___/ \___/|_|     \_____|_| |_|\___|\___|_|\_\___|_|      \_/ |_(_)___/ 
                                                                                
EOF
result=`cat ${tempFile}`
IFS=$'\n'
for line in  $result
do
  echo "${line}"
  sleep 0.1
done                      
echo -e "\n"


echo "Version:1.0"
echo "Author: Maxx"
echo "Mail:caoshijie@sechnic.com"
echo "Date:2022-07-01"

check_super_user(){
echo -e "\033[34m [+] 正在检查可疑超级权限用户.... \033[0m"
if [ -z "$(awk -F: '{if($3==0)print $1}' /etc/passwd | grep -v root)" ] ;then
  echo -e "\033[32m [*] 不存在除root用户外其他超级权限用户.\033[0m"
else
  echo -e "\033[31m [*] 发现超级权限用户!!!!\033[0m";
  for user in $(awk -F: '{if($3==0)print $1}' /etc/passwd | grep -v root);
  do echo $user;
  done
fi
echo -e "\033[34m [+] 超级权限用户检查完毕.\033[0m"
}

check_nopass_user(){
echo -e "\033[34m [+] 正在检查空口令用户....\033[0m"
if [ -z "$(awk -F: '{if($2=="")print $1}' /etc/shadow)" ] ;then
  echo -e "\033[32m [*] 不存在空口令用户.\033[0m"
else
  echo -e "\033[31m [*] 发现空口令用户!!!!\033[0m";
  for user in $(awk -F: '{if($2=="")print $1}' /etc/shadow);
  do echo $user;
  done
fi
echo -e "\033[34m [+] 空口令用户检查完毕.\033[0m"
}

check_SUID_shell(){
echo -e "\033[34m [+] 正在检查SUID权限程序....\033[0m"
if [ -z "$(find / -perm -u=s -type f 2>/dev/null)" ] ;then
  echo "\033[32m [*] 不存在SUID权限程序.\033[0m"
else
  echo -e "\033[31m [*] 发现SUID权限程序!!!!\033[0m";
  for file in $(find / -perm -u=s -type f 2>/dev/null);
  do echo $file;
  done
fi
echo -e "\033[34m [+] SUID权限程序检查完毕.\033[0m"
}

check_hide_cron(){
echo -e "\033[34m [+] 正在检查cron计划任务....\033[0m"
echo -e "\033[34m [*] 正在分析系统cron计划任务....\033[0m"
if [ -n "$(cat /etc/crontab | grep -v "# run-parts" | grep run-parts)" ] ;then
	echo -e "\033[31m [*] 存在系统cron计划任务：\033[0m"
	cat /etc/crontab | grep -v "# run-parts" | grep run-parts
	if [ -n "$(cat /etc/crontab | grep -v "# run-parts" | grep run-parts | grep -aE 'chmod|useradd|groupadd|chattr|bash|sh|wget|curl|py|nc|python|pl|perl|php|system|exec')" ] ;then
	  echo -e "\033[31m [*] 发现可疑系统cron计划任务!!!!\033[0m"
      cat /etc/crontab | grep -v "# run-parts" | grep run-parts | grep -aE 'chmod|useradd|groupadd|chattr|bash|sh|wget|curl|py|nc|python|pl|perl|php|system|exec'
	fi
	if [ -n "$(cat /etc/cron*/* | grep -aE 'chmod|useradd|groupadd|chattr|bash|sh|wget|curl|py|nc|python|pl|perl|php|system|exec')" ] ;then
	  echo -e "\033[31m [*] 发现可疑系统cron计划任务!!!!\033[0m"
	  for cron in $(cat /etc/cron*/* | grep -aE 'chmod|useradd|groupadd|chattr|bash|sh|wget|curl|py|nc|python|pl|perl|php|system|exec');
	  do echo $cron;
   	  done
	fi
else
echo -e "\033[32m [*] 不存在系统cron计划任务.\033[0m"
fi
echo -e "\033[34m [*] 正在分析用户cron计划任务....\033[0m"
cron_str=`cat -A /var/spool/cron/* 2>/dev/null| grep -v "^n"  `
#test_str="no crontab"
#result=$(echo $cron_str | grep "${test_str}")
if [[ $? -eq 0 ]] ;then 
	echo -e "\033[31m [*] 存在用户cron计划任务：\033[0m"
	cat -A /var/spool/cron/* 2>/dev/null | grep -v '^n' 
	echo -e "\033[34m [*] 正在分析用户cron计划任务....\033[0m"
	if [ -n "$(cat -A /var/spool/cron/* | grep -v '^n' | grep -E 'chmod|useradd|groupadd|chattr|bash|sh|wget|curl|py|nc|python|pl|perl|php|system|exec')" ];then
	   echo -e "\033[31m [*] 发现可疑用户cron计划任务!!!!\033[0m"
	   cat -A /var/spool/cron/* | grep -v '^n'l | grep -	E 'chmod|useradd|groupadd|chattr|bash|sh|wget|curl|py|nc|python|pl|perl|php|system|exec';
	fi

var=`cat -A /var/spool/cron/* 2>/dev/null `
if [[ $? -eq 0 ]];then
	#echo 111
	if [[  -z $(cat -A /var/spool/cron/* 2>/dev/null| grep -v 'no' ) ]]; then
		if [[ -n $(cat -A /var/spool/cron/*  2>/dev/null )  ]];then
			echo -e "\033[31m [*] 存在隐藏计划任务：\033[0m"	
   			cat -A /var/spool/cron/*
   		fi
   	fi
	echo -e "\033[34m [*] 正在分析用户cron计划任务....\033[0m"

	if [[ -n "$(cat -A /var/spool/cron/* | grep -E 'chmod|useradd|groupadd|chattr|bash|sh|wget|curl|py|nc|python|pl|perl|php|system|exec')" ]] ;then
	  echo -e "\033[31m [*] 发现可疑用户cron计划任务!!!!\033[0m"
	  cat -A /var/spool/cron/* | grep -E 'chmod|useradd|groupadd|chattr|bash|sh|wget|curl|py|nc|python|pl|perl|php|system|exec';
	fi	
	
else
	echo -e "\033[32m [*] 不存在用户cron计划任务.\033[0m"
fi
fi
echo -e "\033[34m [+] cron计划任务检查完毕.\033[0m"
}

check_soft_ssh(){
echo -e "\033[34m [+] 正在检查是否存在ssh软链接后门....\033[0m"
if [ -n "$(grep -R "UsePAM yes" /etc/ssh/sshd_config)" ] ;then
  echo -e "\033[31m [*] 系统sshd-PAM认证开启：UsePAM yes.\033[0m"
if [[ -n $(grep -R "pam_rootok.so" /etc/pam.d/) ]]; then
	echo -e "\033[31m [*] 以下文件存在ssh软链接风险：\033[0m"
fi
for i in $(ls /etc/pam.d);do
	if [[ -n $(grep -R "pam_rootok.so" /etc/pam.d/$i) ]]; then
		echo /etc/pam.d/$i;
	fi
done
for i in $(ls /etc/pam.d);do
	if [[ -n $(grep -R "pam_rootok.so" /etc/pam.d/$i) ]]; then
		if [[ -n $(netstat -atnpl | grep $i) ]];then
			echo -e "\033[31m 存在可疑ssh软链接外连：\033[0m"
			echo $(netstat -atnpl | grep $i)
		fi
	fi
done

else
  echo -e "\033[32m [*] 系统sshd-PAM认证关闭，不存在ssh软链接后门\033[0m";
fi
echo -e "\033[34m [+] ssh软链接后门检查完毕.\033[0m"
}

check_pubkey_ssh(){
echo -e "\033[34m [+] 正在检查系统所保存的ssh公钥....\033[0m"
var=`cat /root/.ssh/authorized_keys 2>/dev/null `
if [[ $? -eq 0 ]] ;then
  echo -e "\033[31m [*] 系统所保存的ssh公钥如下：\033[0m"
  cat /root/.ssh/authorized_keys
  echo -e "\033[31m [*] 通过ssh公钥登陆过系统的IP如下：\033[0m"
  if [ -n "$(cat /var/log/secure | grep "Accepted publickey")" ] ;then
  for ip in $(cat /var/log/secure | grep "Accepted publickey" | cut -d " " -f 12);do
  	echo $ip;
  done
  fi
else
  echo -e "\033[32m [*] 系统没有保存任何公钥.\033[0m"
fi
echo -e "\033[34m [+] ssh公钥检查完毕.\033[0m"	
}

check_ssh_wrapper(){
echo -e "\033[34m [+] 正在检查是否存在ssh wrapper后门....\033[0m"
var=`cat /usr/sbin/sshd  2>/dev/null| grep -a 'getpeername(STDIN)' `
if [ $? -eq 0 ] ;then
	echo -e "\033[31m [*] 系统存在ssh wrapper后门!!!!!\033[0m"
	echo -e "\033[31m [*] sshd文件已被篡改如下：\033[0m"
	cat /usr/sbin/sshd
	if [[ -n "$(netstat -antpl | grep 22 | grep -v sshd)" ]];then
		echo -e "\033[31m [*] 发现ssh wrapper可疑外连!!!!\033[0m"
		netstat -antpl | grep 22 | grep -v sshd
	fi
else
  echo -e "\033[32m [*] 系统不存在ssh wrapper后门.\033[0m"
fi
echo -e "\033[34m [+] ssh wrapper后门检查完毕.\033[0m"	
}

check_sudoers_root(){
echo -e "\033[34m [+] 正在检查是否存在有sudo执行权限的用户....\033[0m"
var=`cat /etc/sudoers 2>/dev/null| grep "ALL=(ALL" | grep -v '#' | grep -v 'root'`
if [ $? -eq 0 ] ;then
        echo -e "\033[31m [*] 系统存在除root用户外其他具有sudo执行权限用户!!!!!\033[0m"
        echo -e "\033[31m [*] 具有sudo执行权限用户如下：\033[0m"
	cat /etc/sudoers | grep "ALL=(ALL" | grep -v '#' | grep -v 'root'
else
  echo -e "\033[32m [*] 系统不存在除root用户外其他具有sudo执行权限用户.\033[0m"
fi
echo -e "\033[34m [+] sudo权限用户检查完毕.\033[0m"	
}

check_inetd_service(){
echo -e "\033[34m [+] 正在检查是否存在inetd服务后门....\033[0m"
var=`cat /etc/inetd.conf 2>/dev/null `
if [ $? -eq 0 ] ;then
        if [[ -n $(cat /etc/inetd.conf | grep bash) ]];then
                echo -e "\033[31m [*] inetd服务配置文件存在可疑后门配置项!!!!!\033[0m"
                echo -e "\033[31m [*] inetd服务可疑后门配置项如下：\033[0m"
                cat /etc/inetd.conf | grep bash
                echo -e "\033[31m [*] 该可疑配置项关联系统服务如下：\033[0m"
                cat /etc/services | grep $(cat /etc/inetd.conf | grep bash | cut -d " " -f 1)
                port=`echo  "$(cat /etc/services | grep $(cat /etc/inetd.conf | grep bash | cut -d " " -f 1))" | tr -cd "[0-9]" `
            if [[ -n  $(netstat -atnpl | grep $port | grep ESTABLISHED) ]];then
                echo -e "\033[31m [*] 存在可疑的inetd服务外连：\033[0m";
                netstat -atnpl | grep $port | grep ESTABLISHED
            else
                echo -e "\033[32m [*] 不存在可疑的inetd服务外连，但inetd服务已开启：\033[0m"
                netstat -atnpl | grep $port | grep LISTEN
            fi
        fi
else
  echo -e "\033[32m [*] 系统不存在inetd服务后门.\033[0m"
fi
echo -e "\033[34m [+] inetd服务后门检查完毕.\033[0m"
}

check_strace_alias(){
echo -e "\033[34m [+] 正在检查是否存在恶意alias命令的strace键盘记录后门....\033[0m"
var=`cat ~/.bashrc 2>/dev/null | grep alias |grep strace | grep -E 'ssh|read|write|bash|log|su|sudo|ftp|mysql' `
if [ $? -eq 0  ] ;then
	echo -e "\033[31m [*] 系统存在可疑的alias命令!!!!!\033[0m"
	echo -e "\033[31m [*] 可疑的alias命令如下：\033[0m"
	cat ~/.bashrc | grep alias | grep strace | grep -E 'ssh|read|write|bash|log|su|sudo|ftp|mysql|root'
	cat /etc/bashrc | grep alias | grep strace | grep -E 'ssh|read|write|bash|log|su|sudo|ftp|mysql|root'
	
else
  echo -e "\033[32m [*] 系统不存在可疑的alias命令.\033[0m"
fi
echo -e "\033[34m [+] 恶意alias命令的strace键盘记录后门检查完毕.\033[0m"		
}

check_vim_python(){
echo -e "\033[34m [+] 正在检查是否存在vim后门....\033[0m"
if [ -n "$(netstat -atnpl | grep vim)" ] ;then
	echo -e "\033[31m [*] 系统存在可疑的vim进程外连!!!!\033[0m"
	echo -e "\033[31m [*] 可疑的vim进程外连如下：\033[0m"
	netstat -atnpl | grep vim | grep -v grep
	echo -e "\033[31m [*] 进程命令信息如下：\033[0m"
	echo "vim" $(ps -aux | grep 2291 | grep -v grep | awk -F "vim" '{print $2}')

elif [[ -n "$(netstat -antpl | grep ESTABLISHED |grep - | grep -v [0-9]/)" ]]; then
	echo -e "\033[31m [*] vim后门可能被隐藏!!!!\033[0m"
	netstat -antpl | grep ESTABLISHED |grep -
	echo -e "\033[34m [*] 正在检查系统的可疑挂载信息.....\033[0m"
	if [ -n "$(cat /proc/$$/mountinfo | grep proc/[0-9])" ] ;then
		echo -e "\033[31m [*] 系统的可疑挂载信息如下：\033[0m"
		cat /proc/$$/mountinfo | grep proc
		echo -e "\033[34m [*] 正在尝试解除挂载并重新检查外连进程....\033[0m"
		for proc in $(cat /proc/$$/mountinfo | grep proc/[0-9] | cut -d " " -f 5);do
			umount $proc
		done
		if [ -n "$(netstat -atnpl | grep vim)" ] ;then
			echo -e "\033[31m [*] 系统存在可疑的vim进程外连!!!!\033[0m"
			echo -e "\033[31m [*] 可疑的vim进程外连如下：\033[0m"
			netstat -atnpl | grep vim | grep -v grep
			echo -e "\033[31m [*] 进程命令信息如下：\033[0m"
			echo "vim" $(ps -aux | grep 2291 | grep -v grep | awk -F "vim" '{print $2}')
		fi

	else
		echo -e "\033[32m [*] 未找到可疑的挂载信息.\033[0m"
	fi
	
else
  echo -e "\033[32m [*] 系统不存在可疑的vim进程外连.\033[0m"
fi
echo -e "\033[34m [+] vim后门检查完毕.\033[0m"		
}

check_super_user
check_nopass_user
check_SUID_shell
check_hide_cron
check_soft_ssh
check_pubkey_ssh
check_ssh_wrapper
check_sudoers_root
check_inetd_service
check_strace_alias
check_vim_python
