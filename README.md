# BackDoorChecker
### What
  支持检测如下常见Linux后门（测试环境为Centos7）：
  
  超级用户后门 | SUID shell后门 | crontab计划任务后门 | SSH软链接后门 | SSH公私钥登陆后门 | SSH wrapper后门 | /etc/sudoers权限后门 | 空口令用户后门 | ineted服务后门 | strace键盘记录后门 | vim后门 
  
  
### How
  [1] `git clone https://github.com/Maxx200014/BackDoorChecker.git`
  
  [2] `cd BackDoorChecker`
  
  [3] `chmod +x BackDoor_Checker.sh`
  
  [4] `./BackDoor_Checker.sh`

### ToDo
  [1] 完善检测规则 -> 添加动态检测功能
  
  [2] 添加除后门检测外的其他常规系统检查功能
  
  [3] 添加用户自动化拓展检测功能
  
  [4] 系统兼容性
