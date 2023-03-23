# -*- coding: utf-8 -*-
from asyncio.windows_utils import BUFSIZE
from distutils.log import error
from itertools import cycle
import threading  # Python 3已经内置了threading模块来实现多线程,这里引入
import time
import netmiko
from queue import Queue  # 多线程中需要用的队列，这里引入，多线程中需要用的队列，这里引入，通过队列传递数据，安全，不会造成多个线程访问时混乱
import logging
import re
from ftplib import FTP

#loggin seting，使用logging模块跟踪netmiko的log
#logging.basicConfig(filename="test.log", level=logging.DEBUG)
#logger = logging.getLogger("netmiko")

#定义ftp连接函数，连接本地PC的ftp ser
def ftpconnect(host,port,username, password):
    ftp = FTP()
    #ftp.set_debuglevel(1)         #打开调试级别
    ftp.connect(host, port)          #连接
    ftp.login(username, password)  #登录，如果匿名登录则用空串代替即可
    return ftp

def uploadfile(ftp, remotepath, localpath):
    bufsize = 1024
    filepath = open(localpath, 'rb')
    ftp.storbinary('STOR '+ remotepath , filepath, bufsize)    #上传文件
    ftp.set_debuglevel(0)
    filepath.close()

#定义连接函数，使用netmiko连接设备，并输入预定义命令
#def ssh_session(ip, username, password,cmdlist,ftp,output_q):
def ssh_session(ip, username, password,cmdlist,output_q):
    SW = {
        'device_type': 'hp_comware',
        'ip': ip,
        'username': username,
        'password': password,
        #"session_log": "output.txt"#会话logging，netmiko模块自带
        }

    connect = netmiko.ConnectHandler(**SW)
    print("ssh连接成功:" + SW['ip'])
    '''
    config_commands = ['dis arp', 'dis ip routing-table', 'dis int brief']
    output = connect.send_config_set(config_commands)
    print(output)
    print("*" * 20 + "========="+ "*" * 20)
    '''
    ftpconfig_commands = ["ftp ser en","local "+username+" class man","password  simple "+password,"authorization-attribute work-directory flash:/","service-type ftp","authorization-attribute user-role network-admin","quit"]
    ftpconfig_output = connect.send_config_set(ftpconfig_commands,exit_config_mode=False)
    print("==设备ftp ser配置完成==")
    #re_rule = input("输入多个终端正则表达式:")             #匹配bfd session holdtime中0ms ([^0-9])(0{1}ms)+
    #swversion1 = input("输入要匹配的版本:")
    #re_rule = input("输入多个终端正则表达式:")
    execcycle = input("输入执行轮次：")
    version_filepath = input("本地的版本路径及文件名：")
    for i in range(1,int(execcycle)+1):   
            print("++================第%s次==================++"%i)
            for cmd in cmdlist:
                cmd = cmd.strip("\n")
                cmdsplit=cmd.split(",")
                #print(type(cmdsplit))
                for j in range(0,len(cmdsplit)):
                    pattern = re.compile(r'(ware)+',re.S)                   #匹配bfd session holdtime中0ms
                    #pattern = re.compile(str(re_rule),re.S)                       
                    output = connect.send_config_set(cmdsplit[j],exit_config_mode=False)
                    #print(cmdsplit[j])
                    print(output)
                    n = pattern.findall(output)
                    #print(n)
                    #暂时写死变量n，换版本一般都是直接升级，直接进入判断分支
                    #if n == [swversion1]:
                    try:
                        if n == ["ware"]:
                            print("==OK,ftp上传IPE文件中==")
                            time.sleep(1)
                            #以下注释是操作设备ftp客户端方式获取本地ftp文件，暂时废弃
                            """ftpconfig_commands = ['quit','quit',"ftp 192.168.124.239","anonymous",'','\n',"ls","get s6550x-hi-h3cv9trunk10_20.ipe","\n","\n","quit"]
                            ftp_output = connect.send_config_set(ftpconfig_commands,exit_config_mode=False,read_timeout=500)
                            print(ftp_output)
                            """

                            ftp = ftpconnect(ip,21, username, password)
                            uploadfile(ftp, "/newipe1.ipe", version_filepath)
                            print("==上传成功,即将执行boot-loader命令==")
                            ftp.quit()
                            time.sleep(1)
                            bootloader_config_commands = ["quit","quit","","boot-loader file flash:/newipe1.ipe all ma","","y","","y","","y","","quit"]
                            boot_output = connect.send_config_set(bootloader_config_commands,read_timeout=3600,exit_config_mode=False)
                            #print(boot_output)
                            time.sleep(55)
                            print("==boot-loader成功,稍后请手动重启==")
                            #time.sleep(1)
                            print("++=========================================++")
                            #time.sleep()
                            #print(output2)
                            #time.sleep(360)
                            break
                        else:
                            #print("==未匹配==")
                            pass
                            #ftp.quit()
                        #print(format(time.strftime("%X")))
                        #print("*" * 20 + "=========" + "*" * 20)
                    except  RuntimeError as erro1:
                        break
            i+1
    #result = connect.send_command('dis int LoopBack 0')
    #print(result)

print("++++=========================================++++")
print("{}开始执行\n".format(time.strftime("%X")))
threads = []
with open("D:\\pythoncode\\ip_user_pass.txt", "r") as devices_file, open("D:\\pythoncode\\cmdlist.txt", "r") as cmd_file:
    devices = devices_file.readlines()
    cmdlist = cmd_file.readlines()
    for line in devices:
        line = line.strip("\n")
        ip_address = line.split(",")[0]   #split() 通过指定分隔符对字符串进行切片，如果参数 num 有指定值，则分隔 num+1 个子字符串
        username = line.split(",")[1]
        password = line.split(",")[2]
        #使用threading的Thread()函数为ssh_session函数创建一个线程并将它赋值给变量t，注意Thread()函数的target参数对应的是函数名称（即ssh_session）
        #args对应的是该ssh_session函数的参数
        #ftp = FTP()
        output_q = Queue()
        #t = threading.Thread(target=ssh_session, args=(ip_address, username, password, cmdlist,ftp,output_q))
        t = threading.Thread(target=ssh_session, args=(ip_address, username, password, cmdlist,output_q))
        t.start()
        threads.append(t)

    
for a in threads:
    a.join()    #threading的join()方法的作用是强制阻塞调用它的线程，直到该线程运行完毕或者终止（类似单线程同步）

print("{}执行结束\n".format(time.strftime("%X")))
print("++++=======================================++++")