# !/usr/bin/python3
# @File: Redis_scanner.py.py
# --coding:utf-8--
# @Author:kinni
# @Time:  2020年04月12日 20:36:54
# 说明: 基于简单版本修改的多线程版本  单次扫描255台主机以内，自定义线程数量

import socket
import sys
import threading

#密码字典爆破
def Check_password(s):
    """
    s:已连接redis服务器的socket
    返回值：密码字符串，失败返回None
    """
    fp = open("dict.txt")  # 打开密码字典
    passwords = fp.readline()
    fp.close()
    for pwd in passwords:
        # 删除末尾的“\r”,"\n","\r\n"
        pwd = pwd.strip()
        s.sendall("AUTH %s \r\n" % pwd)
        msg = s.recv(1024)
        if msg.find("OK") != -1:
            return pwd
    return None

#判断是否为redis服务
def is_redis_server(ip, port):
    """
      参数ip:字符串形式IP地址
      参数port：数值形式端口号，如6379
      返回值：-1 端口未开放，或者开放但不是Redis服务
              0   为Redis服务，但需要密码
              1   为Redis服务，不需要密码
    """
    # 创建一个TCP类型的socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2.0)
    # 尝试连接端口，如果返回值不为0，表示端口没有开放
    if s.connect_ex((ip, port)) != 0:
        return -1, None
    s.sendall("PING\r\n")
    msg = s.recv(1024)
    res = -1
    pwd = None
    # 如果返回值包含PONG，成功且无密码
    if msg.find("PONG") != -1:
        res = 1
    # 如果返回值如下，则表示需要密码
    elif msg.find("NOAUTH") != -1:
        res = 0
        pwd = Check_password(S)
    # 否则不是Redis服务，res = -1
    # 关闭socket链接
    s.close()
    return res, pwd

# ip字符串转数字
def ip_str2int(ip):
    tmp = ip.split(".")
    a1 = int(tmp[0]) * 256 * 256 * 256
    a2 = int(tmp[1]) * 256 * 256
    a3 = int(tmp[2]) * 256
    a4 = int(tmp[3])
    ip = a1 + a2 + a3 + a4
    return ip

# ip数字转字符串
def ip_int2str(ip):
    a1 = (ip & 0xFF000000) >> 24
    a2 = (ip & 0x00FF0000) >> 16
    a3 = (ip & 0x0000FF00) >> 8
    a4 = ip & 0x0000000FF
    ip = "%d.%d.%d.%d" % (a1, a2, a3, a4)
    return ip

# 扫描的函数
def scan(beg_ip, end_ip):
    """对指定ip返回内的主机进行检测"""
    # 将点分十进制ip,转化成数值
    beg_ip = ip_str2int(beg_ip)
    end_ip = ip_str2int(end_ip)
    # 遍历数值ip返回
    for ip in range(beg_ip, end_ip + 1):
        ip = ip_int2str(ip)
        res, pwd = is_redis_server(ip, 6379)
        if res == 1:
            print(ip)
        elif res == 0 and pwd != None:
            print("%s  -> %s" % (ip, pwd))
    print("Scan Done!")


Warning = """\
参数格式或个数不正确！
示例：
python Redis_scanner.py 192.168.1.1 192.168.1.255 5
#python 命令行运行的python版本
#Redis_scanner.py 脚本名称
后面为开始ip 和 结束ip
最后一个参数表示线程个数
"""

#函数功能是将ip按照线程数量进行分组，并初始化为线程对象
def argv_handle():
    begin_ip_last_num = int(sys.argv[1].split(".")[3])
    end_ip_last_num = int(sys.argv[2].split(".")[3])
    thread_num = int(sys.argv[3])
    step = int((end_ip_last_num - begin_ip_last_num+1) / thread_num) -1  #得到的是每组的个数，比如10个的话，从1到10需要移动9步
    threads = []
    begin_ip_num = ip_str2int(sys.argv[1])  #当前线程的起始ip数值
    end_ip_num = begin_ip_num + step        #当前线程的结束ip数值
    begin_ip = ip_int2str(begin_ip_num)     #将数值转化为ip字符串
    end_ip = ip_int2str(end_ip_num)
    for ip in range(thread_num):
        #print(str(ip)+" "+"begin_ip:"+str(begin_ip)+"  end_ip:"+str(end_ip))
        t = threading.Thread(target=scan, args=(begin_ip, end_ip))
        threads.append(t)        #将线程对象加入列表
        begin_ip_num = ip_str2int(end_ip) + 1   #更新下一个线程组的起始ip和结束ip
        end_ip_num = begin_ip_num + step
        begin_ip = ip_int2str(begin_ip_num)
        end_ip = ip_int2str(end_ip_num)
    return threads

if __name__ == "__main__":
    if len(sys.argv) == 4:
        threads = argv_handle()
        for t in threads:
            t.start()
    else:
        print(Warning)
