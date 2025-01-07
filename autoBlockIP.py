#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 04 1月 2025 8:49 下午
# @Author  : codervibe
# @File    : autoBlockIP.py
# @Project : IPAddressSSHBurstingAutoBlocked
import re
import subprocess
import time

# 定义安全日志文件路径
securityLog = '/var/log/secure'
# 定义黑名单文件路径
hostDeny = '/etc/hosts.deny'
# 定义封禁阈值，即密码错误的次数达到多少次后触发封禁
BlockThreshold = 5

def getDenies():
    """
    获取已经加入黑名单的IP地址，并将其转换为字典形式。

    Returns:
        dict: 包含所有已封禁IP地址的字典，键为IP地址，值为'1'。
    """
    deniedDict = {}
    # 读取黑名单文件中的所有行
    blackIPList = open(hostDeny).readlines()
    for ip in blackIPList:
        # 使用正则表达式提取IP地址
        group = re.search(r'(\d+\.\d+\.\d+\.\d+)', ip)
        if group:
            # 将提取到的IP地址添加到字典中
            deniedDict[group[1]] = '1'
    return deniedDict

def monitor(securityLog):
    """
    监控安全日志文件，统计密码错误次数，当次数达到阈值时自动将IP地址加入黑名单。

    Args:
        securityLog (str): 安全日志文件的路径。
    """
    # 初始化密码错误次数统计字典
    tempIp = {}
    # 获取已经加入黑名单的IP地址字典
    deniedDict = getDenies()
    # 使用subprocess模块实时读取安全日志文件的末尾内容
    popen = subprocess.Popen('tail -f ' + securityLog, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    # 开始监控提示
    print('开始监控')
    while True:
        # 短暂休眠以避免过高CPU占用
        time.sleep(0.1)
        # 读取日志文件新的一行内容
        line = popen.stdout.readline().strip()
        if line:
            # 打印日志内容
            print(line)
            # 使用正则表达式匹配无效用户登录尝试
            group = re.search(r'Invalid user \w+ from (\d+\.\d+\.\d+\.\d+) 该用户不存在', str(line))
            if group and not deniedDict.get(group[1]):
                # 将无效用户登录尝试的IP地址加入黑名单
                subprocess.getoutput('echo \'sshd:{}\' >> {}'.format(group[1], hostDeny))
                deniedDict[group[1]] = '1'
                time_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
                print('{} 加入黑名单 {}'.format(time_str, group[1]))
                print('{} >>>> add ip:{} to host.deny for invalid user'.format(time_str, group[1]))
                continue
            # 使用正则表达式匹配用户名合法但密码错误的登录尝试
            group = re.search(r'Failed password for invalid user \w+ from (\d+\.\d+\.\d+\.\d+) 用户名存在但密码错误', str(line))
            if group:
                ip = group[1]
                # 统计该IP地址密码错误的次数
                if not tempIp.get(ip):
                    tempIp[ip] = 1
                else:
                    tempIp[ip] += 1
                    # 如果密码错误次数超过阈值且该IP地址尚未被封禁，则将其加入黑名单
                    if tempIp[ip] > BlockThreshold and not deniedDict.get(ip):
                        del tempIp[ip]
                        subprocess.getoutput('echo \'sshd:{}\' >> {}'.format(ip, hostDeny))
                        deniedDict[ip] = '1'
                        time_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
                        print('{} 加入黑名单 {}'.format(time_str, ip))
                        print('{} >>>> add ip:{} to host.deny for invalid password'.format(time_str, ip))

if __name__ == '__main__':
    # 程序入口
    print('程序开始')
    # 启动监控
    monitor(securityLog)
    # 打印当前黑名单中的IP地址
    print(f'getDenies(): {getDenies()}')
