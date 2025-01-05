#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 04 1月 2025 8:49 下午
# @Author  : codervibe
# @File    : autoBlockIP.py
# @Project : IPAddressSSHBurstingAutoBlocked
import re
import subprocess
import time

securityLog = '/var/log/secure'
# 黑名单
hostDeny = '/etc/hosts.deny'
# 封禁阈值
# 密码错误的次数 [0,5]
BlockThreshold = 5


def getDenies():
    # 获取已经加入黑名单的Ip转换为字典
    deniedDict = {}
    blackIPList = open(hostDeny).readlines()
    for ip in blackIPList:
        group = re.search(r'(\d+\.\d+\.\d+\.\d+)', ip)
        if group:
            deniedDict[group[1]] = '1'
    return deniedDict


def monitor(securityLog):
    # 统计密码错误的次数
    tempIp = {}
    # 已经来黑的IP列表
    deniedDict = getDenies()
    # 读取安全日志
    popen = subprocess.Popen('tail -f' + securityLog, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    # 开始监控
    print('开始监控')
    while True:
        time.sleep(0.1)
        line = popen.stdout.readline().strip()
        if line:
            print(line)
            group = re.search(r'Invaild user \w + from (\d+\.\d+\.\d+\.\d+) 该用户不存在', str(line))
            # 不存在的用户直接封
            if group and not deniedDict.get(group[1]):
                subprocess.getoutput('echo\'sshd:{}>>{}'.format(group[1]), hostDeny)
                deniedDict[group[1]] = '1'
                time_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
                print('{}加入黑名单{}'.format(time_str, group[1]))
                print('{} >>>> add ip:{} to host.deny for invalid user'.format(time_str, group[1]))
                continue
            # 用户名合法但是密码错误
            group = re.search(r'Failed password for invalid user \w+ from (\d+\.\d+\.\d+\.\d+) 用户名存在但密码错误',
                              str(line))
            if group:
                ip = group[1]
                # 统计这个IP错误的密码的次数
                if not tempIp.get(ip):
                    tempIp[ip] = 1
                else:
                    tempIp[ip] = tempIp[ip] + 1
                    # 如果错误的次数大于阈值 直接封禁
                    if tempIp[ip] > BlockThreshold and not deniedDict.get(ip):
                        del tempIp[ip]
                        subprocess.getoutput('echo \'sshd:{}>>{}'.format(ip), hostDeny)
                        deniedDict[ip] = '1'
                        time_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
                        print('{}加入黑名单{}'.format(time_str, ip))
                        print('{} >>>> add ip:{} to host.deny for invalid password'.format(time_str, ip))


if __name__ == '__main__':
    print('程序开始')
    monitor(securityLog)
    print(f'getDenies():{getDenies()}')
