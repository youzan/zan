#!/bin/sh

name=`uname -s`
if [ "Darwin" == "${name}" ];then
    #mac: 可能不支持 cli_set_process_title，无法设置进程名
    ps -ef|grep -w php|grep -v grep|awk -F' ' '{print $2}' |xargs kill -9
else
    #Linux
    ps -ef|grep BaseTcpServer1|grep master|awk -F' ' '{print $2}' |xargs kill -15

    #如果不设置进程名
    #ps -ef|grep -w php|grep -v grep|awk -F' ' '{print $2}' |xargs kill -9
fi
