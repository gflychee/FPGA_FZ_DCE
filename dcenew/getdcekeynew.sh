#!/bin/bash

logfile=/tmp/$(LC_TIME=en_US.utf8 date +".%Y%m%d_%p_new.log")

get_set()
{
    keystr=$(ssh -i ~/.ssh/id_rsa -o ConnectTimeout=10 -p 19900 wf@119.3.128.227 tail -1 /tmp/dce_tcpdecoder_new.log)
    today=$(LC_TIME=en_US.utf8 date +"%Y%m%d %p")
    echo $today
    key=$(echo $keystr | grep "$today" | awk '{print $4}')
    if [ -z "$key" ]
    then
        echo "no key today"
        /root/dcenew/keysetter exanic0 0
    else
        /root/dcenew/keysetter exanic0 $key
        echo setted key $key
        echo $keystr >$logfile
    fi
}

if [ -f $logfile ]
then
    keystr=$(cat $logfile)
    if [ -z "$keystr" ]
    then
        rm -rf $logfile
        get_set
    else
        echo  $keystr
        key=$(echo $keystr | grep "$today" | awk '{print $4}')
        /root/dcenew/keysetter exanic0 $key
        echo setted key $key
    fi
else
    get_set
fi
