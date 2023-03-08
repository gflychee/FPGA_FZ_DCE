#!/bin/bash

if [ -z "$1" ]
then
    echo "Please specify target install exanic dev" 
    exit 1
fi

# install exanic dev driver
cd dcenew/
tar -xvf exanic-software.tar
cd exanic-software
make && make install && modprobe exanic
if [ $? -ne 0 ]
then
    echo "Failed to install exanic driver. please check the above error info."
    exit 1
fi

# check target dev platform
if [ -f /usr/local/bin/exanic-config ]
then
    DIR=/usr/local/bin
elif [ -f /usr/bin/exanic-config ]
then
    DIR=/usr/bin
else
    echo "cannot find exanic firmware update utils."
    exit 1
fi

PLATFORM=$(exanic-config | grep type | awk '{ print $4}')
cd ..

# update fpga firmware
if [ "$PLATFORM" == "X10" ]
then
    $DIR/exanic-fwupdate -d $1 *x10*.fw.gz -r
elif [ "$PLATFORM" == "X25" ]
then
    $DIR/exanic-fwupdate -d $1 *x25*.fw.gz -r
fi

./initnic.sh
if [ -f /var/spool/cron/root ]
then
    cat cron >> /var/spool/cron/root
else
    crontab cron
fi

rm -rf cron exanic-software* *.fw
cd ..
mv dcenew /root

echo "please tell luis the following info."
echo $(exanic-config $1 | grep "MAC address:" | awk '{print $3}' | head -1)
echo $(ip a | grep inet | awk '{print $2}')
