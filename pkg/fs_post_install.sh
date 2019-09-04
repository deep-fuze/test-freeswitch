#!/bin/bash
echo "Updating ownership for /opt/freeswitch..."
chown freeswitch.freeswitch /opt/freeswitch/ -R

echo "Updating setcap to the freeswitch binary ..."
setcap 'cap_net_bind_service=+ep'  /opt/freeswitch/bin/freeswitch

#echo "Stopping puppet if there is such ..."
#kill -9 $(ps aux | grep "puppet agent" | grep -v grep |  awk '{print $2}') > /dev/null 2>&1

echo "Checking for freeswitch-configs ..."
if [ `dpkg -l freeswitch-configs|grep ii|wc -l` -eq 0 ]; then
	echo "Package freeswitch-configs is not installed"
else
	echo "Starting Freeswitch ..."
	/etc/init.d/freeswitch-nonroot start > /dev/null 2>&1

	if [ $? -ne 0 ]; then
		echo "For sorrow, failed to start Freeswitch, please check!!!"
	else
		echo "Freeswitch started successfully"
	fi
fi


