#!/bin/bash

echo "Stopping Freeswitch ..."
/etc/init.d/freeswitch-nonroot stop > /dev/null 2>&1

if [ $? -ne 0 ]
then

	echo "Forcefully stopping Freeswitch ..."
	kill -9 `ps ax|grep freeswitch|grep -v grep|awk '{print $1}'` > /dev/null 2>&1
	if [ $? -eq 0 ]; then
		echo "Stopped"
	else
		echo "Check what's wrong wit it!!!!!!!!!"
	fi
else
	echo "Freeswitch stopped successfully."

fi

