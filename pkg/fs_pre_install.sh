#!/bin/bash
echo "Installing freeswitch binaries release ..."

/etc/init.d/freeswitch-nonroot stop > /dev/null 2>&1

if [ $? -eq 0 ]
then
	echo "Freeswitch is not running ..."
else
	echo "Freeswitch stopped successfuly"
fi
