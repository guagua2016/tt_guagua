#! /bin/bash
# stop.sh

CMD=`ps -ef | grep msg_server | grep -v grep | grep -v tail | awk '{print $2}'`
nPID="$CMD"
#nPID=$(ps -ef | grep msg_server | grep -v grep | grep -v tail | awk '{print $2}')
echo $nPID
echo "Start kill process msg_server...."
kill -TERM $nPID
usleep l0000
echo "Start process msg_server..."
./daeml ./msg_server
usleep 10000
nPID=`ps -ef | grep msg_server | grep -v grep | grep -v tail | awk '{print $2}'`
echo "The new process ID is $nPID"

