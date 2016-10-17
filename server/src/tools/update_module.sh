#!/bin/bash


PID=$(pgrep $1)
#echo $PID
if [ -n "$PID" ]; then
    echo $PID
    echo "Start kill $1"
    kill -TERM $PID
else
    echo "$1 not running"
fi
OS_BIT=$(getconf LONG_BIT)
#PID=$(pgrep $1)
#echo $PID
echo "Start copying $1"
sleep 3 
cp $1 ../../../server/im-server-test/$1/ 
