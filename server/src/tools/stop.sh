#/bin/sh
#start or stop the im-server


function stop() {
    cd $1
    if [ ! -e *.conf  ]
    then
        echo "no config file"
        return
    fi

    if [ -e server.pid  ]; then
        monitor_pid=`ps -ef|grep 'monitor.sh '$1|grep -v grep|awk '{print $2}'`
        echo "kill pid=$monitor_pid"
        kill $monitor_pid

        pid=`cat server.pid`
        echo "kill pid=$pid"
        kill $pid
    fi
    cd -
}

case $1 in
        login_server)
                stop $1
                ;;
        msg_server)
                stop $1
                ;;
        route_server)
                stop $1
                ;;
        http_msg_server)
                stop $1
                ;;
        file_server)
                stop $1
                ;;
       push_server)
                stop $1
                ;;
        db_proxy_server)
                stop $1
                ;;
        all)
                stop login_server
                stop msg_server
                stop route_server
                stop http_msg_server
                stop file_server
                stop push_server
                stop db_proxy_server
                ;;
        *)
                echo "Usage: "
                echo "  ./stop.sh (login_server|msg_server|route_server|http_msg_server|file_server|push_server|all)"
                ;;
esac
