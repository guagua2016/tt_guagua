/*
 * login_server.cpp
 *
 *  Created on: 2013-6-21
 *      Author: ziteng@mogujie.com
 */

#include "LoginConn.h"
#include "netlib.h"
#include "ConfigFileReader.h"
#include "version.h"
#include "HttpConn.h"
#include "DBServConn.h"
#include "ipparser.h"
#include "tt_core.h"
#include <memory>

IpParser* pIpParser = NULL;
string strMsfsUrl;
string strDiscovery;//发现获取地址

void client_callback(void* callback_data, uint8_t msg, uint32_t handle, void* pParam)
{
	if (msg == NETLIB_MSG_CONNECT)
	{
		CLoginConn* pConn = new CLoginConn();
		pConn->OnConnect2(handle, LOGIN_CONN_TYPE_CLIENT);
	}
	else
	{
		log("!!!error msg: %d ", msg);
	}
}

// this callback will be replaced by imconn_callback() in OnConnect()
void msg_serv_callback(void* callback_data, uint8_t msg, uint32_t handle, void* pParam)
{
    log("msg_server come in");

	if (msg == NETLIB_MSG_CONNECT)
	{
		CLoginConn* pConn = new CLoginConn();
		pConn->OnConnect2(handle, LOGIN_CONN_TYPE_MSG_SERV);
	}
	else
	{
		log("!!!error msg: %d ", msg);
	}
}


void http_callback(void* callback_data, uint8_t msg, uint32_t handle, void* pParam)
{
    if (msg == NETLIB_MSG_CONNECT)
    {
        CHttpConn* pConn = new CHttpConn();
        pConn->OnConnect(handle);
    }
    else
    {
        log("!!!error msg: %d ", msg);
    }
}

#include "EventDispatch.h"
void test_timer_callback(void* callback_data, uint8_t msg, uint32_t handle, void* pParam)
{
	UNUSED(callback_data);
	UNUSED(msg);
	UNUSED(handle);
	UNUSED(pParam);
	return;
}

int main(int argc, char* argv[])
{
    if ((argc == 2) && (strcmp(argv[1], "-v") == 0)) {
        printf("Server Version: LoginServer/%s\n", VERSION);
        printf("Server Build: %s %s\n", __DATE__, __TIME__);
        return 0;
    }

    signal(SIGPIPE, SIG_IGN);
    tzset();

    CConfigFileReader config_file("loginserver.conf");

    char* client_listen_ip = config_file.GetConfigName("ClientListenIP");
    char* str_client_port = config_file.GetConfigName("ClientPort");
    char* http_listen_ip = config_file.GetConfigName("HttpListenIP");
    char* str_http_port = config_file.GetConfigName("HttpPort");
    char* msg_server_listen_ip = config_file.GetConfigName("MsgServerListenIP");
    char* str_msg_server_port = config_file.GetConfigName("MsgServerPort");
    char* db_server_ip = config_file.GetConfigName("DBServerIP");
    char* str_db_server_port = config_file.GetConfigName("DBServerPort");

    char* str_msfs_url = config_file.GetConfigName("msfs");
    char* str_discovery = config_file.GetConfigName("discovery");

    if (!msg_server_listen_ip || !str_msg_server_port || !http_listen_ip
        || !str_http_port || !str_msfs_url || !str_discovery
        || !db_server_ip || !str_db_server_port) {
		log("config item missing, exit... ");
		return -1;
    }

    uint16_t client_port = atoi(str_client_port);
    uint16_t msg_server_port = atoi(str_msg_server_port);
    uint16_t http_port = atoi(str_http_port);
    uint16_t db_server_port = atoi(str_db_server_port);

    strMsfsUrl = str_msfs_url;
    strDiscovery = str_discovery;
    
    
    pIpParser = new IpParser();
    
	int ret = netlib_init();

	if (ret == NETLIB_ERROR)
		return ret;
	CStrExplode client_listen_ip_list(client_listen_ip, ';');
	for (uint32_t i = 0; i < client_listen_ip_list.GetItemCnt(); i++) {
		ret = netlib_listen(client_listen_ip_list.GetItem(i), client_port, client_callback, NULL);
		if (ret == NETLIB_ERROR)
			return ret;
	}

	CStrExplode msg_server_listen_ip_list(msg_server_listen_ip, ';');
	for (uint32_t i = 0; i < msg_server_listen_ip_list.GetItemCnt(); i++) {
		ret = netlib_listen(msg_server_listen_ip_list.GetItem(i), msg_server_port, msg_serv_callback, NULL);
		if (ret == NETLIB_ERROR)
			return ret;
	}
    
    CStrExplode http_listen_ip_list(http_listen_ip, ';');
    for (uint32_t i = 0; i < http_listen_ip_list.GetItemCnt(); i++) {
        ret = netlib_listen(http_listen_ip_list.GetItem(i), http_port, http_callback, NULL);
        if (ret == NETLIB_ERROR)
            return ret;
    }
    
    log("server start listen on:\nFor client %s:%d\nFor MsgServer: %s:%d\nFor http:%s:%d\n",
        client_listen_ip, client_port, msg_server_listen_ip, msg_server_port, http_listen_ip, http_port);
    init_login_conn();
    init_http_conn();
    init_db_serv_conn(db_server_ip, db_server_port);

#if 0
    //rb_timer_item conn_timer;
    for (int i = 0; i < 100; i++)
    {
    	rb_timer_item *conn_timer = (rb_timer_item *)malloc(sizeof(rb_timer_item));
    	//std::shared_ptr<rb_timer_item> conn_timer = std::make_shared<rb_timer_item>();
    	sleep(1);
    	rbtimer_init(conn_timer,test_timer_callback,NULL,1000,0,0);
    	netlib_register_timer(conn_timer);
    }
#endif //0

    log("now enter the event loop...\n");
    
   //DEBUG("###timer tree count = %d.",CEventDispatch::Instance()->TimerTreeNodeCount());
    //DEBUG("###timer tree hight = %d.",CEventDispatch::Instance()->TimerTreeHight());

    writePid();

	netlib_eventloop();

	return 0;
}
