/*
 * DBServConn.cpp
 *
 *  Created on: 2013-7-8
 *      Author: ziteng@mogujie.com
 */

#include "DBServConn.h"
#include "ImPduBase.h"
#include "AttachData.h"
#include "HttpConn.h"
#include "EventDispatch.h"

#include "IM.Other.pb.h"
#include "IM.Login.pb.h"
#include "public_define.h"

using namespace IM::BaseDefine;

static CDBServConn *g_db_server_conn;
static string g_db_server_ip;
static int32_t g_db_server_portNum;
static rb_timer_item g_db_server_conn_timer;

static void db_server_conn_timer_callback(void* callback_data, uint8_t msg, uint32_t handle, void* pParam)
{
	//DEBUG("###Enter db_server_conn_timer_callback");
	ConnMap_t::iterator it_old;
	CDBServConn* pConn = NULL;
	uint64_t cur_time = get_tick_count();

	if (g_db_server_conn != NULL && g_db_server_conn->IsOpen()) {
		g_db_server_conn->OnTimer(cur_time);
	}

	//TODO: reconnect db server
	if (g_db_server_conn == NULL) {
		log("Start reconnect to db_server");
		g_db_server_conn = new CDBServConn();
		g_db_server_conn->Connect(g_db_server_ip.c_str(), g_db_server_portNum);
	}
}

static void dbservconn_callback(void* callback_data, uint8_t msg, uint32_t handle, void* pParam)
{
	(void)callback_data;
	(void)handle;
	(void)pParam;

	if (g_db_server_conn == NULL) return;

	CDBServConn *pConn = g_db_server_conn;
	switch (msg) {
	case NETLIB_MSG_CONFIRM:
		pConn->OnConfirm();
		break;
	case NETLIB_MSG_READ:
		pConn->OnRead();
		break;
	case NETLIB_MSG_WRITE:
		pConn->OnWrite();
		break;
	case NETLIB_MSG_CLOSE:
		pConn->OnClose();
		break;
	default:
		loge("!!!dbservconn_callback error msg: %d ", msg);
		break;
        }
}

void init_db_serv_conn(string server_ip, uint16_t port)
{
	g_db_server_ip = server_ip;
	g_db_server_portNum = port;
	if (g_db_server_conn == NULL) {
		g_db_server_conn = new CDBServConn();
		g_db_server_conn->Connect(server_ip.c_str(), port);
	}
	//netlib_register_timer(db_server_conn_timer_callback, NULL, 1000);
	rbtimer_init(&g_db_server_conn_timer,db_server_conn_timer_callback,NULL,1000,0,0);
	netlib_register_timer(&g_db_server_conn_timer);
}

CDBServConn* get_db_serv_conn()
{
	return g_db_server_conn;
}

CDBServConn::CDBServConn()
{
	m_bOpen = false;
}

CDBServConn::~CDBServConn()
{
	log("Enter CDBServConn::~CDBServConn");
}

void CDBServConn::Connect(const char* server_ip, uint16_t server_port)
{
	if (g_db_server_conn == NULL || g_db_server_conn == this) {
		log("Connecting to DB Storage Server %s:%d ", server_ip, server_port);
		m_handle = netlib_connect(server_ip, server_port, dbservconn_callback, NULL);
	} else {
		loge("DB server connection already exists.");
	}
}

void CDBServConn::Close()
{
	if (m_handle != NETLIB_INVALID_HANDLE) {
		log("disconnect to db_server");
		netlib_close(m_handle);
		g_db_server_conn = NULL;
	}

	ReleaseRef();
}

void CDBServConn::OnConfirm()
{
	log("connect to db server success");
	m_bOpen = true;
}

void CDBServConn::OnClose()
{
	log("onclose from db server handle=%d", m_handle);
	Close();
}

void CDBServConn::OnTimer(uint64_t curr_tick)
{
	if (curr_tick > m_last_send_tick + SERVER_HEARTBEAT_INTERVAL) {
		IM::Other::IMHeartBeat msg;
		CImPdu pdu;
		pdu.SetPBMsg(&msg);
		pdu.SetServiceId(SID_OTHER);
		pdu.SetCommandId(CID_OTHER_HEARTBEAT);
		SendPdu(&pdu);
	}

	if (curr_tick > m_last_recv_tick + SERVER_TIMEOUT) {
		log("conn to db server timeout");
		Close();
	}
}

void CDBServConn::HandlePdu(CImPdu* pPdu)
{
	switch (pPdu->GetCommandId()) {
        case CID_OTHER_HEARTBEAT:
		    break;
	    case CID_LOGIN_RES_USERTOKEN:
		    _HandleGetUserTokenRsp(pPdu);
		    break;
        default:
            log("db server, wrong cmd id=%d ", pPdu->GetCommandId());
	}
}

void CDBServConn::_HandleGetUserTokenRsp(CImPdu* pPdu)
{
	IM::Login::IMGetUserTokenRsp msg;
	CHECK_PB_PARSE_MSG(msg.ParseFromArray(pPdu->GetBodyData(), pPdu->GetBodyLength()));

	uint32_t user_id = msg.user_id();
	uint32_t app_id = msg.app_id();
	uint32_t domain_id = msg.domain_id();
	uint32_t result_code = msg.result_code();
	string result_string = msg.result_string();
	string user_token = msg.user_token();
	
	log("HandleGetUserTokenRsp: uid=%u, app_id=%u, domain_id=%u", user_id, app_id, domain_id);
	if (result_code != 0) {
		loge("Unable to get user token:%u/%s", result_code, result_string.c_str());
		return;
	}
	CDbAttachData attach_data((uchar_t*)msg.attach_data().c_str(), msg.attach_data().length());	
	uint32_t handle = attach_data.GetHandle();

	CHttpConn *pConn = FindHttpConnByHandle(handle);
	if (pConn != NULL) {
		pConn->onGetUserToken(user_token);
	} else {
		loge("Invalid Http handle:%u", handle);
	}
}
