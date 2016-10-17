/*
 * LoginConn.cpp
 *
 *  Created on: 2013-6-21
 *      Author: ziteng@mogujie.com
 */

#include "LoginConn.h"
#include "HttpConn.h"
#include "DBServConn.h"
#include "AttachData.h"
#include "EventDispatch.h"
#include "IM.Server.pb.h"
#include "IM.Other.pb.h"
#include "IM.Login.pb.h"
#include "public_define.h"
using namespace IM::BaseDefine;
static ConnMap_t g_client_conn_map;
static ConnMap_t g_msg_serv_conn_map;
static uint32_t g_total_online_user_cnt = 0;	// 并发在线总人数
map<uint32_t, msg_serv_info_t*> g_msg_serv_info;
static rb_timer_item g_conn_timer;

void login_conn_timer_callback(void* callback_data, uint8_t msg, uint32_t handle, void* pParam)
{
	//DEBUG("******Enter login_conn_timer_callback");
	uint64_t cur_time = get_tick_count();

	static uint64_t start_time = get_tick_count();

	for (ConnMap_t::iterator it = g_client_conn_map.begin(); it != g_client_conn_map.end(); ) {
		ConnMap_t::iterator it_old = it;
		it++;

		CLoginConn* pConn = (CLoginConn*)it_old->second;
		pConn->OnTimer(cur_time);
	}

	for (ConnMap_t::iterator it = g_msg_serv_conn_map.begin(); it != g_msg_serv_conn_map.end(); ) {
		ConnMap_t::iterator it_old = it;
		it++;

		CLoginConn* pConn = (CLoginConn*)it_old->second;
		pConn->OnTimer(cur_time);
	}

#if 0
	if ( (cur_time - start_time) > 30000 )
	{
		//DEBUG("*****Start remove timer");
		netlib_disable_timer(&g_conn_timer);
	}
#endif 0

}

void unregister_user(uint32_t user_id, uint32_t app_id, uint32_t domain_id)
{
    // Should not kill the same users in the unregister process.
#if 0
	IM::Server::IMServerKickUser msg;
	msg.set_user_id(user_id);
	msg.set_app_id(app_id);
	msg.set_domain_id(domain_id);
	msg.set_reason(IM::BaseDefine::KICK_REASON_DUPLICATE_USER);
	CImPdu pdu;
	pdu.SetPBMsg(&msg);
	pdu.SetServiceId(SID_OTHER);
	pdu.SetCommandId(CID_OTHER_SERVER_KICK_USER);

	for (ConnMap_t::iterator it = g_msg_serv_conn_map.begin(); it != g_msg_serv_conn_map.end(); it++) {
		CLoginConn *pConn = (CLoginConn*)it->second;
		if (pConn != NULL) {
			pConn->SendPdu(&pdu);
		}
	}
#else
    log("unregister_user, user_id=%d, app_id=%d, domain_id=%d, ", user_id, app_id, domain_id);

	IM::Login::IMLogoutReq msg;
	msg.set_user_id(user_id);
	msg.set_app_id(app_id);
	msg.set_domain_id(domain_id);	
	CImPdu pdu;
	pdu.SetPBMsg(&msg);
	pdu.SetServiceId(SID_LOGIN);
	pdu.SetCommandId(CID_LOGIN_REQ_LOGINOUT);
	
	for (ConnMap_t::iterator it = g_msg_serv_conn_map.begin(); it != g_msg_serv_conn_map.end(); it++) {
		CLoginConn *pConn = (CLoginConn*)it->second;
		if (pConn != NULL) {
			pConn->SendPdu(&pdu);
		}
	}
#endif
}

void get_user_token(CHttpConn *pHttpConn, uint32_t user_id, uint32_t app_id, uint32_t domain_id)
{
    log("get_user_token, user_id=%d, app_id=%d, domain_id=%d, ", user_id, app_id, domain_id);
	CDBServConn *pDbConn = get_db_serv_conn();
	if (pDbConn != NULL) {
		IM::Login::IMGetUserTokenReq msg;
		msg.set_user_id(user_id);
		msg.set_app_id(app_id);
		msg.set_domain_id(domain_id);
		CDbAttachData attach_data(ATTACH_TYPE_HANDLE, pHttpConn->GetConnHandle(), 0);
		msg.set_attach_data(attach_data.GetBuffer(), attach_data.GetLength());
		CImPdu pdu;
		pdu.SetPBMsg(&msg);
		pdu.SetServiceId(SID_LOGIN);
		pdu.SetCommandId(CID_LOGIN_REQ_USERTOKEN);
		pDbConn->SendPdu(&pdu);
	}
}		

void init_login_conn()
{
	//netlib_register_timer(login_conn_timer_callback, NULL, 1000);
	rbtimer_init(&g_conn_timer,login_conn_timer_callback,NULL,1000,0,0);
	netlib_register_timer(&g_conn_timer);
}

CLoginConn::CLoginConn()
{
}

CLoginConn::~CLoginConn()
{

}

void CLoginConn::Close()
{
	if (m_handle != NETLIB_INVALID_HANDLE) {
		netlib_close(m_handle);
		if (m_conn_type == LOGIN_CONN_TYPE_CLIENT) {
			g_client_conn_map.erase(m_handle);
		} else {
			g_msg_serv_conn_map.erase(m_handle);

			// remove all user count from this message server
			map<uint32_t, msg_serv_info_t*>::iterator it = g_msg_serv_info.find(m_handle);
			if (it != g_msg_serv_info.end()) {
				msg_serv_info_t* pMsgServInfo = it->second;

				g_total_online_user_cnt -= pMsgServInfo->cur_conn_cnt;
				log("onclose from MsgServer: %s:%u ", pMsgServInfo->hostname.c_str(), pMsgServInfo->port);
				delete pMsgServInfo;
				g_msg_serv_info.erase(it);
			}
		}
	}

	ReleaseRef();
}

void CLoginConn::OnConnect2(net_handle_t handle, int conn_type)
{
	m_handle = handle;
	m_conn_type = conn_type;
	ConnMap_t* conn_map = &g_msg_serv_conn_map;
	if (conn_type == LOGIN_CONN_TYPE_CLIENT) {
		conn_map = &g_client_conn_map;
	}else

	conn_map->insert(make_pair(handle, this));

	netlib_option(handle, NETLIB_OPT_SET_CALLBACK, (void*)imconn_callback);
	netlib_option(handle, NETLIB_OPT_SET_CALLBACK_DATA, (void*)conn_map);
}

void CLoginConn::OnClose()
{
    log("onclose in CLoginConn, handle=%d", m_handle);
	Close();
}

void CLoginConn::OnTimer(uint64_t curr_tick)
{
	if (m_conn_type == LOGIN_CONN_TYPE_CLIENT) {
		if (curr_tick > m_last_recv_tick + CLIENT_TIMEOUT) {
			Close();
		}
	} else {
		if (curr_tick > m_last_send_tick + SERVER_HEARTBEAT_INTERVAL) {
            IM::Other::IMHeartBeat msg;
            CImPdu pdu;
            pdu.SetPBMsg(&msg);
            pdu.SetServiceId(SID_OTHER);
            pdu.SetCommandId(CID_OTHER_HEARTBEAT);
			SendPdu(&pdu);
		}

		if (curr_tick > m_last_recv_tick + SERVER_TIMEOUT) {
			log("connection to MsgServer timeout ");
			Close();
		}
	}
}

void CLoginConn::HandlePdu(CImPdu* pPdu)
{
	switch (pPdu->GetCommandId()) {
        case CID_OTHER_HEARTBEAT:
            break;
        case CID_OTHER_MSG_SERV_INFO:
            _HandleMsgServInfo(pPdu);
            break;
        case CID_OTHER_USER_CNT_UPDATE:
            _HandleUserCntUpdate(pPdu);
            break;
        case CID_LOGIN_REQ_MSGSERVER:
            _HandleMsgServRequest(pPdu);
            break;

        default:
            log("wrong msg, cmd id=%d ", pPdu->GetCommandId());
            break;
	}
}

void CLoginConn::_HandleMsgServInfo(CImPdu* pPdu)
{
	msg_serv_info_t* pMsgServInfo = new msg_serv_info_t;
    IM::Server::IMMsgServInfo msg;
    msg.ParseFromArray(pPdu->GetBodyData(), pPdu->GetBodyLength());
    
	pMsgServInfo->ip_addr1 = msg.ip1();
	pMsgServInfo->ip_addr2 = msg.ip2();
	pMsgServInfo->port = msg.port();
	pMsgServInfo->max_conn_cnt = msg.max_conn_cnt();
	pMsgServInfo->cur_conn_cnt = msg.cur_conn_cnt();
	pMsgServInfo->hostname = msg.host_name();
	g_msg_serv_info.insert(make_pair(m_handle, pMsgServInfo));

	g_total_online_user_cnt += pMsgServInfo->cur_conn_cnt;

	log("MsgServInfo, ip_addr1=%s, ip_addr2=%s, port=%d, max_conn_cnt=%d, cur_conn_cnt=%d, "\
		"hostname: %s. ",
		pMsgServInfo->ip_addr1.c_str(), pMsgServInfo->ip_addr2.c_str(), pMsgServInfo->port,pMsgServInfo->max_conn_cnt,
		pMsgServInfo->cur_conn_cnt, pMsgServInfo->hostname.c_str());
}

void CLoginConn::_HandleUserCntUpdate(CImPdu* pPdu)
{
	map<uint32_t, msg_serv_info_t*>::iterator it = g_msg_serv_info.find(m_handle);
	if (it != g_msg_serv_info.end()) {
		msg_serv_info_t* pMsgServInfo = it->second;
        IM::Server::IMUserCntUpdate msg;
        msg.ParseFromArray(pPdu->GetBodyData(), pPdu->GetBodyLength());
        uint32_t user_id = msg.user_id();

		uint32_t action = msg.user_action();
		if (action == USER_CNT_INC) {
			pMsgServInfo->cur_conn_cnt++;
			g_total_online_user_cnt++;
		} else {
			pMsgServInfo->cur_conn_cnt--;
			g_total_online_user_cnt--;
		}

		log("%s:%d, user %d update %d, cur_cnt=%u, total_cnt=%u ", pMsgServInfo->hostname.c_str(),
            pMsgServInfo->port, user_id, action, pMsgServInfo->cur_conn_cnt, g_total_online_user_cnt);
	}
}

void CLoginConn::_HandleMsgServRequest(CImPdu* pPdu)
{
    IM::Login::IMMsgServReq msg;
    msg.ParseFromArray(pPdu->GetBodyData(), pPdu->GetBodyLength());

	log("HandleMsgServReq. ");

	// no MessageServer available
	if (g_msg_serv_info.size() == 0) {
        IM::Login::IMMsgServRsp msg;
        msg.set_result_code(::IM::BaseDefine::REFUSE_REASON_NO_MSG_SERVER);
        CImPdu pdu;
        pdu.SetPBMsg(&msg);
        pdu.SetServiceId(SID_LOGIN);
        pdu.SetCommandId(CID_LOGIN_RES_MSGSERVER);
        pdu.SetSeqNum(pPdu->GetSeqNum());
        SendPdu(&pdu);
        Close();
		return;
	}

	// return a message server with minimum concurrent connection count
	msg_serv_info_t* pMsgServInfo;
	uint32_t min_user_cnt = (uint32_t)-1;
	map<uint32_t, msg_serv_info_t*>::iterator it_min_conn = g_msg_serv_info.end(),it;

	for (it = g_msg_serv_info.begin() ; it != g_msg_serv_info.end(); it++) {
		pMsgServInfo = it->second;
		if ( (pMsgServInfo->cur_conn_cnt < pMsgServInfo->max_conn_cnt) &&
			 (pMsgServInfo->cur_conn_cnt < min_user_cnt))
        {
			it_min_conn = it;
			min_user_cnt = pMsgServInfo->cur_conn_cnt;
		}
	}

	if (it_min_conn == g_msg_serv_info.end()) {
		log("All TCP MsgServer are full ");
        IM::Login::IMMsgServRsp msg;
        msg.set_result_code(::IM::BaseDefine::REFUSE_REASON_MSG_SERVER_FULL);
        CImPdu pdu;
        pdu.SetPBMsg(&msg);
        pdu.SetServiceId(SID_LOGIN);
        pdu.SetCommandId(CID_LOGIN_RES_MSGSERVER);
        pdu.SetSeqNum(pPdu->GetSeqNum());
        SendPdu(&pdu);
	}
    else
    {
        IM::Login::IMMsgServRsp msg;
        msg.set_result_code(::IM::BaseDefine::REFUSE_REASON_NONE);
        msg.set_prior_ip(it_min_conn->second->ip_addr1);
        msg.set_backip_ip(it_min_conn->second->ip_addr2);
        msg.set_port(it_min_conn->second->port);
        CImPdu pdu;
        pdu.SetPBMsg(&msg);
        pdu.SetServiceId(SID_LOGIN);
        pdu.SetCommandId(CID_LOGIN_RES_MSGSERVER);
        pdu.SetSeqNum(pPdu->GetSeqNum());
        SendPdu(&pdu);
    }

	Close();	// after send MsgServResponse, active close the connection
}
