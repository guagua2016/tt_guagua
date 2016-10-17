/*
 * ImUser.cpp
 *
 *  Created on: 2014年4月16日
 *      Author: ziteng
 *  Brief:
 *  	a map from user_id to userInfo and connection list
 */

#include "ImUser.h"
#include "MsgConn.h"
#include "RouteServConn.h"
#include "IM.Server.pb.h"
#include "IM.Login.pb.h"
using namespace ::IM::BaseDefine;

CImUser::CImUser(uint32_t user_id)
{
    m_bValidate = false;
    m_user_id = user_id;
    m_user_updated = false;
    m_pc_login_status = IM::BaseDefine::USER_STATUS_OFFLINE;
}

CImUser::~CImUser()
{
    //log("~ImUser, userId=%u\n", m_user_id);
}

CMsgConn* CImUser::GetUnValidateMsgConn(uint32_t handle)
{
    for (set<CMsgConn*>::iterator it = m_unvalidate_conn_set.begin(); it != m_unvalidate_conn_set.end(); it++)
    {
        CMsgConn* pConn = *it;
        if (pConn->GetHandle() == handle) {
            return pConn;
        }
    }
    
    return NULL;
}

CMsgConn* CImUser::GetMsgConn(uint32_t handle)
{
    CMsgConn* pMsgConn = NULL;
    map<uint32_t, CMsgConn*>::iterator it = m_conn_map.find(handle);
    if (it != m_conn_map.end()) {
        pMsgConn = it->second;
    }
    return pMsgConn;
}

CMsgConn* CImUser::GetMsgConnById(uint32_t app_id, uint32_t domain_id)
{
    CMsgConn* pMsgConn = NULL;

    for (map<uint32_t, CMsgConn*>::iterator it = m_conn_map.begin(); it != m_conn_map.end(); it++) {
        pMsgConn = it->second;
        
	    if (pMsgConn->getAppId() == app_id
		    && pMsgConn->getDomainId() == domain_id) {
		    break;
        }
    }

    return pMsgConn;
}


void CImUser::ValidateMsgConn(uint32_t handle, CMsgConn* pMsgConn)
{
    AddMsgConn(handle, pMsgConn);
    DelUnValidateMsgConn(pMsgConn);
}


user_conn_t CImUser::GetUserConn()
{
    uint32_t conn_cnt = 0;
    for (map<uint32_t, CMsgConn*>::iterator it = m_conn_map.begin(); it != m_conn_map.end(); it++)
    {
        CMsgConn* pConn = it->second;
        if (pConn->IsOpen()) {
            conn_cnt++;
        }
    }
    
    user_conn_t user_cnt = {m_user_id, conn_cnt};
    return user_cnt;
}

void CImUser::BroadcastPdu(CImPdu* pPdu, CMsgConn* pFromConn)
{
    for (map<uint32_t, CMsgConn*>::iterator it = m_conn_map.begin(); it != m_conn_map.end(); it++)
    {
        CMsgConn* pConn = it->second;
        if (pConn != pFromConn) {
            pConn->SendPdu(pPdu);
        }
    }
}

void CImUser::BroadcastPduWithOutMobile(CImPdu *pPdu, CMsgConn* pFromConn)
{
    for (map<uint32_t, CMsgConn*>::iterator it = m_conn_map.begin(); it != m_conn_map.end(); it++)
    {
        CMsgConn* pConn = it->second;
        if (pConn != pFromConn && pConn->isPCClient()) {
            pConn->SendPdu(pPdu);
        }
    }
}

void CImUser::BroadcastPduToMobile(CImPdu* pPdu, CMsgConn* pFromConn)
{
    for (map<uint32_t, CMsgConn*>::iterator it = m_conn_map.begin(); it != m_conn_map.end(); it++)
    {
        CMsgConn* pConn = it->second;
        if (pConn != pFromConn && pConn->isMobileClient()) {
            pConn->SendPdu(pPdu);
        }
    }
}


void CImUser::BroadcastClientMsgData(CImPdu* pPdu, uint32_t msg_id, CMsgConn* pFromConn, uint32_t from_id)
{
    for (map<uint32_t, CMsgConn*>::iterator it = m_conn_map.begin(); it != m_conn_map.end(); it++)
    {
        CMsgConn* pConn = it->second;
        if (pConn != pFromConn) {
            pConn->SendPdu(pPdu);
            log("###Start AddToSendList msg_id=%d, from_id=%d,handle=%d",msg_id, from_id,pConn->GetHandle());
            pConn->AddToSendList(msg_id, from_id);
        }
    }
}

void CImUser::BroadcastData(void *buff, uint32_t len, CMsgConn* pFromConn)
{
    if(!buff)
        return;
    for (map<uint32_t, CMsgConn*>::iterator it = m_conn_map.begin(); it != m_conn_map.end(); it++)
    {
        CMsgConn* pConn = it->second;
        
        if(pConn == NULL)
            continue;
        
        if (pConn != pFromConn) {
            pConn->Send(buff, len);
        }
    }
}

void CImUser::HandleKickUser(CMsgConn* pConn, uint32_t reason)
{
    map<uint32_t, CMsgConn*>::iterator it = m_conn_map.find(pConn->GetHandle());
    if (it != m_conn_map.end()) {
        CMsgConn* pConn = it->second;
        if(pConn) {
            log("kick service user, user_id=%u.", m_user_id);
            IM::Login::IMKickUser msg;
            msg.set_user_id(m_user_id);
            msg.set_kick_reason((::IM::BaseDefine::KickReasonType)reason);
            CImPdu pdu;
            pdu.SetPBMsg(&msg);
            pdu.SetServiceId(SID_LOGIN);
            pdu.SetCommandId(CID_LOGIN_KICK_USER);
            pConn->SendPdu(&pdu);
            pConn->SetKickOff();
            //pConn->Close();
        }
    }
}

// 只支持一个WINDOWS/MAC客户端登陆,或者一个ios/android登录
bool CImUser::KickOutSameClientType(uint32_t app_id, uint32_t domain_id, uint32_t reason, CMsgConn* pFromConn)
{
    bool is_mobile;
    bool is_pc;

    switch (app_id) {
    case 1:
    case 2:
    case 21:
    case 22:
        is_mobile = true;
        break;
    default:
        is_mobile = false;
        break;
    }

    switch (app_id) {
    case 3:
    case 11:
        is_pc = true;
    default:
        is_pc = false;
    }

    for (map<uint32_t, CMsgConn*>::iterator it = m_conn_map.begin(); it != m_conn_map.end(); it++) {
        CMsgConn* pMsgConn = it->second;
        
	if (pMsgConn != pFromConn 
		&& pMsgConn->getDomainId() == domain_id
		&& pMsgConn->isMobileClient() == is_mobile
		&& pMsgConn->isPCClient() == is_pc) {
		HandleKickUser(pMsgConn, reason);
		break;
        }
    }
    return true;
}

bool CImUser::CloseMsgConn(uint32_t app_id, uint32_t domain_id)
{
    for (map<uint32_t, CMsgConn*>::iterator it = m_conn_map.begin(); it != m_conn_map.end(); it++) {
        CMsgConn* pMsgConn = it->second;
        
    	if ( pMsgConn->getAppId() == app_id
    		&& pMsgConn->getDomainId() == domain_id) {

            log("user %u logout, close msg conn. app_id=%u, domain_id=%u", m_user_id, app_id, domain_id);
            
    		pMsgConn->Close();
    		break;
        }
    }
    return true;
}


uint32_t CImUser::GetClientTypeFlag()
{
    uint32_t client_type_flag = 0x00;
    map<uint32_t, CMsgConn*>::iterator it = m_conn_map.begin();
    for (; it != m_conn_map.end(); it++)
    {
        CMsgConn* pConn = it->second;
        if (pConn->isPCClient())
        {
            client_type_flag |= CLIENT_TYPE_FLAG_PC;
        }
        else if (pConn->isMobileClient())
        {
            client_type_flag |= CLIENT_TYPE_FLAG_MOBILE;
        }
    }
    return client_type_flag;
}


CImUserManager::~CImUserManager()
{
    RemoveAll();
}

CImUserManager* CImUserManager::GetInstance()
{
    static CImUserManager s_manager;
    return &s_manager;
}

CImUser* CImUserManager::GetImUserById(uint32_t user_id)
{
    CImUser* pUser = NULL;
    ImUserMap_t::iterator it = m_im_user_map.find(user_id);
    if (it != m_im_user_map.end()) {
        pUser = it->second;
    }
    return pUser;
}

CMsgConn* CImUserManager::GetMsgConnByHandle(uint32_t user_id, uint32_t handle)
{
    CMsgConn* pMsgConn = NULL;
    CImUser* pImUser = GetImUserById(user_id);
    if (pImUser) {
        pMsgConn = pImUser->GetMsgConn(handle);
    }
    return pMsgConn;
}

bool CImUserManager::AddImUserById(uint32_t user_id, CImUser *pUser)
{
    bool bRet = false;
    if (GetImUserById(user_id) == NULL) {
        m_im_user_map[user_id] = pUser;
        bRet = true;
    }
    return bRet;
}

void CImUserManager::RemoveImUserById(uint32_t user_id)
{
    m_im_user_map.erase(user_id);
}

void CImUserManager::RemoveImUser(CImUser *pUser)
{
    if (pUser != NULL) {
        RemoveImUserById(pUser->GetUserId());
        delete pUser;
        pUser = NULL;
    }
}

void CImUserManager::RemoveAll()
{
    for (ImUserMap_t::iterator it = m_im_user_map.begin(); it != m_im_user_map.end();
         it++)
    {
        CImUser* pUser = it->second;
        if (pUser != NULL) {
            delete pUser;
            pUser = NULL;
        }
    }
    m_im_user_map.clear();
}

void CImUserManager::GetOnlineUserInfo(list<user_stat_t>* online_user_info)
{
    user_stat_t status;
    CImUser* pImUser = NULL;
    for (ImUserMap_t::iterator it = m_im_user_map.begin(); it != m_im_user_map.end(); it++) {
        pImUser = (CImUser*)it->second;
        if (pImUser->IsValidate()) {
            map<uint32_t, CMsgConn*>& ConnMap = pImUser->GetMsgConnMap();
            for (map<uint32_t, CMsgConn*>::iterator it = ConnMap.begin(); it != ConnMap.end(); it++)
            {
                CMsgConn* pConn = it->second;
                if (pConn->IsOpen())
                {
                    status.user_id = pImUser->GetUserId();
                    status.status = pConn->GetOnlineStatus();
                    status.app_id = pConn->getAppId();
                    status.domain_id = pConn->getDomainId();
                    online_user_info->push_back(status);
                }
            }
        }
    }
}

void CImUserManager::GetUserConnCnt(list<user_conn_t>* user_conn_list, uint32_t& total_conn_cnt)
{
    total_conn_cnt = 0;
    CImUser* pImUser = NULL;
    for (ImUserMap_t::iterator it = m_im_user_map.begin(); it != m_im_user_map.end(); it++)
    {
        pImUser = (CImUser*)it->second;
        if (pImUser->IsValidate())
        {
            user_conn_t user_conn_cnt = pImUser->GetUserConn();
            user_conn_list->push_back(user_conn_cnt);
            total_conn_cnt += user_conn_cnt.conn_cnt;
        }
    }
}

void CImUserManager::BroadcastPdu(CImPdu* pdu, uint32_t client_type_flag)
{
    CImUser* pImUser = NULL;
    for (ImUserMap_t::iterator it = m_im_user_map.begin(); it != m_im_user_map.end(); it++)
    {
        pImUser = (CImUser*)it->second;
        if (pImUser->IsValidate())
        {
            switch (client_type_flag) {
                case CLIENT_TYPE_FLAG_PC:
                    pImUser->BroadcastPduWithOutMobile(pdu);
                    break;
                case CLIENT_TYPE_FLAG_MOBILE:
                    pImUser->BroadcastPduToMobile(pdu);
                    break;
                case CLIENT_TYPE_FLAG_BOTH:
                    pImUser->BroadcastPdu(pdu);
                    break;
                default:
                    break;
            }
        }
    }
}

