/*
 * ImUser.h
 *
 *  Created on: 2014年4月16日
 *      Author: ziteng
 */

#ifndef IMUSER_H_
#define IMUSER_H_

#include "imconn.h"
#include "public_define.h"
#define MAX_ONLINE_FRIEND_CNT		100	//通知好友状态通知的最多个数

class CMsgConn;

class CImUser
{
public:
    CImUser(uint32_t user_id = 0);
    ~CImUser();
    
    void SetUserId(uint32_t user_id) { m_user_id = user_id; }
    uint32_t GetUserId() { return m_user_id; }
    bool IsValidate() { return m_bValidate; }
    void SetValidated() { m_bValidate = true; }
    uint32_t GetPCLoginStatus() { return m_pc_login_status; }
    void SetPCLoginStatus(uint32_t pc_login_status) { m_pc_login_status = pc_login_status; }
    
    
    user_conn_t GetUserConn();
    
    bool IsMsgConnEmpty() { return m_conn_map.empty(); }
    void AddMsgConn(uint32_t handle, CMsgConn* pMsgConn) { m_conn_map[handle] = pMsgConn; }
    void DelMsgConn(uint32_t handle) { m_conn_map.erase(handle); }
    CMsgConn* GetMsgConn(uint32_t handle);
    CMsgConn* GetMsgConnById(uint32_t app_id, uint32_t domain_id);
    void ValidateMsgConn(uint32_t handle, CMsgConn* pMsgConn);
    
    void AddUnValidateMsgConn(CMsgConn* pMsgConn) { m_unvalidate_conn_set.insert(pMsgConn); }
    void DelUnValidateMsgConn(CMsgConn* pMsgConn) { m_unvalidate_conn_set.erase(pMsgConn); }
    CMsgConn* GetUnValidateMsgConn(uint32_t handle);
    
    map<uint32_t, CMsgConn*>& GetMsgConnMap() { return m_conn_map; }

    void BroadcastPdu(CImPdu* pPdu, CMsgConn* pFromConn = NULL);
    void BroadcastPduWithOutMobile(CImPdu* pPdu, CMsgConn* pFromConn = NULL);
    void BroadcastPduToMobile(CImPdu* pPdu, CMsgConn* pFromConn = NULL);
    void BroadcastClientMsgData(CImPdu* pPdu, uint32_t msg_id, CMsgConn* pFromConn = NULL, uint32_t from_id = 0);
    void BroadcastData(void* buff, uint32_t len, CMsgConn* pFromConn = NULL);
        
    void HandleKickUser(CMsgConn* pConn, uint32_t reason);
    
    bool KickOutSameClientType(uint32_t app_id, uint32_t domain_id, uint32_t reason, CMsgConn* pFromConn = NULL);

	bool CloseMsgConn(uint32_t app_id, uint32_t domain_id);

    uint32_t GetClientTypeFlag();
private:
    uint32_t		m_user_id;
    bool 		m_user_updated;
    uint32_t        m_pc_login_status;  // pc client login状态，1: on 0: off
    
    bool 		m_bValidate;
    
    map<uint32_t /* handle */, CMsgConn*>	m_conn_map;
    set<CMsgConn*> m_unvalidate_conn_set;
};

typedef map<uint32_t /* id */, CImUser*> ImUserMap_t;

class CImUserManager
{
public:
    CImUserManager() {}
    ~CImUserManager();
    
    static CImUserManager* GetInstance();
    CImUser* GetImUserById(uint32_t user_id);
    
    CMsgConn* GetMsgConnByHandle(uint32_t user_id, uint32_t handle);
    
    bool AddImUserById(uint32_t user_id, CImUser* pUser);
    void RemoveImUserById(uint32_t user_id);
    
    void RemoveImUser(CImUser* pUser);
    
    void RemoveAll();
    void GetOnlineUserInfo(list<user_stat_t>* online_user_info);
    void GetUserConnCnt(list<user_conn_t>* user_conn_list, uint32_t& total_conn_cnt);
    
    void BroadcastPdu(CImPdu* pdu, uint32_t client_type_flag);
private:
    ImUserMap_t m_im_user_map;
};

void get_online_user_info(list<user_stat_t>* online_user_info);


#endif /* IMUSER_H_ */
