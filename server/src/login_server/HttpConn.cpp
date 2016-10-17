/*
 * HttpConn.cpp
 *
 *  Created on: 2013-9-29
 *      Author: ziteng@mogujie.com
 */

#include "Base64.h"
#include "HttpConn.h"
#include "json/json.h"
#include "LoginConn.h"
#include "HttpParserWrapper.h"
#include "ipparser.h"

static HttpConnMap_t g_http_conn_map;

extern map<uint32_t, msg_serv_info_t*>  g_msg_serv_info;

extern IpParser* pIpParser;
extern string strMsfsUrl;
extern string strDiscovery;
static rb_timer_item g_httpConn_timer;
// conn_handle 从0开始递增，可以防止因socket handle重用引起的一些冲突
static uint32_t g_conn_handle_generator = 0;

CHttpConn* FindHttpConnByHandle(uint32_t conn_handle)
{
    CHttpConn* pConn = NULL;
    HttpConnMap_t::iterator it = g_http_conn_map.find(conn_handle);
    if (it != g_http_conn_map.end()) {
        pConn = it->second;
    }

    return pConn;
}

void httpconn_callback(void* callback_data, uint8_t msg, uint32_t handle, uint32_t uParam, void* pParam)
{
    NOTUSED_ARG(uParam);
    NOTUSED_ARG(pParam);

    // convert void* to uint32_t, oops
    uint32_t conn_handle = *((uint32_t*)(&callback_data));
    CHttpConn* pConn = FindHttpConnByHandle(conn_handle);
    if (!pConn) {
        return;
    }

	switch (msg)
	{
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
		log("!!!httpconn_callback error msg: %d ", msg);
		break;
	}
}

void http_conn_timer_callback(void* callback_data, uint8_t msg, uint32_t handle, void* pParam)
{
	//DEBUG("###Enter http_conn_timer_callback");
	(void)callback_data;
	(void)msg;
	(void)handle;
	(void)pParam;

	CHttpConn* pConn = NULL;
	HttpConnMap_t::iterator it, it_old;
	uint64_t cur_time = get_tick_count();

	for (it = g_http_conn_map.begin(); it != g_http_conn_map.end(); ) {
		it_old = it;
		it++;

		pConn = it_old->second;
		pConn->OnTimer(cur_time);
	}
}



void init_http_conn()
{
	//netlib_register_timer(http_conn_timer_callback, NULL, 1000);
	rbtimer_init(&g_httpConn_timer,http_conn_timer_callback,NULL,1000,0,0);
	netlib_register_timer(&g_httpConn_timer);
}

//////////////////////////
CHttpConn::CHttpConn()
{
	m_busy = false;
	m_sock_handle = NETLIB_INVALID_HANDLE;
	m_state = CONN_STATE_IDLE;
    
	m_last_send_tick = m_last_recv_tick = get_tick_count();
	m_conn_handle = ++g_conn_handle_generator;
	if (m_conn_handle == 0) {
		m_conn_handle = ++g_conn_handle_generator;
	}


	//log("CHttpConn, handle=%u\n", m_conn_handle);
}

CHttpConn::~CHttpConn()
{
	//log("~CHttpConn, handle=%u\n", m_conn_handle);
}

int CHttpConn::Send(void* data, int len)
{
	m_last_send_tick = get_tick_count();

	if (m_busy)
	{
		m_out_buf.Write(data, len);
		return len;
	}

	int ret = netlib_send(m_sock_handle, data, len);
	if (ret < 0)
		ret = 0;

	if (ret < len)
	{
		m_out_buf.Write((char*)data + ret, len - ret);
		m_busy = true;
		//log("not send all, remain=%d\n", m_out_buf.GetWriteOffset());
	} else {
		OnWriteComplete();
	}
	return len;
}

void CHttpConn::Close()
{
    m_state = CONN_STATE_CLOSED;
    
    g_http_conn_map.erase(m_conn_handle);
    netlib_close(m_sock_handle);
    ReleaseRef();
}

void CHttpConn::OnConnect(net_handle_t handle)
{
    printf("OnConnect, handle=%d\n", handle);
    m_sock_handle = handle;
    m_state = CONN_STATE_CONNECTED;
    g_http_conn_map.insert(make_pair(m_conn_handle, this));
    
    netlib_option(handle, NETLIB_OPT_SET_CALLBACK, (void*)httpconn_callback);
    netlib_option(handle, NETLIB_OPT_SET_CALLBACK_DATA, reinterpret_cast<void *>(m_conn_handle) );
    netlib_option(handle, NETLIB_OPT_GET_REMOTE_IP, (void*)&m_peer_ip);
}

#define IM_UNREGISTER		"im.unregister"
#define IM_CONNECT		"im.connect"
#define IM_REFRESH_TOKEN	"im.refreshToken"

void CHttpConn::OnRead()
{
	for (;;)
	{
		uint32_t free_buf_len = m_in_buf.GetAllocSize() - m_in_buf.GetWriteOffset();
		if (free_buf_len < READ_BUF_SIZE + 1)
			m_in_buf.Extend(READ_BUF_SIZE + 1);

		int ret = netlib_recv(m_sock_handle, m_in_buf.GetBuffer() + m_in_buf.GetWriteOffset(), READ_BUF_SIZE);
		if (ret <= 0)
			break;

		m_in_buf.IncWriteOffset(ret);

		m_last_recv_tick = get_tick_count();
	}

	// 每次请求对应一个HTTP连接，所以读完数据后，不用在同一个连接里面准备读取下个请求
	char* in_buf = (char*)m_in_buf.GetBuffer();
	uint32_t buf_len = m_in_buf.GetWriteOffset();
	in_buf[buf_len] = '\0';

	// 如果buf_len 过长可能是受到攻击，则断开连接
	// 正常的url最大长度为2048，我们接受的所有数据长度不得大于1K
	if(buf_len > 1024) {
		loge("get too much data:%d ", buf_len);
		Close();
		return;
	}

	//log("OnRead, buf_len=%u, conn_handle=%u\n", buf_len, m_conn_handle); // for debug

	
	m_cHttpParser.ParseHttpContent(in_buf, buf_len);

	if (m_cHttpParser.IsReadAll()) {
		string url = _urlDecode(m_cHttpParser.GetUrl());
		size_t pos = url.find('?');
		if (pos != std::string::npos) {
			size_t equal_pos = 0, ampersand_pos = 0;
			string name, value;
			string params = url.substr(pos + 1);
			pos = 0;
			while (pos < params.length()) {
				equal_pos = params.find('=', pos);
				if (equal_pos == std::string::npos) {
					loge("invalid parameter name:%s", params.c_str());
					Close();
				}
				name = params.substr(pos, equal_pos - pos);
				pos = equal_pos + 1;
				ampersand_pos = params.find('&', pos);
				if (ampersand_pos == std::string::npos) {
					// to the end
					value = params.substr(pos);
					pos = params.length();
				} else {
					value = params.substr(pos, ampersand_pos - pos);
					pos = ampersand_pos + 1;
				}
				mParams.insert(make_pair(name, value));
			}
			ParamMap_t::iterator it = mParams.find("method_id");
			string method;
			if (it == mParams.end() || (method = it->second).empty()) {
				loge("Not contain methoid_id parameter");
				Close();
			} else {
				size_t len = strlen(method.c_str());
				if (len == strlen(IM_UNREGISTER) && strncmp(method.c_str(), IM_UNREGISTER, len) == 0) {
					mMethodId = METHOD_UNREGISTER;
				} else if (len == strlen(IM_CONNECT) && strncmp(method.c_str(), IM_CONNECT, len) == 0) {
					mMethodId = METHOD_CONNECT;
				} else if (len == strlen(IM_REFRESH_TOKEN) && strncmp(method.c_str(), IM_REFRESH_TOKEN, len) == 0) {
					mMethodId = METHOD_REFRESH_TOKEN;
				} else {
					mMethodId = -1;
				}
				_HandleRequest();
			}
			
		} else {
			log("url unknown, url=%s ", url.c_str());
			Close();
		}
	}
}

void CHttpConn::OnWrite()
{
	if (!m_busy)
		return;

	int ret = netlib_send(m_sock_handle, m_out_buf.GetBuffer(), m_out_buf.GetWriteOffset());
	if (ret < 0)
		ret = 0;

	int out_buf_size = (int)m_out_buf.GetWriteOffset();

	m_out_buf.Read(NULL, ret);

	if (ret < out_buf_size)
	{
		m_busy = true;
		log("not send all, remain=%d ", m_out_buf.GetWriteOffset());
	}
	else
	{
		OnWriteComplete();
		m_busy = false;
	}
}

void CHttpConn::OnClose()
{
    Close();
}

void CHttpConn::OnTimer(uint64_t curr_tick)
{
	if (curr_tick > m_last_recv_tick + HTTP_CONN_TIMEOUT) {
		log("HttpConn timeout, handle=%d ", m_conn_handle);
		Close();
	}
}

void CHttpConn::_HandleRequest()
{
	uint32_t uid;
	uint32_t aid;
	uint32_t did;

	if (mMethodId == -1) {
		loge("No method_id");
		Close();
		return;
	}

	switch (mMethodId) {
	case METHOD_UNREGISTER:
	case METHOD_CONNECT:
	case METHOD_REFRESH_TOKEN:
	{
		string user_id;
		string app_id;
		string domain_id;

		ParamMap_t::iterator it = mParams.find("user_id");
		if (it == mParams.end() || (user_id = it->second).empty()) {
			loge("no user_id");
			Close();
			return;
		} else {
			const char *ptr = user_id.c_str();
			char *endptr;
			uid = strtoul(ptr, &endptr, 0);
			if (*endptr != '\0') {
				loge("Invalid user_id : %s", ptr);
				Close();
				return;
			}
		}

		it = mParams.find("app_id");
		if (it == mParams.end() || (app_id = it->second).empty()) {
			loge("no app_id");
			Close();
			return;
		} else {
			const char *ptr = app_id.c_str();
			char *endptr;
			aid = strtoul(ptr, &endptr, 0);
			if (*endptr != '\0') {
				loge("Invalid app_id : %s", ptr);
				Close();
				return;
			}
		}

		it = mParams.find("domain_id");
		if (it == mParams.end() || (domain_id = it->second).empty()) {
			loge("no domain_id");
			Close();
			return;
		} else {
			const char *ptr = domain_id.c_str();
			char *endptr;
			did = strtoul(ptr, &endptr, 0);
			if (*endptr != '\0') {
				loge("Invalid domain_id : %s", ptr);
				Close();
				return;
			}
		}
		break;
	}
	default: // For future extension
		break;
	}

	Json::Value value;
	string content;
	char* szContent;
	string token;

	if (mMethodId == METHOD_REFRESH_TOKEN) { // refreshToken
		ParamMap_t::iterator it = mParams.find("old_token");
		string token_base64;
		if (it == mParams.end() || (token_base64 = it->second).empty()) {
			loge("No token");
			Close();
			return;
		}
		token = base64_decode(token_base64);
		if (token.length() != 32) {
			loge("Invalid token's length: %d", token.length());
			value["result_code"] = 5;
			value["user_token"] = "";
			value["expire_date"] = 0;
			content = value.toStyledString();
			szContent = new char[HTTP_RESPONSE_HTML_MAX];
			snprintf(szContent, HTTP_RESPONSE_HTML_MAX, HTTP_RESPONSE_HTML, content.length(), content.c_str());
			Send((void*)szContent, strlen(szContent));
			delete [] szContent;
			return;
		}
	}


	switch (mMethodId) {
	case METHOD_UNREGISTER:
		if (g_msg_serv_info.size() <= 0) {
            log("Unregister Error : msg_server unconnect ... ");
			value["result_code"] = 2;
		} else {
			unregister_user(uid, aid, did);
			value["result_code"] = 0;
		}
		content = value.toStyledString();
		szContent = new char[HTTP_RESPONSE_HTML_MAX];
		snprintf(szContent, HTTP_RESPONSE_HTML_MAX, HTTP_RESPONSE_HTML, content.length(), content.c_str());
		Send((void*)szContent, strlen(szContent));
		delete [] szContent;
		break;
	case METHOD_CONNECT:
	case METHOD_REFRESH_TOKEN:
		get_user_token(this, uid, aid, did);
		break;
	default: // For future extension
		break;
	}
}

void CHttpConn::onGetUserToken(const string& token)
{
	string token_base64 = base64_encode(token);
	time_t expire;

	time(&expire);
	expire -= timezone;
	expire -= (expire % 86400);
	expire += ((3 * 86400) + timezone);
	
	Json::Value value;
	string content;
	char* szContent;

	if (mMethodId == METHOD_CONNECT) {
		msg_serv_info_t* pMsgServInfo;
		uint32_t min_user_cnt = (uint32_t)-1;
		map<uint32_t, msg_serv_info_t*>::iterator it_min_conn = g_msg_serv_info.end();
		map<uint32_t, msg_serv_info_t*>::iterator it;

		if(g_msg_serv_info.size() <= 0) {
            log("CONNECT Error : msg_server unconnect ... ");
			value["result_code"] = 2;
			value["prior_ip"] = "";
			value["backup_ip"] = "";
			value["port"] = 0;
			value["msfs_url"] = "";
			value["user_token"] = "";
			value["expire_date"] = 0;
		} else {

			for (it = g_msg_serv_info.begin() ; it != g_msg_serv_info.end(); it++) {
				pMsgServInfo = it->second;
				if ( (pMsgServInfo->cur_conn_cnt < pMsgServInfo->max_conn_cnt) &&
					(pMsgServInfo->cur_conn_cnt < min_user_cnt)) {
					it_min_conn = it;
					min_user_cnt = pMsgServInfo->cur_conn_cnt;
				}
			}
			if (it_min_conn == g_msg_serv_info.end()) {
				loge("All TCP MsgServer are full ");
				value["result_code"] = 2;
				value["prior_ip"] = "";
				value["backup_ip"] = "";
				value["port"] = 0;
				value["msfs_url"] = "";
				value["user_token"] = "";
				value["expire_date"] = 0;
			} else {
				value["result_code"] = 0;
				if(pIpParser->isTelcome(GetPeerIP())) {
					value["prior_ip"] = string(it_min_conn->second->ip_addr1);
					value["backup_ip"] = string(it_min_conn->second->ip_addr2);
				} else {
					value["prior_ip"] = string(it_min_conn->second->ip_addr2);
					value["backup_ip"] = string(it_min_conn->second->ip_addr1);
				}
				value["port"] = it_min_conn->second->port;
				value["msfs_url"] = strMsfsUrl;
				value["user_token"] = token_base64;
				value["expire_date"] = (uint32_t)expire;
			}
		}
		content = value.toStyledString();
		szContent = new char[HTTP_RESPONSE_HTML_MAX];
		snprintf(szContent, HTTP_RESPONSE_HTML_MAX, HTTP_RESPONSE_HTML, content.length(), content.c_str());
		Send((void*)szContent, strlen(szContent));
		delete [] szContent;
	} else if (mMethodId == METHOD_REFRESH_TOKEN) {
		if(g_msg_serv_info.size() <= 0) {
            log("REFRESH_TOKEN Error : msg_server unconnect ... ");
			value["result_code"] = 2;
			value["user_token"] = "";
			value["expire_date"] = 0;
		} else {
			value["result_code"] = 0;
			value["user_token"] = token_base64;
			value["expire_date"] = (uint32_t)expire;
		}
		content = value.toStyledString();
		szContent = new char[HTTP_RESPONSE_HTML_MAX];
		snprintf(szContent, HTTP_RESPONSE_HTML_MAX, HTTP_RESPONSE_HTML, content.length(), content.c_str());
		Send((void*)szContent, strlen(szContent));
		delete [] szContent;
	}
}

void CHttpConn::OnWriteComplete()
{
    log("write complete ");
    Close();
}


unsigned char CHttpConn::_fromHex(unsigned char x)
{
	unsigned char y;
	if (x >= 'A' && x <= 'Z') y = x - 'A' + 10;
	else if (x >= 'a' && x <= 'z') y = x - 'a' + 10;
	else if (x >= '0' && x <= '9') y = x - '0';
	else assert(0);
	return y;
}


std::string CHttpConn::_urlDecode(const std::string& str)
{
	std::string strTemp = "";
	size_t length = str.length();
	for (size_t i = 0; i < length; i++)
	{
		if (str[i] == '+') strTemp += ' ';
		else if (str[i] == '%')
		{
			assert(i + 2 < length);
			unsigned char high = _fromHex((unsigned char)str[++i]);
			unsigned char low = _fromHex((unsigned char)str[++i]);
			strTemp += high*16 + low;
		}
		else strTemp += str[i];
	}
	return strTemp;
}


