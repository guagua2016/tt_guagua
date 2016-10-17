/*================================================================
 *   Copyright (C) 2014 All rights reserved.
 *
 *   文件名称：Login.cpp
 *   创 建 者：Zhang Yuanhao
 *   邮    箱：bluefoxah@gmail.com
 *   创建日期：2014年12月15日
 *   描    述：
 *
 ================================================================*/

#include <list>
#include "../ProxyConn.h"
#include "../HttpClient.h"
#include "../SyncCenter.h"
#include "../CachePool.h"
#include "Login.h"
#include "UserModel.h"
#include "TokenValidator.h"
#include "json/json.h"
#include "Common.h"
#include "IM.Server.pb.h"
#include "IM.Login.pb.h"
#include "Base64.h"
#include "InterLogin.h"
#include "ExterLogin.h"

CInterLoginStrategy g_loginStrategy;

hash_map<string, list<uint32_t> > g_hmLimits;
CLock g_cLimitLock;
namespace DB_PROXY {

#define AUTH_ENCRYPT_KEY "Mgj!@#123"

// Constants are the integer part of the sines of integers (in radians) * 2^32.
const uint32_t k[64] = {
0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee ,
0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501 ,
0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be ,
0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821 ,
0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa ,
0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8 ,
0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed ,
0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a ,
0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c ,
0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70 ,
0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05 ,
0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665 ,
0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039 ,
0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1 ,
0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1 ,
0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391 };

// r specifies the per-round shift amounts
const uint32_t r[] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                      5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
                      4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                      6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

// leftrotate function definition
#define LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))

void to_bytes(uint32_t val, uint8_t *bytes)
{
    bytes[0] = (uint8_t) val;
    bytes[1] = (uint8_t) (val >> 8);
    bytes[2] = (uint8_t) (val >> 16);
    bytes[3] = (uint8_t) (val >> 24);
}

uint32_t to_int32(const uint8_t *bytes)
{
    return (uint32_t) bytes[0]
        | ((uint32_t) bytes[1] << 8)
        | ((uint32_t) bytes[2] << 16)
        | ((uint32_t) bytes[3] << 24);
}

void md5(const uint8_t *initial_msg, size_t initial_len, uint8_t *digest) {

    // These vars will contain the hash
    uint32_t h0, h1, h2, h3;

    // Message (to prepare)
    uint8_t *msg = NULL;

    size_t new_len, offset;
    uint32_t w[16];
    uint32_t a, b, c, d, i, f, g, temp;

    // Initialize variables - simple count in nibbles:
    h0 = 0x67452301;
    h1 = 0xefcdab89;
    h2 = 0x98badcfe;
    h3 = 0x10325476;

    //Pre-processing:
    //append "1" bit to message
    //append "0" bits until message length in bits ≡ 448 (mod 512)
    //append length mod (2^64) to message

    for (new_len = initial_len + 1; new_len % (512/8) != 448/8; new_len++)
        ;

    msg = (uint8_t*)malloc(new_len + 8);
    memcpy(msg, initial_msg, initial_len);
    msg[initial_len] = 0x80; // append the "1" bit; most significant bit is "first"
    for (offset = initial_len + 1; offset < new_len; offset++)
        msg[offset] = 0; // append "0" bits

    // append the len in bits at the end of the buffer.
    to_bytes(initial_len*8, msg + new_len);
    // initial_len>>29 == initial_len*8>>32, but avoids overflow.
    to_bytes(initial_len>>29, msg + new_len + 4);

    // Process the message in successive 512-bit chunks:
    //for each 512-bit chunk of message:
    for(offset=0; offset<new_len; offset += (512/8)) {

        // break chunk into sixteen 32-bit words w[j], 0 ≤ j ≤ 15
        for (i = 0; i < 16; i++)
            w[i] = to_int32(msg + offset + i*4);

        // Initialize hash value for this chunk:
        a = h0;
        b = h1;
        c = h2;
        d = h3;

        // Main loop:
        for(i = 0; i<64; i++) {

            if (i < 16) {
                f = (b & c) | ((~b) & d);
                g = i;
            } else if (i < 32) {
                f = (d & b) | ((~d) & c);
                g = (5*i + 1) % 16;
            } else if (i < 48) {
                f = b ^ c ^ d;
                g = (3*i + 5) % 16;
            } else {
                f = c ^ (b | (~d));
                g = (7*i) % 16;
            }

            temp = d;
            d = c;
            c = b;
            b = b + LEFTROTATE((a + f + k[i] + w[g]), r[i]);
            a = temp;

        }

        // Add this chunk's hash to result so far:
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;

    }

    // cleanup
    free(msg);

    //var char digest[16] := h0 append h1 append h2 append h3 //(Output is in little-endian)
    to_bytes(h0, digest);
    to_bytes(h1, digest + 4);
    to_bytes(h2, digest + 8);
    to_bytes(h3, digest + 12);
}

/**
 * return 0 if generate token successful
 */
int genToken(uint32_t uid, uint32_t app_id, uint32_t domain_id, time_t tick, char* md5_str_buf)
{
	//MD5_CTX ctx;
	char tmp_buf[512];
	char t_buf[128];
	unsigned char md5_buf[32];
	struct tm* tm;

	tm = localtime(&tick);
	snprintf(t_buf,sizeof(t_buf), "%04d-%02d-%02d-%02d", tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,  tm->tm_hour);
	snprintf(tmp_buf,sizeof(tmp_buf), "%s_%u_%u_%u_%s_%s", AUTH_ENCRYPT_KEY, uid, app_id, domain_id, t_buf, AUTH_ENCRYPT_KEY);

	md5((unsigned char*)tmp_buf, strlen(tmp_buf), md5_buf);

	for (int i = 0; i < 16; i++) {
		sprintf(md5_str_buf + 2 * i, "%02x", md5_buf[i]);
	}

	// reverse md5_str_buf
	char c = 0;
	for (int i = 0; i < 16; i++) {
		c = md5_str_buf[i];
		md5_str_buf[i] = md5_str_buf[31 - i];
		md5_str_buf[31 - i] = c;
	}

	// switch md5_str_buf[i] and md5_str_buf[i + 1]
	for (int i = 0; i < 32; i += 2) {
		c = md5_str_buf[i];
		md5_str_buf[i] = md5_str_buf[i + 1];
		md5_str_buf[i + 1] = c;
	}

	return 0;
}

bool isUserTokenValid(uint32_t user_id, uint32_t app_id, uint32_t domain_id, const char* token)
{
	char token1[32], token2[32], token3[32];
	time_t today;
	time(&today);
	today -= timezone;
	today -= (today % 86400);
	today += timezone;

	genToken(user_id, app_id, domain_id, today - (86400 * 2), token1);	// token two days ago
	genToken(user_id, app_id, domain_id, today - 86400, token2);            // token one day ago
	genToken(user_id, app_id, domain_id, today, token3);	                // current token

	if (!strcmp(token, token1) || !strcmp(token, token2) || !strcmp(token, token3)) {
		return true;
	}
	return false;
}    
    
void doGetUserToken(CImPdu* pPdu, uint32_t conn_uuid)
{
	CImPdu* pPduResp = new CImPdu;

	IM::Login::IMGetUserTokenReq msg;
	IM::Login::IMGetUserTokenRsp msgResp;

	if (msg.ParseFromArray(pPdu->GetBodyData(), pPdu->GetBodyLength())) {
		uint32_t user_id = msg.user_id();
		uint32_t app_id = msg.app_id();
		uint32_t domain_id = msg.domain_id();

		msgResp.set_user_id(user_id);
		msgResp.set_app_id(app_id);
		msgResp.set_domain_id(domain_id);

		CacheManager *pCacheManager = CacheManager::getInstance();
		CacheConn *pCacheConn = pCacheManager->GetCacheConn("user_token");
		if (pCacheConn) {
			string key = "user_" + int2string(user_id) +
				"_" + int2string(app_id) + "_" + int2string(domain_id);
			char token[32];
			time_t today;
			time_t now;
			time(&today);
			now = today;
			today -= timezone;
			today -= (today % 86400);
			today += timezone;

			genToken(user_id, app_id, domain_id, today, token);
			msgResp.set_user_token(token);
			msgResp.set_result_code(0);
			msgResp.set_result_string("成功");
			time_t expire = (today + 3 * 86400) - now;
			pCacheConn->setex(key, expire, token); 
			pCacheManager->RelCacheConn(pCacheConn);
		} else {
			msgResp.set_result_code(1);
			msgResp.set_result_string("没有缓存服务器");
		}
	} else {
		msgResp.set_result_code(2);
		msgResp.set_result_string("服务器内部错误");
	}
	msgResp.set_attach_data(msg.attach_data());
	pPduResp->SetPBMsg(&msgResp);
	pPduResp->SetSeqNum(pPdu->GetSeqNum());
	pPduResp->SetServiceId(IM::BaseDefine::SID_LOGIN);
	pPduResp->SetCommandId(IM::BaseDefine::CID_LOGIN_RES_USERTOKEN);
	CProxyConn::AddResponsePdu(conn_uuid, pPduResp);
}

void doLogin(CImPdu* pPdu, uint32_t conn_uuid)
{
    
    CImPdu* pPduResp = new CImPdu;
    
    IM::Server::IMValidateReq msg;
    IM::Server::IMValidateRsp msgResp;
    if(msg.ParseFromArray(pPdu->GetBodyData(), pPdu->GetBodyLength()))
    {
        uint32_t user_id = msg.user_id();
        uint32_t app_id = msg.app_id();
        uint32_t domain_id = msg.domain_id();
        string token_base64 = msg.user_token();
	string token = base64_decode(token_base64);

        msgResp.set_user_id(user_id);
        msgResp.set_app_id(app_id);
        msgResp.set_domain_id(domain_id);
        msgResp.set_attach_data(msg.attach_data());      

        IM::BaseDefine::UserInfo* pUser = msgResp.mutable_user_info();
        pUser->set_user_id(user_id);
        pUser->set_app_id(app_id);
        pUser->set_domain_id(domain_id);
        CacheManager *pCacheManager = CacheManager::getInstance();
        CacheConn *pCacheConn = pCacheManager->GetCacheConn("user_token");
        if (pCacheConn) {
            string key = "user_" + int2string(user_id) + 
                "_" + int2string(app_id) + "_" + int2string(domain_id);
            string value = pCacheConn->get(key);
            if (!value.empty()) {
                if (token == value /*&& isUserTokenValid(user_id, app_id, domain_id, value.data())*/) {
                    msgResp.set_result_code(0);
                    msgResp.set_result_string("成功");
                } else {
                    msgResp.set_result_code(7);
                    msgResp.set_result_string("无效的令牌");
                }
            } else {
                msgResp.set_result_code(8);
                msgResp.set_result_string("未发现令牌");
            }
            pCacheManager->RelCacheConn(pCacheConn);
        } else {
            msgResp.set_result_code(9);
            msgResp.set_result_string("没有缓存服务器");
        }

    } else {
        msgResp.set_result_code(2);
        msgResp.set_result_string("服务端内部错误");
    }
    msgResp.set_attach_data(msg.attach_data());
    pPduResp->SetPBMsg(&msgResp);
    pPduResp->SetSeqNum(pPdu->GetSeqNum());
    pPduResp->SetServiceId(IM::BaseDefine::SID_OTHER);
    pPduResp->SetCommandId(IM::BaseDefine::CID_OTHER_VALIDATE_RSP);
    CProxyConn::AddResponsePdu(conn_uuid, pPduResp);
}

};

