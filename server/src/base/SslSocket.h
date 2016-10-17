#ifndef __SSL_SOCKET_H__
#define __SSL_SOCKET_H__

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "ostype.h"
#include "util.h"
#include "BaseSocket.h"

class CSslSocket : public CBaseSocket
{
public:
	CSslSocket(const char *cert_file, const char *key_file, const char *dh_file);
	CSslSocket(SSL_CTX *ctx, SOCKET sock);
	virtual ~CSslSocket();

	bool isHandshaked() const { return m_isHandshaked; }
        virtual int Listen(
		const char*		server_ip, 
		uint16_t		port,
		callback_t		callback,
		void*			callback_data);

	virtual net_handle_t Connect(
		const char*		server_ip, 
		uint16_t		port,
		callback_t		callback,
		void*			callback_data);

	virtual int Send(void* buf, int len);

	virtual int Recv(void* buf, int len);

	virtual int Close();

	virtual void OnRead();
	virtual void OnWrite();
	virtual void OnClose();
	bool IsHandshaked() {return m_isHandshaked;};
	void SetHandshaked(bool bHandshaked) { m_isHandshaked = bHandshaked; };
	void SetHandshakeBuff(bool bHandshakeBuffSet) { m_bHandshakeBuffSet = bHandshakeBuffSet; };
	bool IsSetHandshakeBuff() {return m_bHandshakeBuffSet;};
	SSL* GetSSL(){ return m_ssl;};

private:
	struct ScopedBio
	{
		BIO* p;
		~ScopedBio() { if (p) ::BIO_free(p); }
	};

	struct ScopedDh
	{
		DH* p;
		~ScopedDh() { if (p) ::DH_free(p); }
	};

	int SslAccept(SSL	*m_ssl, int nTimeout);

	int create_ssl_connect();

	int ssl_handshake();

	SSL_CTX* _initSslContext();
protected:
	string			m_cert;
	string			m_key;
	string			m_dh;
	SSL_CTX			*m_ssl_ctx;
	SSL			   *m_ssl;
	ScopedBio		m_bio;
	bool			m_ownCtx;
	bool			m_isHandshaked;
	bool 			m_bHandshakeBuffSet;

};

#endif
