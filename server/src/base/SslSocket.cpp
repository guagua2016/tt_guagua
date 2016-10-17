#include "SslSocket.h"
#include "FileUtil.h"
#include "EventDispatch.h"

int  ssl_connection_index;
#define SSL_BUFSIZE  16384
static void ssl_info_callback(const SSL *ssl_conn, int where,int ret);

CSslSocket::CSslSocket(const char *cert, const char *key, const char *dh)
{
	if (cert != NULL) m_cert = cert;
	if (key != NULL) m_key = key;
	if (dh != NULL) m_dh = dh;
	m_ssl_ctx = NULL;
	m_ssl = NULL;
	m_bio.p = NULL;
	::SSL_load_error_strings();
	::SSL_library_init();
	::ERR_clear_error();
	const SSL_METHOD *method = ::SSLv23_method();
	m_ssl_ctx = ::SSL_CTX_new(method);
	if (m_ssl_ctx == NULL) {
		loge("SSL_CTX_new failed:%s", ::ERR_reason_error_string(::ERR_get_error()));
	} else {
		m_ownCtx = true;
	}
}


int CSslSocket::SslAccept(SSL	*ssl, int nTimeout)
{
	int reset_blocking_mode = 0;
	int nSleepTimes = 10000;
	int nWantReadTimes = 0, nMaxWantReadTimes = nTimeout*1000000/nSleepTimes;
	if (NULL == ssl)
		return -1;

	if (SSL_is_init_finished(ssl))
		return 0;

	if (!SSL_in_accept_init(ssl))
		::SSL_set_accept_state(ssl);

	if (nTimeout != 0)
	{
#if 0
		struct timeval tm;
		tm.tv_sec = nTimeout; //seconds
		tm.tv_usec = 0;
		if (setsockopt(m_socket,SOL_SOCKET,SO_RCVTIMEO,(void*)&tm,sizeof(tm)) < 0)
			ERROR("Set SO_RCVTIMEO failed!");
		if (setsockopt(m_socket,SOL_SOCKET,SO_SNDTIMEO,(void*)&tm,sizeof(tm)) < 0)
			ERROR("Set SO_SNDTIMEO failed!");
#endif //0

		reset_blocking_mode = 1;
		DEBUG("###set nonblock,nMaxWantReadTimes=%d",nMaxWantReadTimes);
		setNonblock(true);
	}

	int status;
	  do
	    {
	      // These handle sets are used to set up for whatever SSL_accept
	      // says it wants next. They're reset on each pass around the loop.
	      status = ::SSL_accept (ssl);
	      switch (::SSL_get_error (ssl, status))
	        {
	        case SSL_ERROR_NONE:
	        	DEBUG("SSL_get_error=>SSL_ERROR_NONE");
	          status = 0;               // To tell caller about success
	          break;                    // Done

	        case SSL_ERROR_WANT_WRITE:
	        	DEBUG("SSL_get_error=>SSL_ERROR_WANT_WRITE");
	        	usleep(nSleepTimes);//sleep 10 microseconds
	        	status = 1;
	        	break;
	        case SSL_ERROR_WANT_READ:
	        	//DEBUG("SSL_get_error=>SSL_ERROR_WANT_READ");
	        	if (nWantReadTimes++ > nMaxWantReadTimes)
	        	{
	        		status = -1;
	        	} else {
	        		usleep(nSleepTimes);
	        		status = 1;        // Wait for more activity
	        	}
	          break;

	        case SSL_ERROR_ZERO_RETURN:
	          // The peer has notified us that it is shutting down via
	          // the SSL "close_notify" message so we need to
	          // shutdown, too.
	          status = -1;
	          break;

	        case SSL_ERROR_SYSCALL:
	        	   ERROR("SSL_ERROR_SYSCALL:%s",strerror(errno));

	        	 status = -1;
#if 0
	        	 if (errno == EWOULDBLOCK)
	        		 DEBUG("###SO_RCVTIMEO Timeout");
	          if (errno == EWOULDBLOCK &&
	              status == -1)
	            {
	              // Although the SSL_ERROR_WANT_READ/WRITE isn't getting
	              // set correctly, the read/write state should be valid.
	              // Use that to decide what to do.
	              status = 1;               // Wait for more activity
	              if (SSL_want_write (ssl))
	            	      DEBUG("SSL_want_write ");
	                //wr_handle.set_bit (handle);
	              else if (SSL_want_read (ssl))
	            	   DEBUG("SSL_want_read");
	                //rd_handle.set_bit (handle);
	              else
	                status = -1;            // Doesn't want anything - bail out
	            }
	          else
	            status = -1;
#endif //0
	          break;

	        default:
	        	loge("SSL_accept failed: %s", ::ERR_reason_error_string(::ERR_get_error()));
	          status = -1;
	          break;
	        }
	    } while (status == 1 && !SSL_is_init_finished (ssl));

	  if (reset_blocking_mode)
	  {
		  DEBUG("###disable set nonblock, nWantReadTimes = %d",nWantReadTimes);
		  setNonblock(false);
	  }
	  return (status == -1 ? -1 : 0);
}

CSslSocket::CSslSocket(SSL_CTX *ctx, SOCKET sock)
{
	m_socket = sock;
	m_ssl_ctx = ctx;
	m_ownCtx = false;
	m_bio.p = ::BIO_new_socket(sock, BIO_NOCLOSE);
	m_ssl = ::SSL_new(m_ssl_ctx);
	::SSL_set_bio(m_ssl, m_bio.p, m_bio.p);
	::ERR_clear_error();

#if 0 // nginx
	SSL_CTX_set_info_callback(m_ssl_ctx, ssl_info_callback);

   ssl_connection_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
   if (ssl_connection_index == -1) {
        loge("SSL_get_ex_new_index() failed");
    }
#endif //0

//#if 0
	if (this->SslAccept(m_ssl,5) == 0)
		m_isHandshaked = true;
	else
		m_isHandshaked = false;
//#endif //0

#if 0
	if (::SSL_accept(m_ssl) != 1) {
		loge("SSL_accept failed: %s", ::ERR_reason_error_string(::ERR_get_error()));
                
		m_isHandshaked = false;
	} else {
		m_isHandshaked = true;
	}
#endif //0

}

CSslSocket::~CSslSocket()
{
	if (m_ssl) {
		::SSL_shutdown(m_ssl);
		if (m_bio.p != NULL) {
			m_bio.p = NULL; // SSL_free will call BIO_free
		}
		::SSL_free(m_ssl);
		m_ssl = NULL;
	}
	if (m_ssl_ctx && m_ownCtx == true) {
		::SSL_CTX_free(m_ssl_ctx);
	}
}

int CSslSocket::Listen(const char* server_ip, uint16_t port, callback_t callback, void* callback_data)
{
	if (m_ssl_ctx == NULL || 
		m_cert.empty() || m_cert.length() == 0 || !CFileUtil::exist(m_cert.c_str()) ||
		m_key.empty() || m_key.length() == 0 || !CFileUtil::exist(m_key.c_str())) {
		return NETLIB_ERROR;
	}
	int rc = CBaseSocket::Listen(server_ip, port, callback, callback_data);
	if (rc == NETLIB_OK) {
		bool use_dh = false;

		::ERR_clear_error();
		::SSL_CTX_set_options(m_ssl_ctx, 
			SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_COMPRESSION);
		if (!m_dh.empty() && m_dh.length() > 0 && CFileUtil::exist(m_dh.c_str())) {
			::SSL_CTX_set_options(m_ssl_ctx, SSL_OP_SINGLE_DH_USE);
			use_dh = true;
		}
		if (::SSL_CTX_use_certificate_file(m_ssl_ctx, m_cert.c_str(), SSL_FILETYPE_PEM) != 1) {
			loge("SSL_CTX_use_certificate_file failed: %s", 
				::ERR_reason_error_string(::ERR_get_error()));
			return NETLIB_ERROR;
		}

		if (::SSL_CTX_use_PrivateKey_file(m_ssl_ctx, m_key.c_str(), SSL_FILETYPE_PEM) != 1) {
			loge("SSL_CTX_use_PrivateKey_file failed: %s",
				::ERR_reason_error_string(::ERR_get_error()));
			return NETLIB_ERROR;
		}
		if (use_dh) {
			::SSL_CTX_set_options(m_ssl_ctx, SSL_OP_SINGLE_DH_USE);
			ScopedBio bio = { ::BIO_new_file(m_dh.c_str(), "r") };
			if (bio.p == NULL) {
				loge("BIO_new_file failed: %s",
					::ERR_reason_error_string(::ERR_get_error()));
				return NETLIB_ERROR;
			}
			ScopedDh dh = { ::PEM_read_bio_DHparams(bio.p, 0, 0, 0) };
			if (dh.p == NULL) {
				loge("PEM_read_bio_DHparams failed: %s", 
					::ERR_reason_error_string(::ERR_get_error()));
				return NETLIB_ERROR;
			}
			::SSL_CTX_set_tmp_dh(m_ssl_ctx, dh.p);
		}
		return NETLIB_OK;
	}
	return NETLIB_ERROR;
}

net_handle_t CSslSocket::Connect(const char* server_ip, uint16_t port, callback_t callback, void* callback_data)
{
	if (m_cert.empty() || m_cert.length() == 0 || !CFileUtil::exist(m_cert.c_str())) {
		loge("CSslSocket::Connect, invalid certificate file");
		return NETLIB_INVALID_HANDLE;
	}
	::SSL_CTX_set_verify(m_ssl_ctx, SSL_VERIFY_PEER, SSL_CTX_get_verify_callback(m_ssl_ctx));
	if (::SSL_CTX_load_verify_locations(m_ssl_ctx, m_cert.c_str(), 0) != 1) {
		loge("SSL_CTX_load_verify_locations failed: %s", ERR_reason_error_string(ERR_get_error()));
		return NETLIB_INVALID_HANDLE;
	}
	m_remote_ip = server_ip;
	m_remote_port = port;
	m_callback = callback;
	m_callback_data = callback_data;
	m_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (m_socket == INVALID_SOCKET) {
		loge("CSslSocket::Connect socket failed: %s", ::strerror(errno));
		return NETLIB_INVALID_HANDLE;
	}
	sockaddr_in serv_addr;
	_SetAddr(server_ip, port, &serv_addr);
	int ret = connect(m_socket, (sockaddr*)&serv_addr, sizeof(sockaddr_in));
	if ( (ret == SOCKET_ERROR) && (!_IsBlock(_GetErrorCode())) ) {
		log("CSslSocket::Connect connect failed: %s", ::strerror(errno));
		::close(m_socket);
		return NETLIB_INVALID_HANDLE;
	}
	m_bio.p = ::BIO_new_socket(m_socket, BIO_NOCLOSE);
	m_ssl = ::SSL_new(m_ssl_ctx);
	if (m_ssl == NULL) {
		loge("SSL_new failed: %s", ::ERR_reason_error_string(::ERR_get_error()));
		::close(m_socket);
		return NETLIB_INVALID_HANDLE;
	}
	::SSL_set_bio(m_ssl, m_bio.p, m_bio.p);
	if (::SSL_connect(m_ssl) != 1) {
		loge("SSL_connect failed: %s", ::ERR_reason_error_string(::ERR_get_error()));
		::close(m_socket);
		return NETLIB_INVALID_HANDLE;
	}
	setNonblock(true);
	setTcpNoDelay(true);
	m_state = SOCKET_STATE_CONNECTING;
	AddBaseSocket(this);
	CEventDispatch::Instance()->AddEvent(m_socket, SOCKET_ALL);
	return (net_handle_t)m_socket;
}

int CSslSocket::Send(void* buf, int len)
{
	if (m_state != SOCKET_STATE_CONNECTED)
		return NETLIB_ERROR;

	if (m_ssl == NULL)
		return NETLIB_ERROR;

	int rc = ::SSL_write(m_ssl, buf, len);
	int err = ::SSL_get_error(m_ssl, rc);
	switch (err) {
	case SSL_ERROR_NONE:
		break;
	case SSL_ERROR_ZERO_RETURN:
		log("SSL_write return 0, socket %d maybe shutdown", m_socket);
		break;
	case SSL_ERROR_WANT_READ:
		log("SSL_write return SSL_ERROR_WANT_READ, try again. socket %d", m_socket);
		rc = 0;
		break;
	case SSL_ERROR_WANT_WRITE:
		log("SSL_write return SSL_ERROR_WANT_WRITE, try again");
		rc = 0;
		break;
	default:
		log("SSL_write failed: %d  %s", err, strerror(errno));
		break;
	}
	return rc;
}

int CSslSocket::Recv(void* buf, int len)
{
	if (m_ssl == NULL)
		return NETLIB_ERROR;

	int rc = ::SSL_read(m_ssl, buf, len);
	int err = ::SSL_get_error(m_ssl, rc);
	switch (err) {
	case SSL_ERROR_NONE:
		break;
	case SSL_ERROR_ZERO_RETURN:
		log("SSL_read return 0, socket %d maybe shutdown", m_socket);
		rc = 0;
		break;
	case SSL_ERROR_WANT_READ:
		//log("SSL_read return SSL_ERROR_WANT_READ, try again");
		rc = 0;
		break;
	case SSL_ERROR_WANT_WRITE:
		log("SSL_read return SSL_ERROR_WANT_WRITE, try again. socket %d", m_socket);
		rc = 0;
		break;
	default:
		//unsigned long ret = ::ERR_get_error();
		//loge("SSL_read failed: %d  %d  %d", err, ret, errno);
		break;
	}
	return rc;
}

int CSslSocket::Close()
{
	CBaseSocket::Close();
	if (m_ssl) ::SSL_shutdown(m_ssl);
	return 0;
}


int CSslSocket::create_ssl_connect()
{
	if (NULL == m_ssl) {
		ERROR("SSL_new() failed");
		return -1;
	}

	if (SSL_set_fd(m_ssl,m_socket) == 0) {
		ERROR("SSL_set_fd() failed");
		return -1;
	}

	 SSL_set_accept_state(m_ssl);

   if (SSL_set_ex_data(m_ssl, ssl_connection_index, this) == 0) {
        ERROR("SSL_set_ex_data() failed");
	     return -1;
    }

    SetHandshaked(false);
    SetHandshakeBuff(false);
	 return 0;
}

static void ssl_info_callback(const SSL *pSslConn, int where, int ret)
{
    BIO               *rbio, *wbio;
    CSslSocket  *c =
    		(CSslSocket*)SSL_get_ex_data(pSslConn, ssl_connection_index);

    if (where & SSL_CB_HANDSHAKE_START) {

        if (c->IsHandshaked()) {
        	 ::SSL_renegotiate(c->GetSSL());
        	  // pSslConn->renegotiate = 1;
            log("SSL renegotiation");
        }
    }

    if ((where & SSL_CB_ACCEPT_LOOP) == SSL_CB_ACCEPT_LOOP) {
        if (!c->IsSetHandshakeBuff()) {
            /*
             * By default OpenSSL uses 4k buffer during a handshake,
             * which is too low for long certificate chains and might
             * result in extra round-trips.
             *
             * To adjust a buffer size we detect that buffering was added
             * to write side of the connection by comparing rbio and wbio.
             * If they are different, we assume that it's due to buffering
             * added to wbio, and set buffer size.
             */

            rbio = SSL_get_rbio(pSslConn);
            wbio = SSL_get_wbio(pSslConn);

            if (rbio != wbio) {
                (void) BIO_set_write_buffer_size(wbio,SSL_BUFSIZE);
                    c->SetHandshakeBuff(true);
            }
        }
    }
}


int CSslSocket::ssl_handshake()
{
	 int        n, sslerr;
	 int        err;
    while (ERR_peek_error()) {
        ERROR("ignoring stale global SSL error");
    }
    ERR_clear_error();
   //::SSL_renegotiate(m_ssl);
   n = SSL_do_handshake(this->m_ssl);
   DEBUG("SSL_do_handshake: %d", n);
   if (n == 1) {
	   //handshake successful
	   this->SetHandshaked(true);

	   return 0; //successfull
    }

   sslerr = SSL_get_error(m_ssl, n);
   ERROR("SSL_get_error: %d", sslerr);
   if (sslerr == SSL_ERROR_WANT_READ) {
	   DEBUG("SSL_read return SSL_ERROR_WANT_READ, try again");
	    return 1;
    }

   if (sslerr == SSL_ERROR_WANT_WRITE) {
	   DEBUG("SSL_write return SSL_ERROR_WANT_WRITE, try again");
       return 1;
   }
   err = (sslerr == SSL_ERROR_SYSCALL) ? errno : 0;
   if (sslerr == SSL_ERROR_ZERO_RETURN || ERR_peek_error() == 0) {
        ERROR("peer closed connection in SSL handshake");

        return -1;
    }

   ERROR("SSL_do_handshake() failed");
   return -1;// failed
}


void CSslSocket::OnRead()
{
	if (m_state == SOCKET_STATE_LISTENING) {
		SOCKET fd = -1;
		sockaddr_in peer_addr;
		socklen_t addr_len = sizeof(sockaddr_in);
		char ip_str[64];
		while ((fd = accept(m_socket, (sockaddr*)&peer_addr, &addr_len)) != INVALID_SOCKET) {
			uint32_t ip = ntohl(peer_addr.sin_addr.s_addr);
			uint16_t port = ntohs(peer_addr.sin_port);
			snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d", ip >> 24, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
			log("CsslSocket accepted socket=%d from %s:%d", fd, ip_str, port);
			CSslSocket *pSocket = new CSslSocket(m_ssl_ctx, fd);

#if 0 // nginx
			if (pSocket->create_ssl_connect() != 0) {
				//pSocket->Close();
			    delete pSocket;
			    pSocket = NULL;
			    //return;
				continue;
			}

			if (pSocket->ssl_handshake() != 0)
			{
				//pSocket->Close();
				delete pSocket;
				pSocket = NULL;
				//return;
				continue;
			}

			pSocket->SetCallback(m_callback);
			pSocket->SetCallbackData(m_callback_data);
			pSocket->SetState(SOCKET_STATE_CONNECTED);
			pSocket->SetRemoteIP(ip_str);
			pSocket->SetRemotePort(port);
			pSocket->setTcpNoDelay(true);
			pSocket->setNonblock(true);
			AddBaseSocket(pSocket);
			CEventDispatch::Instance()->AddEvent(fd, SOCKET_READ | SOCKET_EXCEP);
			m_callback(m_callback_data, NETLIB_MSG_CONNECT, (net_handle_t)fd, NULL);
#endif //0
//#if 0
			if (pSocket->isHandshaked()) {
				log("CsslSocket handshake passed. socket=%d from %s:%d", fd, ip_str, port);
				pSocket->SetCallback(m_callback);
				pSocket->SetCallbackData(m_callback_data);
				pSocket->SetState(SOCKET_STATE_CONNECTED);
				pSocket->SetRemoteIP(ip_str);
				pSocket->SetRemotePort(port);
				pSocket->setTcpNoDelay(true);
				pSocket->setNonblock(true);
				AddBaseSocket(pSocket);
				CEventDispatch::Instance()->AddEvent(fd, SOCKET_READ | SOCKET_EXCEP);
				m_callback(m_callback_data, NETLIB_MSG_CONNECT, (net_handle_t)fd, NULL);
			} else {
				log("CsslSocket handshake not passed. socket=%d from %s:%d", fd, ip_str, port);
				closesocket(fd);
				delete pSocket;
			}
//#endif //0
		} // end while
	} else {
		u_long avail = 0;
		m_callback(m_callback_data, NETLIB_MSG_READ, (net_handle_t)m_socket, NULL);
#if 0		
		if ( (ioctlsocket(m_socket, FIONREAD, &avail) == SOCKET_ERROR) || (avail == 0) )
		{
		    log("sslsocket ioctlsocket failed, err_code=%d, %s", _GetErrorCode(), strerror(errno));
			m_callback(m_callback_data, NETLIB_MSG_CLOSE, (net_handle_t)m_socket, NULL);
		}
		else
		{
			m_callback(m_callback_data, NETLIB_MSG_READ, (net_handle_t)m_socket, NULL);
		}
#endif		
	}
}

void CSslSocket::OnWrite()
{
	CBaseSocket::OnWrite();
}

void CSslSocket::OnClose()
{
	CBaseSocket::OnClose();
}
