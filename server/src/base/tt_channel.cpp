/*
 * Channel.cpp
 *
 *  Created on: 2016年5月25日
 *      Author: root
 */

#include <stdlib.h>
#include <stdio.h>
#include <tt_channel.h>


void tt_close_channel(int *fd)
{
    if (close(fd[0]) == -1) {
        ERROR("close() channel failed");
    }

    if (close(fd[1]) == -1) {
        ERROR("close() channel failed");
    }
}



int  tt_write_channel(int nSocketFd, tt_channel_t *ch, size_t size)
{
    ssize_t       n;
    int           nErrNo;
    struct iovec        iov[1];
    struct msghdr       msg;
    memset(&msg,0,sizeof(msg));

    iov[0].iov_base = (void *) ch;
    iov[0].iov_len = size;

    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    n = sendmsg(nSocketFd, &msg, 0);

    if (n == -1) {
        nErrNo = errno;
        if (nErrNo == EAGAIN) {
            return TT_AGAIN;
        }//End if

        ERROR("sendmsg() to channelid=%d,failed,errno=%d",nSocketFd,nErrNo);
        return TT_ERROR;
    }//End if

    DEBUG("sendmsg() to solt=%d,channelid=%d",ch->slot,nSocketFd);
    return TT_OK;
}


int tt_read_channel(int nSockFd, tt_channel_t *ch, size_t size)
{
    ssize_t             n;
    int           nErrNo;
    struct iovec        iov[1];
    struct msghdr       msg;

    iov[0].iov_base = (char *) ch;
    iov[0].iov_len = size;

    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    n = recvmsg(nSockFd, &msg, 0);

     if (n == -1) {
    	 nErrNo = errno;
         if (nErrNo == EAGAIN) {
             return TT_AGAIN;
         }

         FATAL("recvmsg() failed");
         return TT_ERROR;
     }

     if (n == 0) {
         DEBUG("recvmsg() returned zero");
         return TT_ERROR;
     }

     if ((size_t) n < sizeof(tt_channel_t)) {
         FATAL("recvmsg() returned not enough data: %z", n);
         return TT_ERROR;
     }//Endif

     //DEBUG("process_slot:%d, channelid: %d, received %d Bytes", tt_process_slot,nSockFd,n);
#if 0
     if (ch->command == NGX_CMD_OPEN_CHANNEL) {
         if (msg.msg_accrightslen != sizeof(int)) {
             ngx_log_error(NGX_LOG_ALERT, log, 0,
                           "recvmsg() returned no ancillary data");
             return NGX_ERROR;
         }

         ch->fd = fd;
     }
#endif //0

     return n;
}

tt_event_handler_pt  handler;
SOCKET fd;
uint8_t socket_event;
rb_timer_item*  pTimer;

bool CChannelFdSocket::Initialise(SOCKET fd, uint8_t socket_event,rb_timer_item*  pTimer,tt_event_handler_pt  handler)
{
	static bool bInitialised = false;
	if (bInitialised)
		return false;

	m_objEV.fd = fd;
	m_objEV.handler = handler;
	m_objEV.pTimer = pTimer;
	m_objEV.socket_event = socket_event;

	SetSocket(fd);
	AddBaseSocket(this);
	bInitialised = true;
	return true;
}


int tt_add_channel_event(int nSockFd,uint8_t socket_event)
{
	CEventDispatch::Instance()->TTAddEvent(nSockFd,socket_event);
}

void CChannelFdSocket::OnRead()
{
	m_objEV.handler(&m_objEV);
	return;
}
