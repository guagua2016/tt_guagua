#ifndef CHANNEL_H_
#define CHANNEL_H_

#include "util.h"
#include "tt_core.h"
#include "EventDispatch.h"
#include "BaseSocket.h"

typedef struct {
     int   pid;
     int   slot;
     int    fd;
     unsigned long int  command;
} tt_channel_t;

class  CChannelFdSocket : public CBaseSocket
{
public :
	virtual void OnRead();

	bool Initialise(SOCKET fd, uint8_t socket_event,rb_timer_item*  pTimer,tt_event_handler_pt  handler);

private:
	tt_event_t     m_objEV;
};


int  tt_write_channel(int nSocketFd, tt_channel_t *ch, size_t size);

void tt_close_channel(int *fd);

int tt_read_channel(int nSockFd, tt_channel_t *ch, size_t size);

//int tt_add_channel_event(int nSockFd, int event, callback_t handler);
//int tt_add_channel_event(int nSockFd, int event, tt_event_handler_pt handler);
int tt_add_channel_event(int nSockFd,uint8_t socket_event);



#endif //CHANNEL_H_
