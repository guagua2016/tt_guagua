/*
 * tt_core.h
 *
 *  Created on: 2016年5月25日
 *      Author: root
 */

#ifndef BASE_TT_CORE_H_
#define BASE_TT_CORE_H_


#include "util.h"


#define  TT_OK          0
#define  TT_ERROR      -1
#define  TT_AGAIN      -2
#define  TT_BUSY       -3
#define  TT_DONE       -4
#define  TT_DECLINED   -5
#define  TT_ABORT      -6


#ifndef UNUSED
#define UNUSED(v) ((void)(v))
#endif

typedef struct tt_event_s    tt_event_t;
typedef void (*tt_event_handler_pt)(tt_event_t *ev);


#endif /* BASE_TT_CORE_H_ */
