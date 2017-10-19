/*
  +----------------------------------------------------------------------+
  | Zan                                                                  |
  +----------------------------------------------------------------------+
  | Copyright (c) 2016-2017 Zan Group <https://github.com/youzan/zan>    |
  +----------------------------------------------------------------------+
  | This source file is subject to version 2.0 of the Apache license,    |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.apache.org/licenses/LICENSE-2.0.html                      |
  | If you did not receive a copy of the Apache2.0 license and are unable|
  | to obtain it through the world-wide-web, please send a note to       |
  | zan@zanphp.io so we can mail you a copy immediately.                 |
  +----------------------------------------------------------------------+
  |         Zan Group   <zan@zanphp.io>                                  |
  +----------------------------------------------------------------------+
*/

#include "zanIpc.h"
#include "zanLog.h"

int zanMsgQueue_push(zanMsgQueue *pMq, zanQueue_Data *in, int length);
int zanMsgQueue_pop(zanMsgQueue *pMq, zanQueue_Data *out, int length);
int zanMsgQueue_stat(zanMsgQueue *pMq, int *queue_num, int *queue_bytes);
int zanMsgQueue_close(zanMsgQueue *pMq);

int zanMsgQueue_create(zanMsgQueue *pMq, int blocking, key_t msg_key, long type)
{
    if (!pMq){
        zanError("pMq is null, error.");
        return ZAN_ERR;
    }

    int msg_id = msgget(msg_key, IPC_CREAT | O_EXCL | 0666);
    if (-1 == msg_id)
    {
        zanSysError("msgget() failed, errno=%d:%s", errno, strerror(errno));
        return ZAN_ERR;
    }

    pMq->type     = type;
    pMq->msg_id   = msg_id;
    pMq->ipc_wait = (!blocking) ? IPC_NOWAIT : 0;

    pMq->pop      = zanMsgQueue_pop;
    pMq->push     = zanMsgQueue_push;
    pMq->stat     = zanMsgQueue_stat;
    pMq->close    = zanMsgQueue_close;

    return ZAN_OK;
}

int zanMsgQueue_pop(zanMsgQueue *pMq, zanQueue_Data *out, int length)
{
    int flag  = pMq->ipc_wait;
    long type = out->mtype;

    if (!pMq){
        zanError("pMq is null, error.");
        return ZAN_ERR;
    }

    return msgrcv(pMq->msg_id, out, length, type, flag);
}

int zanMsgQueue_push(zanMsgQueue *pMq, zanQueue_Data *in, int length)
{
    int ret = -1;
    while (1)
    {
        ret = msgsnd(pMq->msg_id, in, length, pMq->ipc_wait);
        if (0 != ret)
        {
            if (errno == EINTR)
            {
                continue;
            }
            else if (errno == EAGAIN)
            {
                swYield();
                continue;
            }
        }
        break;
    }
    return ret;
}

int zanMsgQueue_stat(zanMsgQueue *pMq, int *queue_num, int *queue_bytes)
{
    struct msqid_ds stat;
    if (msgctl(pMq->msg_id, IPC_STAT, &stat) == -1)
    {
        zanSysError("msgctl(IPC_STAT) failed, errno=%d:%s", errno, strerror(errno));
        return ZAN_ERR;
    } else {
        *queue_num   = stat.msg_qnum;
        *queue_bytes = stat.msg_qbytes;
        return ZAN_OK;
    }
}

int zanMsgQueue_close(zanMsgQueue *pMq)
{
    int ret = 0;
    if (!pMq){
        zanError("pMq is null, error.");
        return ZAN_ERR;
    }

	if(pMq->deleted == 1)
	{
		return ZAN_OK;
	}
	else
	{
		ret = msgctl(pMq->msg_id, IPC_RMID, 0);
		if (-1 == ret)
		{
			zanError("msgctl failed, errno=%d:%s", errno, strerror(errno));
			return ZAN_ERR;
		}
	}

    return ZAN_OK;
}
