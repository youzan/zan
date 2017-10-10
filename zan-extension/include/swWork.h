/*
  +----------------------------------------------------------------------+
  | Zan                                                                  |
  +----------------------------------------------------------------------+
  | Copyright (c) 2016-2017 Zan Group <https://github.com/youzan/zan>    |
  | Copyright (c) 2012-2016 Swoole Team <http://github.com/swoole>       |
  +----------------------------------------------------------------------+
  | This source file is subject to version 2.0 of the Apache license,    |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.apache.org/licenses/LICENSE-2.0.html                      |
  | If you did not receive a copy of the Apache2.0 license and are unable|
  | to obtain it through the world-wide-web, please send a note to       |
  | zan@zanphp.io so we can mail you a copy immediately.                 |
  +----------------------------------------------------------------------+
  | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
  |         Zan Group   <zan@zanphp.io>                                  |
  +----------------------------------------------------------------------+
*/
#ifndef _SW_WORK_H_
#define _SW_WORK_H_

#include "swoole.h"
#include "swError.h"
//#include "swServer.h"
#include "swSendfile.h"
#include "zanLog.h"

#ifdef __cplusplus
extern "C" {
#endif

enum swWorker_status
{
    SW_WORKER_BUSY = 1,
    SW_WORKER_IDLE = 2,
    SW_WORKER_DEL  = 3,
};

enum swResponseType
{
    SW_RESPONSE_SMALL = 0,
    SW_RESPONSE_BIG   = 1,
};

enum swTaskType
{
    SW_TASK_TMPFILE    = 1,  //tmp file
    SW_TASK_SERIALIZE  = 2,  //php serialize
    SW_TASK_NONBLOCK   = 4,  //task
};

enum swProcessType
{
    SW_PROCESS_OTHERS     = 0,
    SW_PROCESS_MASTER     = 1,
    SW_PROCESS_WORKER     = 2,
    SW_PROCESS_MANAGER    = 3,
    SW_PROCESS_TASKWORKER = 4,
    SW_PROCESS_USERWORKER = 5,
};

#if 0
#define swIsOthers()          (SwooleG.process_type==SW_PROCESS_OTHERS)
#define swIsMaster()          (SwooleG.process_type==SW_PROCESS_MASTER)
#define swIsWorker()          (SwooleG.process_type==SW_PROCESS_WORKER)
#define swIsTaskWorker()      (SwooleG.process_type==SW_PROCESS_TASKWORKER)
#define swIsManager()         (SwooleG.process_type==SW_PROCESS_MANAGER)
#endif

typedef struct _swPackage
{
    void *data;
    uint32_t length;
    uint32_t id;
} swPackage;

typedef struct _swDgramPacket
{
    union
    {
        struct in6_addr v6;
        struct in_addr v4;
        struct
        {
            uint16_t path_length;
        } un;
    } addr;
    uint16_t port;
    uint32_t length;
    char data[0];
} swDgramPacket;

typedef struct
{
    int length;
    char tmpfile[SW_TASK_TMPDIR_SIZE + sizeof(SW_TASK_TMP_FILE)];
} swPackage_task;

typedef struct
{
    int length;
    int worker_id;
} swPackage_response;

#if 0
int swWorker_create(swWorker *worker);
int swWorker_onTask(swFactory *factory, swEventData *task);

void swWorker_free(swWorker *worker);
void swWorker_onStart(swServer *serv);
void swWorker_onStop(swServer *serv);
int swWorker_loop(swFactory *factory, int worker_pti);
int swWorker_send2reactor(swEventData *ev_data, size_t sendn, int fd);
int swWorker_send2worker(swWorker *dst_worker, void *buf, int n, int flag);
void swWorker_clean(void);

void swWorker_signal_handler(int signo);

void swTaskWorker_init(swProcessPool *pool);
int swTaskWorker_onTask(swProcessPool *pool, swEventData *task);
int swTaskWorker_onFinish(swReactor *reactor, swEvent *event);
void swTaskWorker_onStart(swProcessPool *pool, int worker_id);
void swTaskWorker_onStop(swProcessPool *pool, int worker_id);
int swTaskWorker_finish(swServer *serv, char *data, int data_len, int flags);

int swManager_start(swFactory *factory);
pid_t swManager_spawn_user_worker(swServer *serv, swWorker* worker);
int swManager_wait_user_worker(swProcessPool *pool, pid_t pid);
#endif

int swTaskWorker_large_pack(swEventData *task, void *data, int data_len);

#define swTask_type(task)                  ((task)->info.from_fd)

#define swTaskWorker_large_unpack(task, __malloc, _buf, _length)   swPackage_task _pkg;\
    memcpy(&_pkg, task->data, sizeof(_pkg));\
    _length = _pkg.length;\
    if (_length > ServerG.serv->listen_list->protocol.package_max_length) {\
        zanWarn("task package[length=%d] is too big.", _length);\
    }\
    _buf = __malloc(_length + 1);\
    _buf[_length] = 0;\
    int tmp_file_fd = open(_pkg.tmpfile, O_RDONLY);\
    if (tmp_file_fd < 0){\
        zanError("open(%s) failed.", task->data);\
        _length = -1;\
    } else if (swoole_sync_readfile(tmp_file_fd, _buf, _length) > 0) {\
        close(tmp_file_fd);\
        unlink(_pkg.tmpfile);\
    } else {\
        _length = -1;\
        close(tmp_file_fd); \
        unlink(_pkg.tmpfile); \
    }


#ifdef __cplusplus
}
#endif

#endif
