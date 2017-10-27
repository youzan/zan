/*
 +----------------------------------------------------------------------+
 | Zan                                                                  |
 +----------------------------------------------------------------------+
 | Copyright (c) 2012-2016 Swoole Team <http://github.com/swoole>       |
 +----------------------------------------------------------------------+
 | This source file is subject to version 2.0 of the Apache license,    |
 | that is bundled with this package in the file LICENSE, and is        |
 | available through the world-wide-web at the following url:           |
 | http://www.apache.org/licenses/LICENSE-2.0.html                      |
 | If you did not receive a copy of the Apache2.0 license and are unable|
 | to obtain it through the world-wide-web, please send a note to       |
 | license@swoole.com so we can mail you a copy immediately.            |
 +----------------------------------------------------------------------+
 | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
 +----------------------------------------------------------------------+
 */

#include "zanGlobalVar.h"
#include "zanLog.h"

#define swThreadPool_thread(p,id) (&p->threads[id])
static void* swThreadPool_loop(void *arg);

int swThreadPool_create(swThreadPool *pool, int thread_num)
{
    if (!pool){
        return ZAN_ERR;
    }

    bzero(pool, sizeof(swThreadPool));
    pool->threads = (swThread *) sw_calloc(thread_num, sizeof(swThread));
    pool->params = (swThreadParam *) sw_calloc(thread_num, sizeof(swThreadParam));

    if (pool->threads == NULL || pool->params == NULL)
    {
        sw_free(pool->threads);
        sw_free(pool->params);
        zanFatalError("swThreadPool_create malloc fail");
        return ZAN_ERR;
    }

    zanTrace("threads=%p|params=%p", pool->threads, pool->params);
    if (swRingQueue_init(&pool->queue, SW_THREADPOOL_QUEUE_LEN) < 0)
    {
        sw_free(pool->threads);
        sw_free(pool->params);
        return ZAN_ERR;
    }

    if (zanCond_create(&pool->cond) < 0) {
        sw_free(pool->threads);
        sw_free(pool->params);
        return ZAN_ERR;
    }

    pool->thread_num = thread_num;

    return ZAN_OK;
}

int swThreadPool_dispatch(swThreadPool *pool, void *task, int task_len)
{
    int ret = 0;
    int index = 0;
    pool->cond.lock.lock(&pool->cond.lock);
    for (index = 0;index < 5;index++)
    {
        ret = swRingQueue_push(&pool->queue, task);
        if (ret >= 0)
        {
           break;
        }

        usleep(index+10);
        continue;
    }

    pool->cond.lock.unlock(&pool->cond.lock);
    if (ret < 0)
    {
        return ZAN_ERR;
    }
    else
    {
        sw_atomic_t *task_num = &pool->task_num;
        sw_atomic_fetch_add(task_num, 1);
    }

    return pool->cond.notify(&pool->cond);
}

int swThreadPool_run(swThreadPool *pool)
{
    int index = 0;
    for (index = 0; index < pool->thread_num; index++)
    {
        pool->params[index].pti = index;
        pool->params[index].object = pool;
        if (pthread_create(&(swThreadPool_thread(pool,index)->tid), NULL, swThreadPool_loop, &pool->params[index]) < 0)
        {
            zanError("pthread_create failed");
            return ZAN_ERR;
        }
    }

    return ZAN_OK;
}

int swThreadPool_free(swThreadPool *pool)
{
    if (pool->shutdown)
    {
        return ZAN_ERR;
    }

    pool->shutdown = 1;

    //broadcast all thread
    pool->cond.broadcast(&pool->cond);
    int index = 0;
    for (index = 0; index < pool->thread_num; index++)
    {
        pthread_join((swThreadPool_thread(pool,index)->tid), NULL);
    }

    swRingQueue_free(&pool->queue);
    pool->cond.free(&pool->cond);
    sw_free(pool->threads);
    sw_free(pool->params);
    return ZAN_OK;
}

static void* swThreadPool_loop(void *arg)
{
    swThreadParam *param = arg;
    swThreadPool *pool = param->object;

    int id = param->pti;
    if (pool->onStart)
    {
        pool->onStart(pool, id);
    }

    while (ServerG.running)
    {
        pool->cond.lock.lock(&pool->cond.lock);
        if (pool->shutdown)
        {
            pool->cond.lock.unlock(&pool->cond.lock);
            zanTrace("thread [%d] will exit\n", id);
            pthread_exit(NULL);
        }

        while (!pool->shutdown && pool->task_num == 0)
        {
            pool->cond.wait(&pool->cond);
        }

        zanTrace("thread [%d] is starting to work\n", id);

        void *task = NULL;
        int ret = swRingQueue_pop(&pool->queue, &task);
        pool->cond.lock.unlock(&pool->cond.lock);

        if (ret >= 0)
        {
            sw_atomic_t *task_num = &pool->task_num;
            sw_atomic_fetch_sub(task_num, 1);
            pool->onTask(pool, (void *) task, ret);
        }
    }

    if (pool->onStop)
    {
        pool->onStop(pool, id);
    }

    pthread_exit(NULL);
    return NULL;
}

