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

#include "swLog.h"
#include "swLock.h"
#include "swFactory.h"
#include "swGlobalVars.h"

#define swThreadPool_thread(p,id) (&p->threads[id])
static void* swThreadPool_loop(void *arg);

int swThreadPool_create(swThreadPool *pool, int thread_num)
{
	if (!pool){
		return SW_ERR;
	}

    bzero(pool, sizeof(swThreadPool));
    pool->threads = (swThread *) sw_calloc(thread_num, sizeof(swThread));
    pool->params = (swThreadParam *) sw_calloc(thread_num, sizeof(swThreadParam));

    if (pool->threads == NULL || pool->params == NULL)
    {
    	sw_free(pool->threads);
    	sw_free(pool->params);
        swWarn("swThreadPool_create malloc fail");
        return SW_ERR;
    }

    swTrace("threads=%p|params=%p", pool->threads, pool->params);

#ifdef SW_THREADPOOL_USE_CHANNEL
    pool->chan = swChannel_create(1024 * 256, 512, 0);
    if (pool->chan == NULL)
    {
        swWarn("swThreadPool_create create channel failed");
        sw_free(pool->threads);
        sw_free(pool->params);
        return SW_ERR;
    }
#else
    if (swRingQueue_init(&pool->queue, SW_THREADPOOL_QUEUE_LEN) < 0)
    {
    	sw_free(pool->threads);
    	sw_free(pool->params);
        return SW_ERR;
    }
#endif

//    pthread_mutex_init(&(pool->mutex), NULL);
//    pthread_cond_init(&(pool->cond), NULL);
    if (swCond_create(&pool->cond) < 0){
    	sw_free(pool->threads);
    	sw_free(pool->params);
    	return SW_ERR;
    }

    pool->thread_num = thread_num;

    return SW_OK;
}

int swThreadPool_dispatch(swThreadPool *pool, void *task, int task_len)
{
    int ret = 0;
    int index = 0;
    pool->cond.lock.lock(&pool->cond.lock);
    for (index = 0;index < 5;index++)
    {
#ifdef SW_THREADPOOL_USE_CHANNEL
		ret = swChannel_push(pool->chan, task, task_len);
#else
		ret = swRingQueue_push(&pool->queue, task);
#endif
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
        return SW_ERR;
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
            swWarn("pthread_create failed. Error: %s[%d]", strerror(errno), errno);
            return SW_ERR;
        }
    }

    return SW_OK;
}

int swThreadPool_free(swThreadPool *pool)
{
    if (pool->shutdown)
    {
        return SW_ERR;
    }

    pool->shutdown = 1;

    //broadcast all thread
//    pthread_cond_broadcast(&(pool->cond));
    pool->cond.broadcast(&pool->cond);
    int index = 0;
    for (index = 0; index < pool->thread_num; index++)
    {
        pthread_join((swThreadPool_thread(pool,index)->tid), NULL);
    }

#ifdef SW_THREADPOOL_USE_CHANNEL
    swChannel_free(pool->chan);
#else
    swRingQueue_free(&pool->queue);
#endif

    pool->cond.free(&pool->cond);
    sw_free(pool->threads);
    sw_free(pool->params);
    return SW_OK;
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

    while (SwooleG.running)
    {
 //     pthread_mutex_lock(&(pool->mutex));
    	pool->cond.lock.lock(&pool->cond.lock);
        if (pool->shutdown)
        {
//            pthread_mutex_unlock(&(pool->mutex));
        	pool->cond.lock.unlock(&pool->cond.lock);
            swTrace("thread [%d] will exit\n", id);
            pthread_exit(NULL);
        }

        while (!pool->shutdown && pool->task_num == 0)
        {
//            pthread_cond_wait(&(pool->cond), &(pool->mutex));
        	pool->cond.wait(&pool->cond);
        }

        swTrace("thread [%d] is starting to work\n", id);

        void *task = NULL;
        int ret = swRingQueue_pop(&pool->queue, &task);
//      pthread_mutex_unlock(&(pool->mutex));
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

