/*
 +----------------------------------------------------------------------+
 | Zan                                                                  |
 +----------------------------------------------------------------------+
 | Copyright (c) 2012-2016 Swoole Team <http://github.com/swoole>       |
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
 | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
 |         Zan Group   <zan@zanphp.io>                                  |
 +----------------------------------------------------------------------+
 */


#include "php_swoole.h"
#include "zanLog.h"

typedef struct _swTimer_callback
{
    zval* callback;
    zval* data;

#if PHP_MAJOR_VERSION >= 7
    zval  _data;
    zval  _callback ;
#endif
} swTimer_callback;

static void swoole_php_onTimeout(swTimer *timer, swTimer_node *tnode);
static void swoole_php_onInterval(swTimer *timer, swTimer_node *tnode);
static int php_swoole_check_timer(int msec);

static long php_swoole_add_timer(long ms, zval *callback, zval *param, int is_tick TSRMLS_DC);
static void php_swoole_del_timer(void* data);

static zend_class_entry swoole_timer_ce;
zend_class_entry *swoole_timer_class_entry_ptr;

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_timer_tick, 0, 0, 2)
    ZEND_ARG_INFO(0, ms)
    ZEND_ARG_INFO(0, callback)
    ZEND_ARG_INFO(0, param)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_timer_after, 0, 0, 2)
    ZEND_ARG_INFO(0, ms)
    ZEND_ARG_INFO(0, callback)
    ZEND_ARG_INFO(0, param)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_timer_clear, 0, 0, 1)
    ZEND_ARG_INFO(0, timer_id)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_timer_set, 0, 0, 1)
    ZEND_ARG_INFO(0, settings)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_timer_exists, 0, 0, 1)
    ZEND_ARG_INFO(0, timer_id)
ZEND_END_ARG_INFO()

static const zend_function_entry swoole_timer_methods[] =
{
    ZEND_FENTRY(tick, ZEND_FN(swoole_timer_tick), arginfo_swoole_timer_after, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    ZEND_FENTRY(after, ZEND_FN(swoole_timer_after), arginfo_swoole_timer_tick, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    ZEND_FENTRY(exists, ZEND_FN(swoole_timer_exists), arginfo_swoole_timer_exists, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    ZEND_FENTRY(clear, ZEND_FN(swoole_timer_clear), arginfo_swoole_timer_clear, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    ZEND_FENTRY(set, ZEND_FN(swoole_timer_set), arginfo_swoole_timer_set, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_FE_END
};

void swoole_timer_init(int module_number TSRMLS_DC)
{
    memset(&timer_cfg,0x00,sizeof(swTimer_cfg));
    SWOOLE_INIT_CLASS_ENTRY(swoole_timer_ce, "swoole_timer", "Swoole\\Timer", swoole_timer_methods);
    swoole_timer_class_entry_ptr = zend_register_internal_class(&swoole_timer_ce TSRMLS_CC);
}

static long php_swoole_add_timer(long ms, zval *callback, zval *param, int is_tick TSRMLS_DC)
{
    if (ServerG.serv && is_master())
    {
        zanWarn("cannot use timer in master process.");
        return ZAN_ERR;
    }

    if (ms > 86400000 || ms <= 0)
    {
        zanWarn("The given parameters is too big and must be greater than 0.");
        return ZAN_ERR;
    }

    if (!is_taskworker())
    {
        php_swoole_check_reactor();
    }

    if (php_swoole_check_timer(ms) < 0)
    {
        return ZAN_ERR;
    }

    swTimer_callback *cb = emalloc(sizeof(swTimer_callback));
    if (!cb)
    {
        zanWarn("alloc swTimer callback failed.");
        return ZAN_ERR;
    }

    bzero(cb,sizeof(swTimer_callback));
    if (param)
    {
        cb->data = param;
        sw_zval_add_ref(&param);
        sw_copy_to_stack(cb->data,cb->_data);
    }

    if (callback)
    {
        cb->callback = callback;
        sw_zval_add_ref(&callback);
        sw_copy_to_stack(cb->callback,cb->_callback);
    }

    long id = swTimer_add(&ServerG.timer, ms, is_tick, cb,PHPTIMER_USED);
    if (id < 0)
    {
        zanWarn("addtimer failed.");
        if (cb->data) {sw_zval_ptr_dtor(&cb->data);cb->data = NULL;}
        if (cb->callback) {sw_zval_ptr_dtor(&cb->callback);cb->callback = NULL;}

        swoole_efree(cb);

        return ZAN_ERR;
    }

    return id;
}

static void php_swoole_del_timer(void* data)
{
    swTimer_callback* cb = data;
    if (cb && cb->callback) {sw_zval_ptr_dtor(&cb->callback);cb->callback = NULL;}
    if (cb && cb->data) {sw_zval_ptr_dtor(&cb->data);cb->data = NULL;}
    if (cb) swoole_efree(cb);

    return;
}

static void swoole_php_onTimeout(swTimer *timer, swTimer_node *tnode)
{
    SWOOLE_FETCH_TSRMLS;

    swTimer_callback *cb = tnode->data;
    if (!cb)
    {
        zanWarn("swoole_timer_onTimeout: swTimer_callback is NULL");
        swTimer_del(timer,tnode->id);
        return;
    }

    if (!cb->callback || PHPTIMER_USED != tnode->used_type)
    {
        zanWarn("no callback or php_used flag not used.");
        swTimer_del(timer,tnode->id);
        return;
    }

    zval **args[1];
    int argc = (cb->data)? 1:0;
    if (cb->data)
    {
        args[0] = &cb->data;
    }

    zval *retval = NULL;
    if (sw_call_user_function_ex(EG(function_table), NULL, cb->callback, &retval, argc, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        zanWarn("swoole_timer: onTimeout handler error");
    }

    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }

    if (retval)
    {
        sw_zval_ptr_dtor(&retval);
    }

    swTimer_del(timer,tnode->id);
}

static void swoole_php_onInterval(swTimer *timer, swTimer_node *tnode)
{
    SWOOLE_FETCH_TSRMLS;
    swTimer_callback *cb = tnode? tnode->data:NULL;
    if (!cb)
    {
        zanWarn("php_swoole_onInterval: swTimer_callback is NULL");
        swTimer_del(timer,tnode->id);
        return;
    }

    if (!cb->callback || PHPTIMER_USED != tnode->used_type)
    {
        swTimer_del(timer,tnode->id);
        return;
    }

    zval *ztimer_id = NULL;
    SW_MAKE_STD_ZVAL(ztimer_id);
    ZVAL_LONG(ztimer_id, tnode->id);

    zval **args[2];
    args[0] = &ztimer_id;

    int argc = (cb->data)? 2:1;
    if (cb->data)
    {
        args[1] = &cb->data;
    }

    int needDel = 0;
    zval *retval = NULL;
    if (sw_call_user_function_ex(EG(function_table), NULL, cb->callback, &retval, argc, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        zanWarn("swoole_timer: onTimerCallback handler error");
        needDel = 1;
    }

    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }

    if (retval)
    {
        sw_zval_ptr_dtor(&retval);
    }

    sw_zval_ptr_dtor(&ztimer_id);

    if (needDel)
    {
        swTimer_del(timer,tnode->id);
    }
}

static int php_swoole_check_timer(int msec)
{
    if (swTimer_init(&ServerG.timer,msec) < 0)
    {
        return ZAN_ERR;
    }

    register_after_cb(&ServerG.timer,PHPTIMER_USED,swoole_php_onTimeout);
    register_tick_cb(&ServerG.timer,PHPTIMER_USED,swoole_php_onInterval);
    register_dict_cb(&ServerG.timer,PHPTIMER_USED,php_swoole_del_timer);
    return ZAN_OK;
}

/// 周期定时器
PHP_FUNCTION(swoole_timer_tick)
{
    long after_ms = 0;
    zval *callback;
    zval *param = NULL;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "lz|z", &after_ms, &callback, &param))
    {
        return;
    }

    if (swoole_check_callable(callback TSRMLS_CC) < 0)
    {
        RETURN_FALSE;
    }

    long timer_id = php_swoole_add_timer(after_ms, callback, param, 1 TSRMLS_CC);
    if (timer_id < 0)
    {
        RETURN_FALSE;
    }

    RETURN_LONG(timer_id);
}

/// 非周期定时器
PHP_FUNCTION(swoole_timer_after)
{
    long after_ms = 0;
    zval *callback;
    zval *param = NULL;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "lz|z", &after_ms, &callback, &param))
    {
        return;
    }

    if (swoole_check_callable(callback TSRMLS_CC) < 0)
    {
        zanWarn("check callback error.");
        RETURN_FALSE;
    }

    long timer_id = php_swoole_add_timer(after_ms, callback, param, 0 TSRMLS_CC);
    if (timer_id < 0)
    {
        zanWarn("add timer node failed.");
        RETURN_FALSE;
    }

    RETURN_LONG(timer_id);
}

PHP_FUNCTION(swoole_timer_set)
{
    zval *zset = NULL;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &zset))
    {
        return;
    }

    zval *value = NULL ;
    HashTable *vht = Z_ARRVAL_P(zset);
    timer_cfg.use_time_wheel = 0;
    if (php_swoole_array_get_value(vht, "use_time_wheel", value))
    {
        convert_to_long(value);
        timer_cfg.use_time_wheel = (uint8_t) Z_LVAL_P(value);
    }

    value = NULL;
    timer_cfg.precision = 100;
    if (php_swoole_array_get_value(vht, "time_wheel_precision", value))
    {
        convert_to_long(value);
        int precision = (int)Z_LVAL_P(value);
        timer_cfg.precision =  precision < 10? 10:precision;
    }
}

PHP_FUNCTION(swoole_timer_clear)
{
    if (!ServerG.timer.set)
    {
        RETURN_FALSE;
    }

    long id;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &id))
    {
        RETURN_FALSE;
    }

    swTimer_del(&ServerG.timer,id);
    RETURN_TRUE;
}

PHP_FUNCTION(swoole_timer_exists)
{
    if (!ServerG.timer.set)
    {
        RETURN_FALSE;
    }

    long id;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &id))
    {
        return;
    }

    if (!swTimer_exist(&ServerG.timer,id))
    {
       RETURN_FALSE;
    }

    RETURN_TRUE;
}
