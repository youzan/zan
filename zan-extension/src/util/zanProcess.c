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

#include "zanProcess.h"
#include "php_swoole.h"
#include "zanLog.h"

#if !(defined(__APPLE__) || defined(__FreeBSD__))
extern char *program_invocation_name;
#endif

static char *origin_cmdline = NULL;

void zan_initproctitle()
{
#if defined(__APPLE__) || defined(__FreeBSD__)
    const char *program_invocation_name = getprogname();
#endif
    int size = strlen(program_invocation_name) + 1;
    origin_cmdline = malloc(size);
    bzero(origin_cmdline, size);
    strcpy(origin_cmdline, program_invocation_name);
}

void zan_setproctitle(char *title, int prefix_only)
{
    SWOOLE_FETCH_TSRMLS;
    if (strcmp(sapi_module.name, "cli") != 0) {
        return;
    }
    int i;
    char *settitle = title;
    char *tmpbuff = NULL;

    zval *function = NULL;
    zval *retval = NULL;
    SW_MAKE_STD_ZVAL(function);

    if (prefix_only) {
        int size = 0;
        size += strlen(origin_cmdline) + 1;
        size += strlen(settitle) + 1;

        for (i = 0; i < SG(request_info).argc; i++) {
            size += strlen(SG(request_info).argv[i]) + 1;
        }

        tmpbuff = malloc(size);
        bzero(tmpbuff, size);

        strcat(tmpbuff, settitle);
        strcat(tmpbuff, " ");

        strcat(tmpbuff, origin_cmdline);
        strcat(tmpbuff, " ");

        for (i = 0; i < SG(request_info).argc; i++) {
            if (i) strcat(tmpbuff, " ");
            strcat(tmpbuff, SG(request_info).argv[i]);
        }

        settitle = tmpbuff;
    }

#if defined(__APPLE__) || defined(__FreeBSD__)
    setprogname(settitle);
    return;
#endif
    zval *ztitle = NULL;
    zval **args[1];
    SW_MAKE_STD_ZVAL(ztitle);
    SW_ZVAL_STRING(function, "cli_set_process_title", 1);
    SW_ZVAL_STRING(ztitle, settitle, 1);
    args[0] = &ztitle;

    if (sw_call_user_function_ex(EG(function_table), NULL, function, &retval, 1, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        zanWarn("set process failure");
    }

    if (function) {
        sw_zval_ptr_dtor(&function);
    }
    if (retval) {
        sw_zval_ptr_dtor(&retval);
    }
    if (ztitle) {
        sw_zval_ptr_dtor(&ztitle);
    }
    if (tmpbuff) {
        free(tmpbuff);
    }
}

void zan_freeproctitle()
{
    if (origin_cmdline) {
        free(origin_cmdline);
    }
}
