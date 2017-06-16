/*
  +----------------------------------------------------------------------+
  | Zan                                                                  |
  +----------------------------------------------------------------------+
  | Copyright (c) 2016-2017 Zan Group                                    |
  +----------------------------------------------------------------------+
  | This source file is subject to version 2.0 of the Apache license,    |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.apache.org/licenses/LICENSE-2.0.html                      |
  | If you did not receive a copy of the Apache2.0 license and are unable|
  | to obtain it through the world-wide-web, please send a note to       |
  | zan@zanphp.io so we can mail you a copy immediately.                 |
  +----------------------------------------------------------------------+
  | Author: Zan Group   <zan@zanphp.io>                                  |
  +----------------------------------------------------------------------+
*/
#ifndef _SW_PROTOCOL
#define _SW_PROTOCOL

#include "swoole.h"
#include "swConnection.h"

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct _swProtocol
{
    /* one package: eof check */
    uint8_t split_by_eof;
    uint8_t package_eof_len;  //数据缓存结束符长度
    char package_eof[SW_DATA_EOF_MAXLEN + 1];  //数据缓存结束符

    char package_length_type;  //length field type
    uint8_t package_length_size;
    uint16_t package_length_offset;  //第几个字节开始表示长度
    uint16_t package_body_offset;  //第几个字节开始计算长度
    uint32_t package_max_length;

    int (*onPackage)(swConnection *conn, char *data, uint32_t length);
    int (*get_package_length)(struct _swProtocol *protocol, swConnection *conn, char *data, uint32_t length);
} swProtocol;

int swProtocol_get_package_length(swProtocol *protocol, swConnection *conn, char *data, uint32_t size);
int swProtocol_recv_check_length(swProtocol *protocol, swConnection *conn, swString *buffer);
int swProtocol_recv_check_eof(swProtocol *protocol, swConnection *conn, swString *buffer);

#ifdef __cplusplus
}
#endif
#endif
