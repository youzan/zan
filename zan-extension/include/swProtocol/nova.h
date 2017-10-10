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
  | Author: Zan Group   <zan@zanphp.io>                                  |
  +----------------------------------------------------------------------+
*/

#ifndef __NOVA_H__
#define __NOVA_H__

#include "swoole.h"
#include "binarydata.h"
#include "php.h"

#ifdef __cplusplus
extern "C"
{
#endif

#include <arpa/inet.h>

#define NOVA_MAGIC              0xdabc
#define NOVA_HEADER_COMMON_LEN  37

#define CHECK_PACK  if (off > header->head_size) { \
                        zanWarn("unpack error,"); \
                        return SW_ERR; \
                    }

typedef struct swNova_Header{
    int32_t     msg_size;
    uint16_t    magic;
    int16_t     head_size;
    int8_t      version;
    uint32_t    ip;
    uint32_t    port;
    int32_t     service_len;
    char        *service_name;
    int32_t     method_len;
    char        *method_name;
    int64_t     seq_no;
    int32_t     attach_len;
    char        *attach;
}swNova_Header;

swNova_Header* createNovaHeader();
void deleteNovaHeader(swNova_Header* header);
/**
 *  从二进制中解析出nova包头中主要数据
 *
 *  @param data   二进制数据
 *  @param length 二进制数据长度
 *  @param sname  读取的服务名
 *  @param mname  读取的方法名
 *  @param seq_no 读取的seq_no
 *  @param hsize  nova包头长度
 *
 *  @return 成功返回0，出错返回其他
 */
int swNova_unpack(char* data, int length, swNova_Header* header);

/**
 *  打包数据
 *
 *  @param sname  服务名
 *  @param mname  方法名
 *  @param seq_no seq_no
 *  @param data   打包后的数据
 *  @param length 打包后的长度
 *
 *  @return 成功返回0
 */
int swNova_pack(swNova_Header* header, char* body, int len, char **data, int32_t* length);

/**
 *  获取nova包长
 *
 *  @param protocol <#protocol description#>
 *  @param conn     <#conn description#>
 *  @param data     <#data description#>
 *  @param size     <#size description#>
 *
 *  @return <#return value description#>
 */


/**
 *  通过magic判断一个包是否是nova协议
 *
 *  @param data 数据流
 *
 *  @return 是返回0， 否则返回-1
 */
int swNova_IsNovaPack(const char* data, int nLen);

#ifdef __cplusplus
}
#endif

#endif
