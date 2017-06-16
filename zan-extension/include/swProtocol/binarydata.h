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


#ifndef _SW_BINARY_H_
#define _SW_BINARY_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>

#ifndef htonll
#if HAVE_BYTESWAP_H
#include <byteswap.h>
#else
#define bswap_16(value) ((((value) & 0xFF) << 8) | ((value) >> 8))
#define bswap_32(value)                                         \
(((uint32_t)(bswap_16((uint16_t)((value) & 0xFFFF))) << 16) | \
((uint32_t)(bswap_16((uint16_t)((value) >> 16)))))
#define bswap_64(value)                                             \
(((uint64_t)(bswap_32((uint32_t)((value) & 0xFFFFFFFF))) << 32) |  \
((uint64_t)(bswap_32((uint32_t)((value) >> 32)))))
#endif

#ifdef WORDS_BIGENDIAN
#define htonll(value) (value)
#define ntohll(value) (value)
#else
#define htonll(value) (bswap_64(value))
#define ntohll(value) (bswap_64(value))
#endif
#endif

typedef unsigned char	uchar_t;

/**
 *  从二进制数据中读64位的整数据
 *
 *  @param data  二进制数据
 *  @param value 64位整数结果
 *
 *  @return 返回0成功，其他表示出错
 */
int swReadI64(const uchar* data, int64_t *value);

/**
 *  从二进制数据中读32位整数
 *
 *  @param data  二进制数据
 *  @param value 32位证书结果
 *
 *  @return 返回0成功，其他表示出错
 */
int swReadI32(const uchar* data, int32_t *value);
int swReadU32(const uchar* data, uint32_t *value);

/**
 *  从二进制中读取16位整数
 *
 *  @param data  二进制数据
 *  @param value 16位整数结果
 *
 *  @return 成功返回0
 */
int swReadI16(const uchar* data, int16_t *value);
int swReadU16(const uchar* data, uint16_t *value);

/**
 *  从二进制中读取一个Byte
 *
 *  @param data  二进制数据
 *  @param value 读取结果
 *
 *  @return 成功返回0
 */
int swReadByte(const uchar* data, char *value);

/**
 *  从二进制数据中读取字符串
 *
 *  @param data 二进制数据
 *  @param str  读取的字符串
 *
 *  @return 成功返回0
 */
int swReadString(const uchar* data, int data_len, char **str, int* len);
int swReadBytes(const uchar* data, int data_len, char **str, int len);



int swWriteI64(uchar* data, int64_t value);
int swWriteI32(uchar* data, int32_t value);
int swWriteU32(uchar* data, uint32_t value);
int swWriteI16(uchar* data, int16_t value);
int swWriteU16(uchar* data, uint16_t value);
int swWriteByte(uchar* data, char value);
int swWriteString(uchar* data, const char* str, int len);
int swWriteBytes(uchar* data, const char* str, int len);

#ifdef __cplusplus
}
#endif

#endif
