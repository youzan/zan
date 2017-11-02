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
#include "php_swoole.h"
#include "swProtocol/nova.h"

#include "zanLog.h"

#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <ifaddrs.h>

#ifdef HAVE_PCRE
#include <ext/spl/spl_iterators.h>
#endif
#include <ext/session/php_session.h>
#include <ext/standard/php_var.h>

#include "zend_variables.h"

#define PS_DELIMITER '|'
#define PS_UNDEF_MARKER '!'

static uint64_t current_seq_no = 0;
static uint64_t swoole_get_seq_no();
static int getServiceIp(char** ppIp);

static uint64_t swoole_get_seq_no()
{
    if (++current_seq_no >= INT64_MAX) {
        current_seq_no = 1;
    }

    return current_seq_no;
}

static int getServiceIp(char** ppIp)
{
    if (!ppIp || *ppIp != NULL)
    {
        return SW_ERR;
    }

    void *in_addr = NULL;
    struct ifaddrs *ifa = NULL;
    struct ifaddrs *lsif = NULL;
    if (getifaddrs(&lsif) != 0 || !lsif)
    {
        return SW_ERR;
    }

    int result = SW_ERR;
    char* pTmp = sw_malloc(SW_IP_MAX_LENGTH);
    if (!pTmp)
    {
        goto get_result;
    }

    for(ifa=lsif; ifa != NULL; ifa=ifa->ifa_next) {
        if(ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_INET)
        {
            continue;
        }

        in_addr = &(((struct sockaddr_in *)(ifa->ifa_addr))->sin_addr);
        memset(pTmp,0x00,SW_IP_MAX_LENGTH);
        if (!inet_ntop(AF_INET, in_addr, pTmp,SW_IP_MAX_LENGTH))
        {
            continue;
        }
        else if (strncmp(pTmp, "127.",strlen("127.")) != 0)
        {
            result = SW_OK;
            break;
        }
    }

get_result:
    freeifaddrs(lsif);
    *ppIp = pTmp;
    return result;
}

PHP_FUNCTION(nova_decode)
{
    char* pBuf;
    zend_size_t nBufLen;

    zval* zsname;
    zval* zmname;
    zval* zip;
    zval* zport;
    zval* zseqno;
    zval* zdata;
    zval* zattach;

    if (is_master() || is_networker())
    {
        zanWarn("nova_decode can not be used in master or networker process, type=%d", ServerG.process_type);
        RETURN_FALSE;
    }

#if PHP_MAJOR_VERSION < 7
    if(FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "szzzzzzz", &pBuf, &nBufLen, &zsname, &zmname, &zip, &zport, &zseqno, &zattach, &zdata )) {
#else
    if(FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sz/z/z/z/z/z/z/", &pBuf, &nBufLen, &zsname, &zmname, &zip, &zport, &zseqno, &zattach, &zdata)) {
#endif
        RETURN_FALSE;
    }

    if (swNova_IsNovaPack(pBuf, nBufLen) == SW_ERR) {
        zanWarn("not a nova packet");
        RETURN_FALSE;
    }

    //decode
    swNova_Header *pHeader = createNovaHeader();
    if (swNova_unpack(pBuf, nBufLen, pHeader) == SW_ERR) {
        zanWarn("unpack nova failer");
        deleteNovaHeader(pHeader);
        RETURN_FALSE;
    }

    if (pHeader->msg_size > nBufLen) {
        zanWarn("body len not enough,need %ld,but only have %ld",pHeader->msg_size,nBufLen);
        deleteNovaHeader(pHeader);
        RETURN_FALSE;
    }

    SW_ZVAL_STRINGL(zsname, pHeader->service_name, pHeader->service_len, 1);
    SW_ZVAL_STRINGL(zmname, pHeader->method_name, pHeader->method_len, 1);
    ZVAL_LONG(zip, (long ) pHeader->ip);
    ZVAL_LONG(zport, (long ) pHeader->port);
    ZVAL_LONG(zseqno, (long ) pHeader->seq_no);
    SW_ZVAL_STRINGL(zdata, pBuf + pHeader->head_size, pHeader->msg_size - pHeader->head_size, 1);
    SW_ZVAL_STRINGL(zattach, pHeader->attach, pHeader->attach_len, 1);

    deleteNovaHeader(pHeader);
    RETURN_TRUE;
}

PHP_FUNCTION(nova_decode_new)
{
    char* pBuf;
    zend_size_t nBufLen;

    if (is_master() || is_networker())
    {
        zanWarn("nova_decode_new can not be used in master or networker process, type=%d", ServerG.process_type);
        RETURN_FALSE;
    }

    if(FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &pBuf, &nBufLen)) {
        RETURN_FALSE;
    }

    if (swNova_IsNovaPack(pBuf, nBufLen) == SW_ERR) {
        zanWarn("not a nova packet");
        RETURN_FALSE;
    }

    //decode
    swNova_Header *pHeader = createNovaHeader();
    if (swNova_unpack(pBuf, nBufLen, pHeader) == SW_ERR) {
        zanWarn("unpack nova failer");
        deleteNovaHeader(pHeader);
        RETURN_FALSE;
    }

    if (pHeader->msg_size > nBufLen) {
        zanWarn("body len not enough,need %ld,but only have %ld",pHeader->msg_size,nBufLen);
        deleteNovaHeader(pHeader);
        RETURN_FALSE;
    }

    array_init(return_value);
    sw_add_assoc_stringl_ex(return_value, ZEND_STRS("sName"), pHeader->service_name, pHeader->service_len, 1);
    sw_add_assoc_stringl_ex(return_value, ZEND_STRS("mName"), pHeader->method_name, pHeader->method_len, 1);
    sw_add_assoc_long_ex(return_value, ZEND_STRS("ip"), (long ) pHeader->ip);
    sw_add_assoc_long_ex(return_value, ZEND_STRS("port"), (long ) pHeader->port);
    sw_add_assoc_long_ex(return_value, ZEND_STRS("seqNo"), (long ) pHeader->seq_no);
    sw_add_assoc_stringl_ex(return_value, ZEND_STRS("data"), pBuf + pHeader->head_size, pHeader->msg_size - pHeader->head_size, 1);
    sw_add_assoc_stringl_ex(return_value, ZEND_STRS("attach"), pHeader->attach, pHeader->attach_len, 1);

    deleteNovaHeader(pHeader);
}

PHP_FUNCTION(nova_encode)
{
    char* pServiceName = NULL;
    zend_size_t nServiceNameLen = 0;
    char* pMethodName = NULL;
    zend_size_t nMethodNameLen = 0;
    char* pAttach = NULL;
    zend_size_t nAttachLen = 0;
    long nIp = 0;
    long nPort = -1;
    long nSeqNo = -1;
    char* pData = NULL;
    zend_size_t nDataLen = 0;
    zval* zbuffer = NULL;

    if (is_master() || is_networker())
    {
        zanWarn("nova_encode can not be used in master or networker process, type=%d", ServerG.process_type);
        RETURN_FALSE;
    }

#if PHP_MAJOR_VERSION < 7
    if(FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sslllssz", &pServiceName, &nServiceNameLen, &pMethodName, &nMethodNameLen, &nIp, &nPort,
                                &nSeqNo, &pAttach, &nAttachLen, &pData, &nDataLen, &zbuffer)) {
#else
    if(FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sslllssz/", &pServiceName, &nServiceNameLen, &pMethodName, &nMethodNameLen, &nIp, &nPort,
                                &nSeqNo, &pAttach, &nAttachLen, &pData, &nDataLen, &zbuffer)) {
#endif
        RETURN_FALSE;
    }

    swNova_Header* pHeader = createNovaHeader();
    if(!pHeader)
    {
        RETURN_FALSE;
    }

    pHeader->magic = NOVA_MAGIC;
    pHeader->version = 1;
    pHeader->ip = nIp;
    pHeader->port = nPort;

    pHeader->service_len = nServiceNameLen <= 0? 0:nServiceNameLen;
    pHeader->method_len = nMethodNameLen <= 0? 0:nMethodNameLen;
    pHeader->attach_len = nAttachLen <= 0? 0:nAttachLen;
    int headLen = NOVA_HEADER_COMMON_LEN + pHeader->service_len + pHeader->method_len + pHeader->attach_len;
    if (headLen > 0x7fff)
    {
        RETURN_FALSE;
    }

    pHeader->head_size = (int16_t)headLen;

    pHeader->service_name = sw_malloc(pHeader->service_len + 1);
    if (pServiceName)
    {
        memcpy(pHeader->service_name, pServiceName, pHeader->service_len);
    }
    pHeader->service_name[pHeader->service_len] = 0;

    pHeader->method_name = sw_malloc(pHeader->method_len + 1);
    if (pMethodName)
    {
        memcpy(pHeader->method_name, pMethodName, pHeader->method_len);
    }
    pHeader->method_name[pHeader->method_len] = 0;

    pHeader->seq_no = nSeqNo;

    pHeader->attach = sw_malloc(pHeader->attach_len + 1);
    if (pAttach)
    {
        memcpy(pHeader->attach, pAttach, pHeader->attach_len);
    }
    pHeader->attach[pHeader->attach_len] = 0;

    char* pBuffer = NULL;
    int nBufLen = 0;
    if(swNova_pack(pHeader, pData, nDataLen, &pBuffer, &nBufLen) < 0)
    {
        deleteNovaHeader(pHeader);
        sw_free(pBuffer);
        RETURN_FALSE;
    }

    SW_ZVAL_STRINGL(zbuffer, pBuffer, nBufLen, 1);

    deleteNovaHeader(pHeader);
    sw_free(pBuffer);
    RETURN_TRUE;
}

PHP_FUNCTION(nova_encode_new)
{
    char* pServiceName = NULL;
    zend_size_t nServiceNameLen = 0;
    char* pMethodName = NULL;
    zend_size_t nMethodNameLen = 0;
    char* pAttach = NULL;
    zend_size_t nAttachLen = 0;
    long nIp = 0;
    long nPort = -1;
    long nSeqNo = -1;
    char* pData = NULL;
    zend_size_t nDataLen = 0;

    if (is_master() || is_networker())
    {
        zanWarn("nova_encode_new can not be used in master or networker process, type=%d", ServerG.process_type);
        RETURN_FALSE;
    }

    if(FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sslllss", &pServiceName, &nServiceNameLen, &pMethodName, &nMethodNameLen, &nIp, &nPort,
                                &nSeqNo, &pAttach, &nAttachLen, &pData, &nDataLen)) {
        RETURN_FALSE;
    }

    swNova_Header* pHeader = createNovaHeader();
    if(!pHeader)
    {
        RETURN_FALSE;
    }

    pHeader->magic = NOVA_MAGIC;
    pHeader->version = 1;
    pHeader->ip = nIp;
    pHeader->port = nPort;

    pHeader->service_len = nServiceNameLen <= 0? 0:nServiceNameLen;
    pHeader->method_len = nMethodNameLen <= 0? 0:nMethodNameLen;
    pHeader->attach_len = nAttachLen <= 0? 0:nAttachLen;
    int headLen = NOVA_HEADER_COMMON_LEN + pHeader->service_len + pHeader->method_len + pHeader->attach_len;
    if (headLen > 0x7fff)
    {
        RETURN_FALSE;
    }

    pHeader->head_size = (int16_t)headLen;

    pHeader->service_name = sw_malloc(pHeader->service_len + 1);
    if (pServiceName)
    {
        memcpy(pHeader->service_name, pServiceName, pHeader->service_len);
    }
    pHeader->service_name[pHeader->service_len] = 0;

    pHeader->method_name = sw_malloc(pHeader->method_len + 1);
    if (pMethodName)
    {
        memcpy(pHeader->method_name, pMethodName, pHeader->method_len);
    }
    pHeader->method_name[pHeader->method_len] = 0;

    pHeader->seq_no = nSeqNo;

    pHeader->attach = sw_malloc(pHeader->attach_len + 1);
    if (pAttach)
    {
        memcpy(pHeader->attach, pAttach, pHeader->attach_len);
    }
    pHeader->attach[pHeader->attach_len] = 0;

    char* pBuffer = NULL;
    int nBufLen = 0;
    if(swNova_pack(pHeader, pData, nDataLen, &pBuffer, &nBufLen) < 0)
    {
        deleteNovaHeader(pHeader);
        sw_free(pBuffer);
        RETURN_FALSE;
    }

    SW_RETVAL_STRINGL(pBuffer, nBufLen, 1);
    deleteNovaHeader(pHeader);
    sw_free(pBuffer);
}

PHP_FUNCTION(is_nova_packet)
{
    char* pData = NULL;
    zend_size_t nLen =  0;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &pData, &nLen)) {
        RETURN_FALSE;
    }

    if (swNova_IsNovaPack(pData, nLen) < 0) {
        RETURN_FALSE;
    }

    RETURN_TRUE;
}

PHP_FUNCTION(nova_get_sequence)
{
    if (is_master() || is_networker())
    {
        zanWarn("nova_get_sequence can not be used in master or networker process, type=%d", ServerG.process_type);
        RETURN_FALSE;
    }

    RETURN_LONG(swoole_get_seq_no());
}

PHP_FUNCTION(nova_get_time)
{
    if (is_master() || is_networker())
    {
        zanWarn("nova_get_time can not be used in master or networker process, type=%d", ServerG.process_type);
        RETURN_FALSE;
    }

    RETURN_LONG(ServerGS->server_time);
}

PHP_FUNCTION(nova_get_ip)
{
    if (is_networker())
    {
        zanWarn("nova_get_ip can not be used in networker process, type=%d", ServerG.process_type);
        RETURN_FALSE;
    }

    char* ip = NULL;
    if(getServiceIp(&ip) < 0)
    {
        sw_free(ip);
        RETURN_EMPTY_STRING();
    }

    size_t buf_len = strlen(ip);
    char* buf = emalloc(buf_len + 1);
    memcpy(buf, ip, buf_len);
    sw_free(ip);

    buf[buf_len] = 0;
    SW_RETVAL_STRINGL(buf, buf_len, 0);
}

