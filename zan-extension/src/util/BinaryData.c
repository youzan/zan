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

#include "swoole.h"
#include "swProtocol/binarydata.h"
#include "zanMemory/zanMemory.h"

int swReadI64(const uchar_t* pData, int64_t *pValue)
{
    *pValue = ((uint64_t)pData[0] << 56) | ((uint64_t)pData[1] << 48) | ((uint64_t)pData[2] << 40) |((uint64_t)pData[3] << 32)|(pData[4] << 24) |(pData[5] << 16) | (pData[6] << 8) | pData[7];

    return SW_OK;
}

int swReadI32(const uchar_t* pData, int32_t *pValue)
{
    *pValue = (pData[0] << 24) | (pData[1] << 16) | (pData[2] << 8) | pData[3];
    return SW_OK;
}

int swReadU32(const uchar_t* pData, uint32_t *pValue)
{
    *pValue = (pData[0] << 24) | (pData[1] << 16) | (pData[2] << 8) | pData[3];
    return SW_OK;
}

int swReadI16(const uchar_t* pData, int16_t *pValue)
{
    *pValue = (pData[0] << 8) | pData[1];
    return SW_OK;
}

int swReadU16(const uchar_t* pData, uint16_t *pValue)
{
    *pValue = (pData[0] << 8) | pData[1];
    return SW_OK;
}

int swReadByte(const uchar_t* pData, char* pValue)
{
    *pValue = pData[0];
    return SW_OK;
}

int swReadString(const uchar_t* pData, int nDataLen, char **ppStr, int* pLen)
{
    if (nDataLen < 4) {
        return SW_ERR;
    }

    if(swReadI32(pData, pLen) != SW_OK) {
        return SW_ERR;
    }
    if (nDataLen - 4 < *pLen) {
        return SW_ERR;
    }
    char* pTmp = *ppStr;
    if (pTmp != NULL) {
        sw_free(pTmp);
    }
    pTmp = (char*)sw_malloc(*pLen + 1);
    if (pTmp == NULL) {
        return SW_ERR;
    }
    memcpy(pTmp, pData + 4, *pLen);
    pTmp[*pLen] = 0;
    *ppStr = pTmp;
    return SW_OK;
}

int swReadBytes(const uchar_t* pData, int nDataLen, char **ppStr, int nLen)
{
    if (nDataLen < nLen) {
        return  SW_ERR;
    }
    char* pTmp = *ppStr;
    if (pTmp != NULL) {
        sw_free(pTmp);
    }
    pTmp = (char*)sw_malloc(nLen);
    if (pTmp == NULL) {
        return SW_ERR;
    }
    memcpy(pTmp, pData, nLen);
    *ppStr = pTmp;
    return SW_OK;
}

int swWriteI64(uchar_t* pData, int64_t nValue)
{
    pData[0] = (uchar_t)(nValue >> 56);
    pData[1] = (uchar_t)((nValue >> 48) & 0xFF);
    pData[2] = (uchar_t)((nValue >> 40) & 0xFF);
    pData[3] = (uchar_t)((nValue >> 32) & 0xFF);
    pData[4] = (uchar_t)((nValue >> 24) & 0xFF);
    pData[5] = (uchar_t)((nValue >> 16) & 0xFF);
    pData[6] = (uchar_t)((nValue >> 8)  & 0xFF);
    pData[7] = (uchar_t)(nValue & 0xFF);
    return SW_OK;
}

int swWriteI32(uchar_t* pData, int32_t nValue)
{
    pData[0] = (uchar_t)(nValue >> 24);
    pData[1] = (uchar_t)((nValue >> 16) & 0xFF);
    pData[2] = (uchar_t)((nValue >> 8) & 0xFF);
    pData[3] = (uchar_t)(nValue & 0xFF);
    return SW_OK;
}

int swWriteU32(uchar_t* pData, uint32_t nValue)
{
    pData[0] = (uchar_t)(nValue >> 24);
    pData[1] = (uchar_t)((nValue >> 16) & 0xFF);
    pData[2] = (uchar_t)((nValue >> 8) & 0xFF);
    pData[3] = (uchar_t)(nValue & 0xFF);
    return SW_OK;
}

int swWriteI16(uchar_t* pData, int16_t nValue)
{
    pData[0] = (uchar_t)(nValue >> 8);
    pData[1] = (uchar_t)(nValue & 0xFF);
    return SW_OK;
}

int swWriteU16(uchar_t* pData, uint16_t nValue)
{
    pData[0] = (uchar_t)(nValue >> 8);
    pData[1] = (uchar_t)(nValue & 0xFF);
    return SW_OK;
}

int swWriteByte(uchar_t* pData, char cValue)
{
    pData[0] = (char)cValue;
    return SW_OK;
}

int swWriteString(uchar_t* pData, const char* pStr, int nLen)
{
    swWriteI32(pData, nLen);
    memcpy(pData + 4, pStr, nLen);
    return SW_OK;
}

int swWriteBytes(uchar_t* pData, const char* pStr, int nLen)
{
    memcpy(pData, pStr, nLen);
    return SW_OK;
}
