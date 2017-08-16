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

#include "swoole.h"
#include "swProtocol/zanbinarydata.h"
#include "swMemory/memoryPool.h"

int zanReadI64(const uchar_t* pData, int64_t *pValue)
{
    *pValue = ((uint64_t)pData[0] << 56) | ((uint64_t)pData[1] << 48) | ((uint64_t)pData[2] << 40) |((uint64_t)pData[3] << 32)|(pData[4] << 24) |(pData[5] << 16) | (pData[6] << 8) | pData[7];

    return ZAN_OK;
}

int zanReadI32(const uchar_t* pData, int32_t *pValue)
{
    *pValue = (pData[0] << 24) | (pData[1] << 16) | (pData[2] << 8) | pData[3];
    return ZAN_OK;
}

int zanReadU32(const uchar_t* pData, uint32_t *pValue)
{
    *pValue = (pData[0] << 24) | (pData[1] << 16) | (pData[2] << 8) | pData[3];
    return ZAN_OK;
}

int zanReadI16(const uchar_t* pData, int16_t *pValue)
{
    *pValue = (pData[0] << 8) | pData[1];
    return ZAN_OK;
}

int zanReadU16(const uchar_t* pData, uint16_t *pValue)
{
    *pValue = (pData[0] << 8) | pData[1];
    return ZAN_OK;
}

int zanReadByte(const uchar_t* pData, char* pValue)
{
    *pValue = pData[0];
    return ZAN_OK;
}

int zanReadString(const uchar_t* pData, int nDataLen, char **ppStr, int* pLen)
{
    if (nDataLen < 4) {
        return ZAN_ERR;
    }

    if(zanReadI32(pData, pLen) != SW_OK) {
        return ZAN_ERR;
    }
    if (nDataLen - 4 < *pLen) {
        return ZAN_ERR;
    }
    char* pTmp = *ppStr;
    if (pTmp != NULL) {
        sw_free(pTmp);
    }
    pTmp = (char*)sw_malloc(*pLen + 1);
    if (pTmp == NULL) {
        return ZAN_ERR;
    }
    memcpy(pTmp, pData + 4, *pLen);
    pTmp[*pLen] = 0;
    *ppStr = pTmp;
    return ZAN_OK;
}

int zanReadBytes(const uchar_t* pData, int nDataLen, char **ppStr, int nLen)
{
    if (nDataLen < nLen) {
        return  ZAN_ERR;
    }
    char* pTmp = *ppStr;
    if (pTmp != NULL) {
        sw_free(pTmp);
    }
    pTmp = (char*)sw_malloc(nLen);
    if (pTmp == NULL) {
        return ZAN_ERR;
    }
    memcpy(pTmp, pData, nLen);
    *ppStr = pTmp;
    return ZAN_OK;
}

int zanWriteI64(uchar_t* pData, int64_t nValue)
{
    pData[0] = (uchar_t)(nValue >> 56);
    pData[1] = (uchar_t)((nValue >> 48) & 0xFF);
    pData[2] = (uchar_t)((nValue >> 40) & 0xFF);
    pData[3] = (uchar_t)((nValue >> 32) & 0xFF);
    pData[4] = (uchar_t)((nValue >> 24) & 0xFF);
    pData[5] = (uchar_t)((nValue >> 16) & 0xFF);
    pData[6] = (uchar_t)((nValue >> 8)  & 0xFF);
    pData[7] = (uchar_t)(nValue & 0xFF);
    return ZAN_OK;
}

int zanWriteI32(uchar_t* pData, int32_t nValue)
{
    pData[0] = (uchar_t)(nValue >> 24);
    pData[1] = (uchar_t)((nValue >> 16) & 0xFF);
    pData[2] = (uchar_t)((nValue >> 8) & 0xFF);
    pData[3] = (uchar_t)(nValue & 0xFF);
    return ZAN_OK;
}

int zanWriteU32(uchar_t* pData, uint32_t nValue)
{
    pData[0] = (uchar_t)(nValue >> 24);
    pData[1] = (uchar_t)((nValue >> 16) & 0xFF);
    pData[2] = (uchar_t)((nValue >> 8) & 0xFF);
    pData[3] = (uchar_t)(nValue & 0xFF);
    return ZAN_OK;
}

int zanWriteI16(uchar_t* pData, int16_t nValue)
{
    pData[0] = (uchar_t)(nValue >> 8);
    pData[1] = (uchar_t)(nValue & 0xFF);
    return ZAN_OK;
}

int zanWriteU16(uchar_t* pData, uint16_t nValue)
{
    pData[0] = (uchar_t)(nValue >> 8);
    pData[1] = (uchar_t)(nValue & 0xFF);
    return ZAN_OK;
}

int zanWriteByte(uchar_t* pData, char cValue)
{
    pData[0] = (char)cValue;
    return ZAN_OK;
}

int zanWriteString(uchar_t* pData, const char* pStr, int nLen)
{
    zanWriteI32(pData, nLen);
    memcpy(pData + 4, pStr, nLen);
    return ZAN_OK;
}

int zanWriteBytes(uchar_t* pData, const char* pStr, int nLen)
{
    memcpy(pData, pStr, nLen);
    return ZAN_OK;
}
