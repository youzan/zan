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

#include "swLog.h"
#include "swMemory/memoryPool.h"
#include "swProtocol/nova.h"
#include "php7_wrapper.h"

swNova_Header* createNovaHeader()
{
    swNova_Header* tmp =  sw_malloc(sizeof(swNova_Header));
    if (tmp == NULL) {
        return NULL;
    }
    memset(tmp, 0, sizeof(swNova_Header));
    return tmp;
}

void deleteNovaHeader(swNova_Header* header)
{
    if (header != NULL) {
        if(header->service_name != NULL)
        {
            sw_free(header->service_name);
        }
        if(header->method_name != NULL)
        {
            sw_free(header->method_name);
        }
        if (header->attach != NULL) {
            sw_free(header->attach);
        }
        sw_free(header);
    }
}

int swNova_IsNovaPack(const char* data, int nLen)
{
    if (nLen < NOVA_HEADER_COMMON_LEN || !data) {
        return SW_ERR;
    }
    //magic offset
    int off = 4;
    uint16_t magic = 0;
    if(swReadU16((const uchar *)(data + off), &magic) != SW_OK)
    {
        return SW_ERR;
    }
    if(magic != NOVA_MAGIC)
    {
        return SW_ERR;
    }
    
    return SW_OK;
}

int swNova_unpack(char* data, int length, swNova_Header* header)
{
    if (length <= NOVA_HEADER_COMMON_LEN) {
        swWarn("length is less than nova header common length. length=%d", length);
        return SW_ERR;
    }
    int off = 0;
    //read msg length
    if(swReadI32((const uchar *)data + off, &(header->msg_size)) != SW_OK)
    {
        swWarn("read msg length error.");
        return SW_ERR;
    }
    off += 4;
    
    //判断msg_size是否异常
    if(header->msg_size <= NOVA_HEADER_COMMON_LEN) {
        swWarn("msg size is less than nova header common length. msg_size=%d", header->msg_size);
        return SW_ERR;
    }
    
    //read magic
    
    if(swReadU16((const uchar *)data + off, &(header->magic)) != SW_OK)
    {
        swWarn("read magic error");
        return SW_ERR;
    }
    
    off += 2;
    //判断magic是否合法
    if(header->magic != NOVA_MAGIC)
    {
        swWarn("magic error. magic=%x", header->magic);
        return SW_ERR;
    }
    
    //read header size
    if(swReadI16((const uchar *)data + off, &(header->head_size)) != SW_OK)
    {
        swWarn("read header size error");
        return SW_ERR;
    }
    off += 2;
    
    //判断header size是否合法
    if (header->head_size > header->msg_size) {
        swWarn("header size is inval invalid. msg_size=%d, header_size=%d", header->msg_size, header->msg_size);
        return SW_ERR;
    }
    
    //read version
    if(swReadByte((const uchar *)data + off, (char *)&(header->version)) != SW_OK)
    {
        swWarn("read version error");
        return SW_ERR;
    }
    off += 1;
    //read ip
    if(swReadU32((const uchar *)data + off, &(header->ip)) != SW_OK)
    {
        swWarn("read ip error");
        return SW_ERR;
    }
    off += 4;
    //read port
    if(swReadU32((const uchar *)data + off, &(header->port)) != SW_OK)
    {
        swWarn("read port error");
        return SW_ERR;
    }

    off += 4;
    //read service name
    if(swReadString((const uchar *)data + off, length - off, &(header->service_name), &(header->service_len)) != SW_OK)
    {
        swWarn("read service name error");
        return SW_ERR;
    }
    off += 4;
    off += header->service_len;
    CHECK_PACK
    
    //read method name
    if(swReadString((const uchar *)data + off, length - off, &(header->method_name), &(header->method_len)) != SW_OK)
    {
        swWarn("read method name error");
        return SW_ERR;
    }
    off += 4;
    off += header->method_len;
    CHECK_PACK
    
    //read seq no
    if(swReadI64((const uchar *)data + off, &(header->seq_no)) != 0)
    {
        swWarn("read seq no error");
        return SW_ERR;
    }
    off += 8;
    CHECK_PACK
    
    //read attach
    if(swReadString((const uchar *)data + off, length - off, &(header->attach), &(header->attach_len)) != SW_OK)
    {
        swWarn("read attachment error");
        return SW_ERR;
    }
    off += 4;
    off += header->attach_len;
    CHECK_PACK
    
    return SW_OK;
}

int swNova_pack(swNova_Header* header, char* body, int body_len, char **data, int32_t* length)
{
    int header_size = header->head_size;
    int msg_size = header_size + body_len;
    if(*data != NULL)
    {
        sw_free(*data);
    }
    char *pTmp = sw_malloc(msg_size);
    if (!pTmp) {
        return SW_ERR;
    }

    int off = 0;
    //write msg_size
    if(swWriteI32((uchar *)pTmp+off, msg_size) != SW_OK)
    {
        swWarn("write msg size error");
        return SW_ERR;
    }

    off += 4;
    //write magic
    if(swWriteI16((uchar *)pTmp+off, header->magic) != SW_OK)
    {
        swWarn("write magic error");
        return SW_ERR;
    }

    off += 2;
    //write header size
    if(swWriteI16((uchar *)pTmp+off, header->head_size) != SW_OK)
    {
        swWarn("write header size error");
        return SW_ERR;
    }

    off += 2;
    //write version
    if(swWriteByte((uchar *)pTmp+off, header->version) != SW_OK)
    {
        swWarn("write version error");
        return SW_ERR;
    }

    off += 1;
    //write ip
    if(swWriteU32((uchar *)pTmp+off, header->ip) != SW_OK)
    {
        swWarn("write ip error");
        return SW_ERR;
    }

    off += 4;
    //write port
    if(swWriteU32((uchar *)pTmp+off, header->port) != SW_OK)
    {
        swWarn("write port error");
        return SW_ERR;
    }

    off += 4;
    //write service name
    if(swWriteString((uchar *)pTmp+off, header->service_name, header->service_len) != SW_OK)
    {
        swWarn("write service name error");
        return SW_ERR;
    }

    off += 4;
    off += header->service_len;
    //write method name
    if(swWriteString((uchar *)pTmp+off, header->method_name, header->method_len) != SW_OK)
    {
        swWarn("write method name error");
        return SW_ERR;
    }

    off += 4;
    off += header->method_len;
    //write seq no
    if(swWriteI64((uchar *)pTmp+off, header->seq_no) != SW_OK)
    {
        swWarn("write seq no error");
        return SW_ERR;
    }

    off += 8;
    //write attachement
    if(swWriteString((uchar *)pTmp+off, header->attach, header->attach_len) != SW_OK)
    {
        swWarn("write attachement error");
        return SW_ERR;
    }

    off += 4;
    off += header->attach_len;
    //write body
    if(swWriteBytes((uchar *)pTmp+off, (char*)body, body_len) != SW_OK)
    {
        swWarn("write body error");
        return SW_ERR;
    }

    *length = msg_size;
    *data = pTmp;
    return SW_OK;
}
