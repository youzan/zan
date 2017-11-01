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


#include "swError.h"
#include "zanLog.h"
#include "swBaseData.h"

#define swArray_page(array, n)      ((!array->page_size)? array->page_num: (n) / (array)->page_size)
#define swArray_offset(array, n)    ((!array->page_size)? array->page_num: (n) % (array)->page_size)

/**
 * 创建新数组
 */
swArray *swArray_create(int page_size, size_t item_size)
{
    swArray *array = sw_malloc(sizeof(swArray));
    if (array == NULL)
    {
        zanFatalError("malloc[0] failed.");
        return NULL;
    }

    bzero(array, sizeof(swArray));
    array->pages = sw_malloc(sizeof(void*) * SW_ARRAY_PAGE_MAX);
    if (array->pages == NULL)
    {
        sw_free(array);
        zanFatalError("malloc[1] failed.");
        return NULL;
    }

    array->item_size = item_size;
    array->page_size = page_size;

    swArray_extend(array);

    return array;
}

/**
 * 销毁数组
 */
void swArray_free(swArray *array)
{
    int index;
    for (index = 0; index < array->page_num; index++)
    {
        sw_free(array->pages[index]);
    }

    sw_free(array->pages);
    sw_free(array);
}

/**
 * 扩展内存页面
 */
int swArray_extend(swArray *array)
{
    if (!array || array->page_num == SW_ARRAY_PAGE_MAX)
    {
        zanWarn("max page_num is %d", array->page_num);
        return SW_ERR;
    }
    array->pages[array->page_num] = sw_calloc(array->page_size, array->item_size);
    if (array->pages[array->page_num] == NULL)
    {
        zanFatalError("malloc[1] failed.");
        return SW_ERR;
    }

    array->page_num++;
    return SW_OK;
}

/**
 * 获取某一个index的数据内容
 */
void *swArray_fetch(swArray *array, uint32_t n)
{
    if (!array){
        return NULL;
    }

    int page = swArray_page(array, n);

    return (page >= array->page_num)? NULL:
            array->pages[page] + (swArray_offset(array, n) * array->item_size);
}

/**
 * 追加到数组末尾
 */
int swArray_append(swArray *array, void *data)
{
    if (!array){
        return SW_ERR;
    }

    int n = array->offset++;
    int page = swArray_page(array, n);

    if (page >= array->page_num && swArray_extend(array) < 0)
    {
        return SW_ERR;
    }

    array->item_num++;
    memcpy(array->pages[page] + (swArray_offset(array, n) * array->item_size), data, array->item_size);
    return n;
}


int swArray_store(swArray *array, uint32_t n, void *data)
{
    if (!array){
        return SW_ERR;
    }

    int page = swArray_page(array, n);
    if (page >= array->page_num)
    {
        zanWarn("fetch index[%d] out of array", n);
        return SW_ERR;
    }

    memcpy(array->pages[page] + (swArray_offset(array, n) * array->item_size), data, array->item_size);
    return SW_OK;
}

void *swArray_alloc(swArray *array, uint32_t n)
{
    if (!array){
        return NULL;
    }

    while (n >= array->page_num * array->page_size)
    {
        if (swArray_extend(array) < 0)
        {
            return NULL;
        }
    }

    int page = swArray_page(array, n);
    if (page >= array->page_num)
    {
        zanWarn("fetch index[%d] out of array", n);
        return NULL;
    }
    return array->pages[page] + (swArray_offset(array, n) * array->item_size);
}

void swArray_clear(swArray *array)
{
    array->offset = 0;
    array->item_num = 0;
}
