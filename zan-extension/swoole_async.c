/*
  +----------------------------------------------------------------------+
  | Zan                                                                  |
  +----------------------------------------------------------------------+
  | Copyright (c) 2016-2017 Zan Group <https://github.com/youzan/zan>    |
  | Copyright (c) 2012-2016 Swoole Team <http://github.com/swoole>       |
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
#include "php_streams.h"
#include "php_network.h"
#include "swBaseData.h"
#include "swBaseOperator.h"
#include "swDNS.h"

#include "ext/standard/file.h"

typedef struct
{
#if PHP_MAJOR_VERSION >= 7
    zval _callback;
    zval _filename;
#endif
    zval *callback;
    zval *filename;
    int fd;
    off_t offset;
    uint16_t type;
    uint8_t once;
    char *content;
    uint32_t length;
} file_request;

typedef struct
{
#if PHP_MAJOR_VERSION >= 7
    zval _callback;
    zval _domain;
#endif
    zval *callback;
    zval *domain;
} dns_request;

static swHashMap *php_swoole_open_files;
static swHashMap *php_swoole_aio_request;

static void php_swoole_check_aio();
static void php_swoole_aio_onComplete(swAio_event *event);
static void php_swoole_file_request_free(void *data);

static int swoole_gethost_from_cache(zval* domain,zval* callback TSRMLS_DC);
static void swoole_aio_dns_complete(swAio_event *event TSRMLS_DC);
static void swoole_aio_file_complete(swAio_event *event TSRMLS_DC);

static sw_inline void swoole_aio_free(void *ptr)
{
	swoole_efree(ptr);
}

static sw_inline void* swoole_aio_malloc(size_t __size)
{
    return emalloc(__size);
}

static int swoole_gethost_from_cache(zval* domain,zval* callback TSRMLS_DC)
{
	if (SwooleG.disable_dns_cache)
	{
		return SW_ERR;
	}

	int flags = AF_INET | SW_DNS_LOOKUP_CACHE_ONLY;
	flags |= (SwooleG.dns_lookup_random)? SW_DNS_LOOKUP_RANDOM:0;
	char ipaddr[SW_IP_MAX_LENGTH] = {0};
	if (swoole_gethostbyname(flags, Z_STRVAL_P(domain),ipaddr,SW_IP_MAX_LENGTH) < 0)
	{
		return SW_ERR;
	}

	zval *zcontent = NULL;
	SW_MAKE_STD_ZVAL(zcontent);
	SW_ZVAL_STRING(zcontent,ipaddr, 1);

	zval *zdomain = NULL;
	SW_MAKE_STD_ZVAL(zdomain);
	SW_ZVAL_STRINGL(zdomain, Z_STRVAL_P(domain), Z_STRLEN_P(domain), 1);

	zval **args[2];
	args[0] = &zdomain;
	args[1] = &zcontent;

	zval *retval = NULL;
	if (sw_call_user_function_ex(EG(function_table), NULL, callback, &retval, 2, args, 0, NULL TSRMLS_CC) == FAILURE)
	{
		swWarn("swoole_async: onAsyncComplete handler error");
	}

	if (EG(exception))
	{
		zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
	}

	if (retval)
	{
		sw_zval_ptr_dtor(&retval);
	}

	sw_zval_ptr_dtor(&zdomain);
	sw_zval_ptr_dtor(&zcontent);
	return SW_OK;
}

static void php_swoole_check_aio()
{
    if (!SwooleAIO.init)
    {
        php_swoole_check_reactor();
        swAio_init();
        SwooleAIO.callback = php_swoole_aio_onComplete;
    }
}

static void php_swoole_file_request_free(void *data)
{
    file_request *file_req = data;
    if (file_req->callback)
    {
        sw_zval_ptr_dtor(&file_req->callback);
        file_req->callback = NULL;
    }

    swoole_aio_free(file_req->content);
    file_req->content = NULL;

    if (file_req->filename)
    {
        sw_zval_ptr_dtor(&file_req->filename);
    	file_req->filename = NULL;
    }

    swoole_efree(file_req);
}

static void php_swoole_aio_onComplete(swAio_event *event)
{
    SWOOLE_FETCH_TSRMLS;

    if (event->type == SW_AIO_DNS_LOOKUP)
    {
    	swoole_aio_dns_complete(event TSRMLS_CC);
    }
    else if (event->type == SW_AIO_READ || event->type == SW_AIO_WRITE)
    {
    	swoole_aio_file_complete(event TSRMLS_CC);
    }
    else
	{
		swWarn("swoole_async: onAsyncComplete unknown event type[%d].", event->type);
		return;
	}
}

static void swoole_aio_dns_complete(swAio_event *event TSRMLS_DC)
{
	dns_request *dns_req = (dns_request *) event->req;
	if (!dns_req || !dns_req->callback)
	{
		swWarn("swoole_async: dns complete callback not found[0]");
		return;
	}

	zval *zcallback =  dns_req->callback;

	int64_t ret = event->ret;
	if (ret < 0)
	{
		swWarn("swoole_async: file aio Error: %s[%d]", strerror(event->error), event->error);
	}

	zval*  zcontent = NULL;
	SW_MAKE_STD_ZVAL(zcontent);
	const char* content = (const char*)((ret < 0)? "":event->buf);
	SW_ZVAL_STRING(zcontent, content, 1);

	zval** args[2];
	args[0] = &dns_req->domain;
	args[1] = &zcontent;

	zval *retval = NULL;
	if (sw_call_user_function_ex(EG(function_table), NULL, zcallback, &retval,
															2, args, 0, NULL TSRMLS_CC) == FAILURE)
	{
		swWarn("swoole_async: file aio handler error");
	}

	if (EG(exception))
	{
		zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
	}

	if (dns_req->callback)
	{
	    sw_zval_ptr_dtor(&dns_req->callback);
		dns_req->callback = NULL;
	}

	if (dns_req->domain)
	{
	    sw_zval_ptr_dtor(&dns_req->domain);
		dns_req->domain = NULL;
	}

	swoole_efree(dns_req);
	event->req = NULL;
	swoole_efree(event->buf);

	if (zcontent)
	{
		sw_zval_ptr_dtor(&zcontent);
	}

	if (retval)
	{
		sw_zval_ptr_dtor(&retval);
	}
}

static void swoole_aio_file_complete(swAio_event *event TSRMLS_DC)
{
	file_request *file_req = swHashMap_find_int(php_swoole_aio_request, event->task_id);
	if (!file_req || (!file_req->callback && file_req->type == SW_AIO_READ))
	{
		swWarn("swoole_async: file complete callback not found");
		return;
	}

	int isEOF = SW_FALSE;
	int64_t ret = event->ret;
	if (ret < 0)
	{
		SwooleG.error = event->error;
		swoole_php_error(E_WARNING, "Aio Error: %s[%d]", strerror(event->error), event->error);
	}
	else if (0 == ret)
	{
		bzero(event->buf, event->nbytes);
		isEOF = SW_TRUE;
	}
	else if (event->type == SW_AIO_WRITE)
	{
		file_req->offset += ret;
		event->buf += ret;
		event->nbytes -= ret;
		file_req->length = (file_req->length <= ret)? 0:file_req->length - ret;
		isEOF = file_req->length > 0 ? 0: 1;
	}
	else if (file_req->once == 1 && ret < file_req->length)
	{
		swWarn("swoole_async: ret_length[%d] < req->length[%d].", (int ) ret, file_req->length);
	}
	else if (event->type == SW_AIO_READ)
	{
		file_req->offset += ret;
		file_req->length = (file_req->length <= ret)? 0:file_req->length - ret;
	}

	zval **args[2];
	zval *zcontent = NULL;
	SW_MAKE_STD_ZVAL(zcontent);
	if (event->type == SW_AIO_READ)
	{
		memset(event->buf + ret, 0, 1);
		SW_ZVAL_STRINGL(zcontent, event->buf, ret, 1);
	}
	else if (event->type == SW_AIO_WRITE)
	{
		ZVAL_LONG(zcontent, ret);
	}

	args[0] = &file_req->filename;
	args[1] = &zcontent;

	zval *zcallback = file_req->callback;
	zval *retval = NULL;
	if (zcallback && sw_call_user_function_ex(EG(function_table), NULL, zcallback, &retval,
															2, args, 0, NULL TSRMLS_CC) == FAILURE)
	{
		swWarn("swoole_async: file aio handler error");
		goto close_file;
	}

	if (file_req->once)
	{
close_file:
		close(event->fd);
		swHashMap_del_int(php_swoole_aio_request, event->task_id);
	}
	else if(file_req->type == SW_AIO_WRITE)
	{
		if ((retval && !ZVAL_IS_NULL(retval) && !Z_BVAL_P(retval)) || isEOF)
		{
			swHashMap_del(php_swoole_open_files, Z_STRVAL_P(file_req->filename), Z_STRLEN_P(file_req->filename));
			goto close_file;
		}
		else
		{
			event->nbytes = file_req->length;
			int taskId = SwooleAIO.write(event->fd, event->buf, event->nbytes, file_req->offset);
			if (taskId < 0)
			{
				swWarn("swoole_async: continue to read failed. Error: %s[%d]", strerror(event->error), event->error);
				goto close_file;
			}
			else
			{
				swHashMap_move_int(php_swoole_aio_request, event->task_id, taskId);
			}
		}
	}
	else
	{
		if ((retval && !ZVAL_IS_NULL(retval) && !Z_BVAL_P(retval)) || isEOF)
		{
			goto close_file;
		}

		//continue to read
		event->nbytes = event->nbytes < file_req->length? event->nbytes:file_req->length;
		int ret = SwooleAIO.read(event->fd, event->buf, event->nbytes, file_req->offset);
		if (ret < 0)
		{
			swWarn("swoole_async: continue to read failed. Error: %s[%d]", strerror(event->error), event->error);
			goto close_file;
		}
		else
		{
			swHashMap_move_int(php_swoole_aio_request, event->task_id, ret);
		}
	}

	if (EG(exception))
	{
		zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
	}

	if (zcontent)
	{
		sw_zval_ptr_dtor(&zcontent);
	}

	if (retval)
	{
		sw_zval_ptr_dtor(&retval);
	}
}

void swoole_aio_init(int module_number TSRMLS_DC)
{
    bzero(&SwooleAIO, sizeof(SwooleAIO));

    REGISTER_LONG_CONSTANT("SWOOLE_AIO_BASE", SW_AIO_BASE, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SWOOLE_AIO_LINUX", SW_AIO_LINUX, CONST_CS | CONST_PERSISTENT);

    dns_lookup_init();

    php_swoole_open_files = swHashMap_create(SW_HASHMAP_INIT_BUCKET_N,NULL);
    if (!php_swoole_open_files)
    {
        swoole_php_fatal_error(E_ERROR, "create hashmap[1] failed.");
    }

    php_swoole_aio_request = swHashMap_create(SW_HASHMAP_INIT_BUCKET_N, php_swoole_file_request_free);
    if (!php_swoole_aio_request)
    {
        swoole_php_fatal_error(E_ERROR, "create hashmap[2] failed.");
    }
}

PHP_FUNCTION(swoole_async_read)
{
	zval *callback = NULL;
	zval *filename = NULL;
	long buf_size = -1;
	long offset = 0;

	if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zz|ll", &filename, &callback, &buf_size, &offset))
	{
		return;
	}

	if (offset < 0)
	{
		swoole_php_fatal_error(E_WARNING, "offset must be greater than 0.");
		RETURN_FALSE;
	}

	if (swoole_check_callable(callback TSRMLS_CC) < 0)
	{
		swoole_php_fatal_error(E_WARNING,"user must set callback.");
		RETURN_FALSE;
	}

	convert_to_string(filename);
	int open_flag = O_RDONLY;
//	open_flag |= (SwooleAIO.mode == SW_AIO_LINUX)? O_DIRECT:0;
	int fd = open(Z_STRVAL_P(filename), open_flag, 0644);
	if (fd < 0)
	{
		swoole_php_sys_error(E_WARNING, "open(%s, O_RDONLY) failed.", Z_STRVAL_P(filename));
		RETURN_FALSE;
	}

	size_t filelen = get_filelen(fd);
	if (filelen <= 0 || offset >= filelen)
	{
		swoole_php_fatal_error(E_WARNING, "offset must be less than file_size[=%ld].", filelen);
create_error:
		close(fd);
		RETURN_FALSE;
	}

	/// 限制一次读取buf_size 的长度
	///[1] buf_size < 0 读取全部文件.
	buf_size = (buf_size < 0)? filelen:buf_size;
	///[2] buf_size + offset > filelen 则只读取filelen － offset的长度
	buf_size = (buf_size + offset > filelen)? filelen - offset:buf_size;
	int read_size = (buf_size > SW_FILE_MAX_LEN_ONCE)? SW_FILE_MAX_LEN_ONCE:buf_size;
	void *fcnt = swoole_aio_malloc(read_size + 1);
	if (!fcnt)
	{
		swoole_php_sys_error(E_WARNING, "malloc failed.");
		goto create_error;
	}

	file_request *req = emalloc(sizeof(file_request));
	req->fd = fd;
	req->content = fcnt;
	req->once = 0;
	req->type = SW_AIO_READ;
	req->length = buf_size;
	req->offset = offset;

	php_swoole_check_aio();

	int ret = SwooleAIO.read(fd, fcnt, read_size, offset);
	if (ret < 0)
	{
		RETURN_FALSE;
	}

	req->filename = filename;
	sw_zval_add_ref(&filename);
	sw_copy_to_stack(req->filename, req->_filename);

	if (callback && !ZVAL_IS_NULL(callback))
	{
		req->callback = callback;
		sw_zval_add_ref(&callback);
		sw_copy_to_stack(req->callback, req->_callback);
	}else
		req->callback = NULL;

	swHashMap_add_int(php_swoole_aio_request, ret, req);
	RETURN_TRUE;
}

PHP_FUNCTION(swoole_async_write)
{
	zval *callback = NULL;
	zval *filename = NULL;
	char *fcnt = NULL;
	zend_size_t fcnt_len = 0;
	off_t offset = -1;

	if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zs|lz", &filename, &fcnt, &fcnt_len, &offset, &callback))
	{
		return;
	}

	uint32_t maxBuflen = SwooleAIO.buf_max_len > 0? SwooleAIO.buf_max_len:SW_FILE_MAX_LEN_ONCE;
	if (fcnt_len <= 0 || fcnt_len > maxBuflen || !fcnt)
	{
		swWarn("user set data buffer must between 0~%d, and user buffer can not be null",maxBuflen);
		RETURN_FALSE;
	}

	if (callback && !ZVAL_IS_NULL(callback) && swoole_check_callable(callback TSRMLS_CC) < 0)
	{
		RETURN_FALSE;
	}

	convert_to_string(filename);

	long fd = -1;
	int open_flag = O_WRONLY | O_CREAT;
//	open_flag |= (SwooleAIO.mode == SW_AIO_LINUX)? O_DIRECT:0;
	open_flag |= (offset < 0)? O_APPEND:0;

	fd = open(Z_STRVAL_P(filename), open_flag, 0644);
	if (fd < 0)
	{
		swoole_php_fatal_error(E_WARNING, "open(%s, %d) failed. Error: %s[%d]", Z_STRVAL_P(filename), open_flag, strerror(errno), errno);
		RETURN_FALSE;
	}

	offset = (offset < 0)? 0:offset;

	file_request *req = emalloc(sizeof(file_request));
	char *wt_cnt = swoole_aio_malloc(fcnt_len + 1);
	req->fd = fd;
	req->content = wt_cnt;
	req->once = 0;
	req->type = SW_AIO_WRITE;
	req->length = fcnt_len;
	req->offset = offset;

	memcpy(wt_cnt, fcnt, fcnt_len);
	php_swoole_check_aio();

	int ret = SwooleAIO.write(fd, wt_cnt, fcnt_len, offset);
	if (ret < 0)
	{

		close(fd);
		swoole_aio_free(wt_cnt);
		swoole_efree(req);
		RETURN_FALSE;
	}

	req->filename = filename;
	sw_zval_add_ref(&filename);
	sw_copy_to_stack(req->filename, req->_filename);

	if (swoole_check_callable(callback TSRMLS_CC) >= 0)
	{
		req->callback = callback;
		sw_zval_add_ref(&callback);
		sw_copy_to_stack(req->callback, req->_callback);
	}
	else
		req->callback = NULL;

	swHashMap_add_int(php_swoole_aio_request, ret, req);
	RETURN_TRUE;
}

PHP_FUNCTION(swoole_async_set)
{
    zval *zset = NULL;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &zset))
    {
        return;
    }

    zval *value = NULL ;
    php_swoole_array_separate(zset);
    HashTable *vht = Z_ARRVAL_P(zset);
//    if (php_swoole_array_get_value(vht, "aio_mode", value))
//    {
//        convert_to_long(value);
//        SwooleAIO.mode = (uint8_t) Z_LVAL_P(value);
//    }

    value = NULL;
    if (php_swoole_array_get_value(vht, "thread_num", value))
    {
        convert_to_long(value);
        SwooleAIO.thread_num = (uint8_t) Z_LVAL_P(value);
    }

    value = NULL;
    if (php_swoole_array_get_value(vht, "enable_signalfd", value))
    {
        convert_to_boolean(value);
        SwooleG.use_signalfd = Z_BVAL_P(value);
    }

    value = NULL;
    if (php_swoole_array_get_value(vht, "socket_buffer_size", value))
    {
        convert_to_long(value);
        int valueSize = Z_LVAL_P(value);
        valueSize = (valueSize <= 0 || valueSize > SW_MAX_INT)? SW_MAX_INT:valueSize;
        SwooleG.socket_buffer_size = valueSize;
    }

    value = NULL;
    if (php_swoole_array_get_value(vht, "socket_dontwait", value))
    {
        convert_to_boolean(value);
        SwooleG.socket_dontwait = Z_BVAL_P(value);
    }

    value = NULL;
    if (php_swoole_array_get_value(vht,"aio_max_buffer",value))
    {
    	convert_to_long(value);
    	SwooleAIO.buf_max_len = Z_LVAL_P(value);
    }

    value = NULL;
    if (php_swoole_array_get_value(vht, "disable_dns_cache", value))
    {
        convert_to_boolean(value);
        SwooleG.disable_dns_cache = Z_BVAL_P(value);
    }

    value = NULL;
    if (php_swoole_array_get_value(vht, "dns_lookup_random", value))
    {
        convert_to_boolean(value);
        SwooleG.dns_lookup_random = Z_BVAL_P(value);
    }

#if defined(HAVE_REUSEPORT) && defined(HAVE_EPOLL)
    //reuse port
    value = NULL;
    if (php_swoole_array_get_value(vht, "enable_reuse_port", value))
    {
        convert_to_boolean(value);
        if (swoole_version_compare(SwooleG.uname.release, "3.9.0") >= 0)
        {
            SwooleG.reuse_port = Z_BVAL_P(value)? 1:SwooleG.reuse_port;
        }
    }
#endif
    sw_zval_ptr_dtor(&zset);
}

PHP_FUNCTION(swoole_async_dns_lookup)
{
	zval *domain = NULL;
    zval *callback = NULL;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zz", &domain, &callback))
    {
        return;
    }

    if (Z_TYPE_P(domain) != IS_STRING || !Z_STRLEN_P(domain))
    {
        swWarn("domain must be string type ,and not empty.");
        RETURN_FALSE;
    }

    if (swoole_check_callable(callback TSRMLS_CC) < 0)
    {
    	swWarn("async dns lookup callback error.");
    	RETURN_FALSE;
    }

    /// 从缓存中获取到，立即返回
    if (swoole_gethost_from_cache(domain,callback TSRMLS_CC) == SW_OK)
    {
        return ;
    }

    dns_request *req = emalloc(sizeof(dns_request));
    req->callback = callback;
    sw_copy_to_stack(req->callback, req->_callback);
    sw_zval_add_ref(&req->callback);

    req->domain = domain;
    sw_copy_to_stack(req->domain, req->_domain);
    sw_zval_add_ref(&req->domain);

    int buf_size = (Z_STRLEN_P(domain) < SW_IP_MAX_LENGTH)? SW_IP_MAX_LENGTH + 1:Z_STRLEN_P(domain) + 1;

    int flag = SwooleG.disable_dns_cache? (AF_INET|SW_DNS_LOOKUP_NOCACHE):AF_INET;
#ifdef SW_DNS_LOOKUP_USE_THREAD
    void *buf = emalloc(buf_size);
    bzero(buf, buf_size);
    memcpy(buf, Z_STRVAL_P(domain), Z_STRLEN_P(domain));
    php_swoole_check_aio();
    SW_CHECK_RETURN(swAio_dns_lookup(flag,req, buf, buf_size));
#else
    swDNS_request *request = emalloc(sizeof(swDNS_request));
    request->callback = php_swoole_aio_onDNSResponse;
    request->object = req;
    request->domain = Z_STRVAL_P(domain);

    php_swoole_check_reactor();
    swDNSResolver_request(request);
    php_swoole_try_run_reactor();
#endif
}

PHP_FUNCTION(swoole_clean_dns_cache)
{
    swoole_clear_dns_cache();
}

