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
#include "swSendfile.h"

#include "zanLog.h"

#ifdef HAVE_KQUEUE

#include <sys/uio.h>

int swoole_sendfile(int out_fd, int in_fd, off_t *offset, size_t size)
{
    off_t sent_bytes = 0;
    int ret = -1;

#ifdef __MACH__
    struct sf_hdtr hdtr;
    hdtr.headers = NULL;
    hdtr.hdr_cnt = 0;
    hdtr.trailers = NULL;
    hdtr.trl_cnt = 0;
#endif

//    swTrace("send file, out_fd:%d, in_fd:%d, offset:%d, size:%d", out_fd, in_fd, *offset, size);
    while(ret < 0)
	{
#ifdef __MACH__
		ret = sendfile(in_fd, out_fd, *offset, (off_t*)&size, &hdtr, 0);
#else
		ret = sendfile(in_fd, out_fd, *offset, size, 0, &sent_bytes, 0);
#endif
		if (ret < 0)
		{
			if (errno == EAGAIN)
			{
				*offset += sent_bytes;
				return sent_bytes;
			}
			else if (errno == EINTR)
			{
				ret = -1;
			}
			else
			{
				return ZAN_ERR;
			}
		}
		else if (ret == 0)
		{
			*offset += size;
			return size;
		}
		else
		{
			zanError("sendfile failed.");
			return ZAN_ERR;
		}
	}

    return ZAN_OK;
}

#elif !defined(HAVE_SENDFILE)
int swoole_sendfile(int out_fd, int in_fd, off_t *offset, size_t size)
{
    //char buf[SW_BUFFER_SIZE_BIG] = {0};
    int readn = size > sizeof(buf) ? sizeof(buf) : size;

    char *buf = (char *)emalloc(SW_BUFFER_SIZE_BIG);
    memset(buf, 0, SW_BUFFER_SIZE_BIG);

    int ret = -1;
    int n = pread(in_fd, buf, readn, *offset);
    if (n > 0)
    {
        ret = write(out_fd, buf, n);
        if (ret < 0)
        {
            zanError("write() failed.");
        }
        else
        {
            *offset += ret;
        }

        swoole_efree(buf);
        return ret;
    }
    else
    {
        zanError("pread() failed.");
        swoole_efree(buf);
        return SW_ERR;
    }
}
#endif


int swoole_sync_readfile(int fd, void *buf, int len)
{
    int n = 0;
    int count = len, toread = 0, readn = 0;

    while (count > 0)
    {
        toread = count;
        if (toread > SW_FILE_CHUNK_SIZE)
        {
            toread = SW_FILE_CHUNK_SIZE;
        }
        n = read(fd, buf, toread);
        if (n > 0)
        {
            buf += n;
            count -= n;
            readn += n;
        }
        else if (n == 0)
        {
            break;
        }
        else
        {
            zanError("read() failed.");
            break;
        }
    }
    return readn;
}

int swoole_sync_writefile(int fd, void *data, int len)
{
    int n = 0;
    int count = len, towrite = 0, written = 0;

    while (count > 0)
    {
        towrite = (count > SW_FILE_CHUNK_SIZE)? SW_FILE_CHUNK_SIZE: count;
        n = write(fd, data, towrite);
        if (n > 0)
        {
            data += n;
            count -= n;
            written += n;
        }
        else
        {
            zanError("write() failed.");
            break;
        }
    }
    return written;
}
