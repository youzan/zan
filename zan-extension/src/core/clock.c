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

#if defined(HAVE_CLOCK_GETTIME)
#include <time.h>
#endif

#include "swClock.h"
#include "swLog.h"


#if defined(HAVE_CLOCK_GETTIME) && defined(CLOCK_MONOTONIC)

static int monotonic_works;

int swClock_init()
{
	struct timespec ts;

	monotonic_works = 0;

	if (0 == clock_gettime(CLOCK_MONOTONIC, &ts)) {
		monotonic_works = 1;
	}

	return 0;
}

int swClock_get(struct timeval *tv)
{
	if (monotonic_works) {
		struct timespec ts;

		if (0 > clock_gettime(CLOCK_MONOTONIC, &ts)) {
			swError("clock_gettime() failed");
			return -1;
		}

		tv->tv_sec = ts.tv_sec;
		tv->tv_usec = ts.tv_nsec / 1000;
		return 0;
	}

	return gettimeofday(tv, 0);
}

/* macosx clock */
#elif defined(HAVE_CLOCK_GET_TIME)

#include <mach/mach.h>
#include <mach/clock.h>
#include <mach/mach_error.h>

static clock_serv_t mach_clock;

/* this code borrowed from here: http://lists.apple.com/archives/Darwin-development/2002/Mar/msg00746.html */
/* mach_clock also should be re-initialized in child process after fork */
int swClock_init()
{
	kern_return_t ret;
	mach_timespec_t aTime;

	ret = host_get_clock_service(mach_host_self(), REALTIME_CLOCK, &mach_clock);

	if (ret != KERN_SUCCESS) {
		swError("host_get_clock_service() failed: %s", mach_error_string(ret));
		return -1;
	}

	/* test if it works */
	ret = clock_get_time(mach_clock, &aTime);

	if (ret != KERN_SUCCESS) {
		swError("clock_get_time() failed: %s", mach_error_string(ret));
		return -1;
	}

	return 0;
}

int swClock_get(struct timeval *tv)
{
	kern_return_t ret;
	mach_timespec_t aTime;

	ret = clock_get_time(mach_clock, &aTime);

	if (ret != KERN_SUCCESS) {
		swError("clock_get_time() failed: %s", mach_error_string(ret));
		return -1;
	}

	tv->tv_sec = aTime.tv_sec;
	tv->tv_usec = aTime.tv_nsec / 1000;

	return 0;
}

#else /* no clock */

int swClock_init()
{
	return 0;
}

int swClock_get(struct timeval *tv)
{
	return gettimeofday(tv, 0);
}

#endif
