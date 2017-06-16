#include "tests.h"
#include "swoole.h"
#include "async.h"

#define BUF_SIZE (1024 * 1024)

bool aio_read()
{
	swReactor reactor;
	char *test_file = "aio_test_file";
	int fd = open(test_file, O_RDONLY);
	if (fd < 0)
	{
		perror("open");
		return 3;
	}
	char *buf;
	if (swReactorEpoll_create(&reactor, 128) < 0)
	{
		return 1;
	}
    bzero(&SwooleAIO, sizeof(SwooleAIO));
    SwooleG.main_reactor = &reactor;
	swAio_init();

	char *outbuf = malloc(BUF_SIZE);

	SwooleAIO.read(fd, outbuf, BUF_SIZE, 0);
	reactor.wait(&reactor, NULL);
	close(fd);

	return 0;
}

bool aio_write()
{
	swReactor reactor;
	char *test_file = "aio_test_file";
	int fd = open(test_file, O_RDWR | O_CREAT | O_DIRECT, 0644);
	if (fd < 0)
	{
		perror("open");
		return 3;
	}
	char *buf;
	if (posix_memalign((void **)&buf, getpagesize(), BUF_SIZE))
	{
		perror("posix_memalign");
		return 5;
	}

	if (swReactorEpoll_create(&reactor, 128) < 0)
	{
		return 1;
	}
	bzero(&SwooleAIO, sizeof(SwooleAIO));
	SwooleG.main_reactor = &reactor;
	swAio_init();

	memset(buf, 'A', BUF_SIZE - 1);
	buf[BUF_SIZE - 1] = 0;

	SwooleAIO.write(fd, buf, BUF_SIZE, 0);
	reactor.wait(&reactor, NULL);
	SwooleAIO.destroy();
	close(fd);

	return 0;
}
