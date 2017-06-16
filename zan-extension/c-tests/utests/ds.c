#include <string.h>
#include "swoole.h"
#include "Server.h"
#include "rbtree.h"
#include <netinet/tcp.h>
#include "tests.h"


typedef struct
{
	int fd;
	int key;
} swFdInfo;

bool type_eof()
{
	char eof[] = SW_DATA_EOF;
	printf("SW_DATA_STREAM_EOF = %s\n", eof);
	return 0;
}

bool hashmap1()
{
	swHashMap *hm = swHashMap_new(16, NULL);

	printf("---insert to hashmap---\n");
	swHashMap_add(hm, SW_STRL("hello")-1, (void *)199, NULL);
	swHashMap_add(hm, SW_STRL("swoole22")-1, (void *)8877, NULL);
	swHashMap_add(hm, SW_STRL("hello2")-1, (void *)200, NULL);
	swHashMap_add(hm, SW_STRL("willdel")-1, (void *)888, NULL);
	swHashMap_add(hm, SW_STRL("willupadte")-1, (void *)9999, NULL);
	swHashMap_add(hm, SW_STRL("hello3")-1, (void *)78978, NULL);

	printf("---delete node key=willdel---\n");
	swHashMap_del(hm, SW_STRL("willdel")-1);

	printf("---update node key=willupadte---\n");
	swHashMap_update(hm, SW_STRL("willupadte")-1, (void *) (9999*5555));

	printf("---find node---\n");
	int ret = (int) swHashMap_find(hm, SW_STRL("hello")-1);
	printf("ret=%d\n", ret);

	int ret2 = (int) swHashMap_find(hm, SW_STRL("hello2")-1);
	printf("ret2=%d\n", ret2);

	printf("---foreach hashmap---\n");
	char *key;
	int data;

	while(1)
	{
	    data = (int) swHashMap_each(hm, &key);
	    if (!data) break;
		printf("key=%s|value=%d\n", key, data);
	}
	swHashMap_free(hm);
	return 0;
}

#define BUFSIZE 128
char data[BUFSIZE];

bool hashmap2()
{
	swHashMap *ht = swHashMap_new(16, free);
	swFdInfo *pkt, *tmp;
	int i;

	for (i = 0; i < 10; i++)
	{
		pkt = (swFdInfo *) malloc(sizeof(swFdInfo));
		pkt->key = i;
		pkt->fd = i * 34;
		swHashMap_add_int(ht, i, pkt, NULL);
	}

	tmp = swHashMap_find_int(ht, 7);
	if (tmp != NULL)
	{
		printf("The key(%d) exists in hash. Fd = %d\n", i, tmp->fd);
	}
	return 0;
}

bool rbtree()
{
	swRbtree *tree = swRbtree_new();
	uint32_t key;
	int i;
	for (i = 1; i < 20000; i++)
	{
		key = i * 3;
		swRbtree_insert(tree, key, (void *) (i * 8));
	}
	printf("find_n %d\n", (int) swRbtree_find(tree, 17532));
	return 0;
}

static void err_exit(const char *msg)
{
	printf("%s:%s\n", msg, strerror(errno));
	exit(-1);
}

bool chan()
{
	if (object->argc != 3)
	{
		printf("usage: ipc_benchmark rw_num worker_num\n");
		return 0;
	}
	pid_t pid;
	int num = atoi(object->argv[1]);
	int worker_num = atoi(object->argv[2]);
	int ret;

	char item[BUFSIZE];
	swChannel *chan = swChannel_new(1024 * 80, 1000, SW_CHAN_NOTIFY | SW_CHAN_LOCK | SW_CHAN_SHM);
	if (chan == NULL)
	{
		err_exit("msgget");
	}

	int i;
	for (i = 0; i < worker_num; i++)
	{
		if ((pid = fork()) < 0)
		{
			err_exit("fork");
		}
		else if (pid > 0)
		{
			continue;
		}
		else
		{
			int recvn = 0;
			while (1)
			{
				swChannel_wait(chan);
				ret = swChannel_pop(chan, item, BUFSIZE);
				if (ret < 0)
					continue;
				recvn++;
				printf("Worke[%d] recv[%d]=%s\n", i, recvn, item);
			}
			printf("Worker[%d] Finish: recv=%d\n", i, recvn);
			exit(0);
		}
	}

	main_loop: sleep(1);
	int sendn = 0;
	while (num >= 0)
	{
		sprintf(item, "%d--||||||||||||nnnnnnnnnnn", sendn);
		swChannel_push(chan, item, BUFSIZE);
		swChannel_notify(chan);
		sendn++;
		printf("Master send[%d]\n", sendn);
		num--;
	}
	if (ret < 0)
	{
		err_exit("parent msgsnd");
	}
	printf("Send finish|num=%d|sendn=%d\n", num, sendn);
	int status;
	for (i = 0; i < worker_num; i++)
	{
		wait(&status);
	}
	return 0;
}

//list test
typedef struct _test_node
{
    struct _test_node *next, *prev;
    void *data;
    int exectime;
} test_node;

static struct
{
    test_node *root;
} timer;

void list_add(int exectime);
void list_dump();

bool list()
{
    int i = 0;
    for (i = 0; i < 10000; i++)
    {
        list_add(swoole_system_random(10000, 99999));
    }
    list_dump();
}

void list_dump()
{
    test_node *tmp = timer.root;
    printf("root=%d\n", tmp->exectime);

    while (tmp->next)
    {
        tmp = tmp->next;
        printf("node=%d\n", tmp->exectime);

    }
}

void list_add(int exectime)
{

    test_node *node = malloc(sizeof(test_node));
    bzero(node, sizeof(test_node));
    node->data = NULL;
    node->exectime = exectime;

    if (timer.root == NULL)
    {
        timer.root = node;
        return;
    }

    test_node *tmp = timer.root;
    while (1)
    {
        if (tmp->exectime >= node->exectime)
        {
            node->prev = tmp->prev;
            node->next = tmp;
            if (node->prev)
            {
                node->prev->next = node;
            }

            tmp->prev = node;

            if (tmp == timer.root)
            {
                timer.root = node;
            }
            break;
        }
        else if (tmp->next)
        {
            tmp = tmp->next;
        }
        else
        {
            tmp->next = node;
            node->prev = tmp;
            break;
        }
    }
}

