#ifndef _UNI_TEST_H
#define _UNI_TEST_H
#include "check.h"
Suite *make_mem_suite(void);
Suite *make_server_suite(void);
Suite *make_client_suite(void);
Suite *make_http_suite(void);
Suite *make_aio_suite(void);
Suite *make_ds_suite(void);
Suite *make_heap_suite(void);
Suite *make_pool_suite(void);
Suite *make_ringbuffer_suite(void);
Suite *make_pipe_suite(void);
#endif