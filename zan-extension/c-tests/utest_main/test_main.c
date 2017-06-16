#include "uni_test.h"
#include <stdlib.h>

int main(void) {
    int number_failed;
    SRunner *sr;
    sr = srunner_create(make_mem_suite()); 
    sr = srunner_create(make_server_suite());
    sr = srunner_create(make_client_suite());
    sr = srunner_create(make_http_suite());
    sr = srunner_create(make_aio_suite());
    sr = srunner_create(make_ds_suite());
    sr = srunner_create(make_heap_suite());
    sr = srunner_create(make_pool_suite());
    sr = srunner_create(make_ringbuffer_suite());
    sr = srunner_create(make_pipe_suite());
    srunner_set_fork_status(sr, CK_NOFORK);
    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);     
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}