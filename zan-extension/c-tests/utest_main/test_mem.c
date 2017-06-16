#include "check.h"
//#include "uni_test.h"
//#include "mem.h"
START_TEST(test_mem) {
    fail_unless(mem_alloc); 
    fail_unless(mem_FixedPool);
    fail_unless(mem_MemoryGlobal);
    fail_unless(mem_RingBuffer);
}
END_TEST

Suite * make_mem_suite(void) {
    Suite *s = suite_create("mem");       // 建立Suite
    TCase *tc_mem = tcase_create("mem");  // 建立测试用例集
    suite_add_tcase(s, tc_mem);           // 将测试用例加到Suite中
    tcase_add_test(tc_mem, test_mem);     // 测试用例加到测试集中
    return s;
}