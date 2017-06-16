#include "check.h"

START_TEST(test_pool) {
    fail_unless(pool_thread); 
}
END_TEST

Suite * make_pool_suite(void) {
    Suite *s = suite_create("pool");       // 建立Suite
    TCase *tc_pool = tcase_create("pool");  // 建立测试用例集
    suite_add_tcase(s, tc_pool);           // 将测试用例加到Suite中
    tcase_add_test(tc_pool, test_pool);     // 测试用例加到测试集中
    return s;
}