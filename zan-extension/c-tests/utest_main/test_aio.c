#include "check.h"

START_TEST(test_aio) {
    fail_unless(aio_read); 
    fail_unless(aio_write); 
}
END_TEST

Suite * make_aio_suite(void) {
    Suite *s = suite_create("aio");       // 建立Suite
    TCase *tc_aio = tcase_create("aio");  // 建立测试用例集
    suite_add_tcase(s, aio);           // 将测试用例加到Suite中
    tcase_add_test(tc_aio, test_aio);     // 测试用例加到测试集中
    return s;
}