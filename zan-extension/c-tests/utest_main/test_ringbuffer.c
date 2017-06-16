#include "check.h"

START_TEST(test_ringbuffer) {
    fail_unless(ringbuffer);  
}
END_TEST

Suite * make_ringbuffer_suite(void) {
    Suite *s = suite_create("ringbuffer");       // 建立Suite
    TCase *tc_ringbuffer = tcase_create("ringbuffer");  // 建立测试用例集
    suite_add_tcase(s, ringbuffer);           // 将测试用例加到Suite中
    tcase_add_test(tc_ringbuffer, test_ringbuffer);     // 测试用例加到测试集中
    return s;
}