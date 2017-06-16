#include "check.h"

START_TEST(test_http) {
    fail_unless(http_get); 
    fail_unless(http_post); 
}
END_TEST

Suite * make_http_suite(void) {
    Suite *s = suite_create("http");       // 建立Suite
    TCase *tc_http = tcase_create("http");  // 建立测试用例集
    suite_add_tcase(s, tc_http);           // 将测试用例加到Suite中
    tcase_add_test(tc_http, test_http);     // 测试用例加到测试集中
    return s;
}