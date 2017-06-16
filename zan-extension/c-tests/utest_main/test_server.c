#include "check.h"

START_TEST(test_server) {
    fail_unless(server); 
}
END_TEST

Suite * make_server_suite(void) {
    Suite *s = suite_create("server");       // 建立Suite
    TCase *tc_server = tcase_create("server");  // 建立测试用例集
    suite_add_tcase(s, tc_server);           // 将测试用例加到Suite中
    tcase_add_test(tc_server, test_server);     // 测试用例加到测试集中
    return s;
}