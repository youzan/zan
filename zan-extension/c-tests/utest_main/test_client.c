#include "check.h"

START_TEST(test_client) {
    fail_unless(client); 
}
END_TEST

Suite * make_client_suite(void) {
    Suite *s = suite_create("client");       // 建立Suite
    TCase *tc_client = tcase_create("client");  // 建立测试用例集
    suite_add_tcase(s, tc_client);           // 将测试用例加到Suite中
    tcase_add_test(tc_client, test_client);     // 测试用例加到测试集中
    return s;
}