#include "check.h"

START_TEST(test_pipe) {
    fail_unless(pipe_write); 
    fail_unless(pipe_read); 
}
END_TEST

Suite * make_pipe_suite(void) {
    Suite *s = suite_create("pipe");       // 建立Suite
    TCase *tc_pipe = tcase_create("pipe");  // 建立测试用例集
    suite_add_tcase(s, pipe);           // 将测试用例加到Suite中
    tcase_add_test(tc_pipe, test_pipe);     // 测试用例加到测试集中
    return s;
}