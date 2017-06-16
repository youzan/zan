#include "check.h"

START_TEST(test_heap) {
    fail_unless(heap); 
}
END_TEST

Suite * make_heap_suite(void) {
    Suite *s = suite_create("heap");       // 建立Suite
    TCase *tc_heap = tcase_create("heap");  // 建立测试用例集
    suite_add_tcase(s, heap);           // 将测试用例加到Suite中
    tcase_add_test(tc_heap, test_heap);     // 测试用例加到测试集中
    return s;
}