#include "check.h"

START_TEST(test_ds) {
    fail_unless(type_eof); 
    fail_unless(hashmap1); 
    fail_unless(hashmap2); 
    fail_unless(rbtree); 
    fail_unless(chan); 
    fail_unless(list);
}
END_TEST

Suite * make_ds_suite(void) {
    Suite *s = suite_create("ds");       // 建立Suite
    TCase *tc_ds = tcase_create("ds");  // 建立测试用例集
    suite_add_tcase(s, ds);           // 将测试用例加到Suite中
    tcase_add_test(tc_ds, test_ds);     // 测试用例加到测试集中
    return s;
}