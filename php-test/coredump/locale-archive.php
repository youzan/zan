<?php
/*
sudo rm -rf /opt/php/etc/php.d/mongo.ini
sudo rm -rf /opt/php/etc/php.d/yaf.ini
sudo rm -rf /opt/php/etc/php.d/yar.ini
sudo rm -rf /opt/php/etc/php.d/libevent.ini
sudo rm -rf /opt/php/etc/php.d/opcache.ini
sudo rm -rf /opt/php/etc/php.d/uuid.ini
sudo rm -rf /opt/php/etc/php.d/redis.ini
*/


// call zif_debug_print_backtrace(0,(zval*)0,(zval**)0, (zval*)0, 0)

// pf-api-0
/*
Jan 13 14:18:28 bc-prod-pf-api0 kernel: php[5684]: segfault at 7fc92fcd3664 ip 00007fc92fcd3664 sp 00007fc8e3d1e590 error 14 in libevent-2.0.so.5.1.9[7fc930677000+44000]

PHP Fatal error:  Cannot use PfApi\Member\Service\MemberService as MemberService because the name is already in use in /home/www/pf-api/src/Goods/Service/ItemService.php on line 25
[2017-01-13 14:18:28 *5616.1]	WARNING	zm_deactivate_swoole: PHP_RSHUTDOWN_FUNCTION(swoole).
[2017-01-13 14:18:28 *5616.1]	ERROR	zm_deactivate_swoole (ERROR 103): Fatal error: Cannot use PfApi\Member\Service\MemberService as MemberService because the name is already in use in /home/www/pf-api/src/Goods/Service/ItemService.php on line 25.
*/

// scrm 1000 fatal error, 各种coredump

// gdb --args php -r 'swoole_async_dns_lookup("www.youzan.com", function() { fatal_errror(); });'
// source .gdbinit

// 1358 if (sapi_module->startup(sapi_module) == FAILURE) {
// 415     static int php_cli_startup(sapi_module_struct *sapi_module)
// 2065    int php_module_startup(sapi_module_struct *sf, zend_module_entry *additional_modules, uint num_additional_modules)
// b 1358

// zend_module_entry

// b sapi_startup
// b php_module_startup
// zend_startup(&zuf, NULL TSRMLS_CC);
// zend_startup_builtin_functions
// b php_module_shutdown
    // b zend_destroy_modules
        // zend_hash_graceful_reverse_destroy

// HashTable module_registry
// print_ht &module_registry

// M_SHUTDOWN or R_SHUTDOWN 退出子线程
// aio 线程 pthread_cond_wait

// 重复运行 coredump
// 初始化 AIO线程池
// swoole_async_dns_lookup("www.youzan.com", function() { fatal_errror(); });


while (true) {
    $pid = pcntl_fork();
    if ($pid < 0) {
        exit;
    }

    if ($pid === 0) {
        // 初始化 AIO线程池
        swoole_async_dns_lookup("www.youzan.com", function($host, $ip) {
            fatal_errror();
        });
        exit();
    }

    pcntl_waitpid($pid, $status);
    if (!pcntl_wifexited($status)) {
        fprintf(STDERR, "$pid %s exit [exit_status=%d, stop_sig=%d, term_sig=%d]\n",
            pcntl_wifexited($status) ? "normal": "abnormal",
            pcntl_wexitstatus($status),
            pcntl_wstopsig($status),
            pcntl_wtermsig($status)
        );
        exit(1);
    }
}