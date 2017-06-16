--TEST--
swoole_async: swoole_clean_dns_cache

--SKIPIF--
<?php require  __DIR__ . "/../inc/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php
require_once __DIR__ . "/../inc/zan.inc";
swoole_async_dns_lookup("www.baidu.com", function($host, $ip) {
    assert(ip2long($ip));
    echo "SUCCESS\n";
});

swoole_clean_dns_cache();

swoole_async_dns_lookup("www.baidu.com", function($host, $ip) {
    assert(ip2long($ip));
    echo "SUCCESS\n";
});

?>

--EXPECT--
SUCCESS
SUCCESS
