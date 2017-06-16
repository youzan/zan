--TEST--
swoole_get_local_ip

--SKIPIF--
<?php require  __DIR__ . "/../inc/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0

--FILE--
<?php

$ips = swoole_get_local_ip();
foreach ($ips as $ip) {
    assert(filter_var($ip, FILTER_VALIDATE_IP) === $ip);
    assert(strstr($ip, ".", true) !== "127");
    assert(in_array(nova_get_ip(), array_values(swoole_get_local_ip()), true));
}

?>

--EXPECT--
