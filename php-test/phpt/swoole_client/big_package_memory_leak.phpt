--TEST--
swoole_client: big_package_memory_leak

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

$tcp_server = __DIR__ . "/../../memoryleak/tcp_client_memory_leak/tcp_serv.php";
start_server($tcp_server, "127.0.0.1", 9001);

require_once __DIR__ . "/../../memoryleak/tcp_client_memory_leak/tcp_client.php";
?>

--EXPECT--