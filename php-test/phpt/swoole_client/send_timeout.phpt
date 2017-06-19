--TEST--
swoole_client: swoole_client send timeout

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

$simple_tcp_server = __DIR__ . "/../../apitest/swoole_server/simple_server.php";
$closeServer = start_server($simple_tcp_server, TCP_SERVER_HOST, TCP_SERVER_PORT);

require_once __DIR__."/../../apitest/swoole_client/send_timeout.php";

send_timeout(TCP_SERVER_HOST, TCP_SERVER_PORT);

suicide(1000, SIGTERM, $closeServer);

?>

--EXPECT--
send timeout
close