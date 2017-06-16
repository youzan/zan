--TEST--
swoole_client: swoole_client sendfile

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

$simple_tcp_server = __DIR__ . "/../../apitest/swoole_server/simple_tcp_server.php";
start_server($simple_tcp_server, TCP_SERVER_HOST, $port = get_one_free_port());

$cli = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
$cli->connect(TCP_SERVER_HOST, $port);

$filename = __DIR__ . "/swoole_client.phpt";
echo "sendfile name:$filename\n";
$ret = $cli->sendfile($filename);

$retstr = $cli->recv();
echo "receive=$retstr\n";

?>

--EXPECTF--
sendfile name:%s
receive=testsendfile.txt
