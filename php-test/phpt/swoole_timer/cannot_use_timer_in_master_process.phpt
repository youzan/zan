--TEST--
swoole_timer: cannot use timer in master process.
--SKIPIF--
<?php require __DIR__ . "/../inc/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php
require __DIR__ . "/../inc/zan.inc";

$tcpServer = new swoole_server("127.0.0.1", rand(8000, 9000), SWOOLE_PROCESS, SWOOLE_SOCK_TCP);
swoole_async_set(["socket_dontwait" => 1]);

$logfile = __DIR__ . '/swoole.log';
$tcpServer->set([
    //"log_file" => $logfile,
    "worker_num" => 1
]);
$tcpServer->on('start', function(swoole_server $server) use($logfile) {
    swoole_timer_after(1, function() {});
    //assert(strpos(file_get_contents($logfile), "cannot use timer in master process"));
    //unlink($logfile);
    `ps aux | grep php | grep -v grep | grep -v phpstorm | grep -v 'run-tests' | awk '{print $2}' | xargs kill -9`;
});
$tcpServer->on('shutdown', function(swoole_server $server) {});
$tcpServer->on('workerStart', function(swoole_server $server, $worker_id) {});
$tcpServer->on('workerStop', function(swoole_server $server, $worker_id) {});
$tcpServer->on('workerError', function(swoole_server $server, $worker_id, $workerPid, $exitCode, $sigNo) {});
$tcpServer->on('connect', function() {});
$tcpServer->on('close', function() {});
$tcpServer->on('receive', function(swoole_server $server, $fd, $fromId, $data) {});
$tcpServer->start();
?>
--EXPECTF--
[%d%d%d%d-%d%d-%d%d %d%d:%d%d:%d%d m.%f] WARNING php_swoole_add_timer(:%d): cannot use timer in master process.
[%d%d%d%d-%d%d-%d%d %d%d:%d%d:%d%d m.%f] WARNING zif_swoole_timer_after(:%d): add timer node failed.

Termsig=0