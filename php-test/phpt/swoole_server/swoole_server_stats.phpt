--TEST--
swoole_server:
--SKIPIF--
<?php require __DIR__ . "/../inc/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php
require_once __DIR__ . "/../inc/zan.inc";

$simple_tcp_server = __DIR__ . "/../../apitest/swoole_server/stats_server.php";
$port = get_one_free_port();

start_server($simple_tcp_server, TCP_SERVER_HOST, $port);

suicide(2000);
usleep(500 * 1000);

makeTcpClient(TCP_SERVER_HOST, $port, function(\swoole_client $cli) {
    $r = $cli->send(opcode_encode("stats", []));
    assert($r !== false);
}, function(\swoole_client $cli, $recv) {
    list($op, $data) = opcode_decode($recv);
    var_dump($data['last_reload']);
    var_dump($data['connection_num']);
    var_dump($data['accept_count']);
    var_dump($data['close_count']);
    var_dump($data['tasking_num']);
    var_dump($data['request_count']);
    var_dump($data['total_worker']);
    var_dump($data['total_task_worker']);
    var_dump($data['active_worker']);
    var_dump($data['idle_worker']);
    var_dump($data['max_active_worker']);
    var_dump($data['max_active_task_worker']);
    var_dump($data['worker_normal_exit']);
    var_dump($data['worker_abnormal_exit']);
    var_dump($data['task_worker_normal_exit']);
    var_dump($data['task_worker_abnormal_exit']);
    var_dump(count($data['workers_detail']));
    // workers detail
    $busy = false;
    $task_worker_count = $worker_count = 0;
    foreach ($data['workers_detail'] as $worker) {
	    if ($worker['status'] == 'BUSY') {
		    $busy = true;
	    }
	    if ($worker['type'] == 'worker') {
		    $worker_count++;
	    } elseif ($worker['type'] == 'task_worker') {
		    $task_worker_count++;
	    }
    }
    var_dump($busy);
    var_dump($worker_count);
    var_dump($task_worker_count);
    swoole_event_exit();
});

?>
--EXPECT--
int(0)
int(1)
int(2)
int(1)
int(0)
int(0)
int(2)
int(2)
int(1)
int(1)
int(1)
int(0)
int(0)
int(0)
int(0)
int(0)
int(4)
bool(true)
int(2)
int(2)

