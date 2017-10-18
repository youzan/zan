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

$host = TCP_SERVER_HOST;
$port = TCP_SERVER_PORT;

$pid = pcntl_fork();
if ($pid < 0) {
    exit;
}

if ($pid === 0) {
    usleep(1000);

    $client = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);
    
    //设置事件回调函数
    $client->on("connect", function($cli) {
        $cli->send("Hello Server!\n");
        $cli->close();
    });
    $client->on("receive", function($cli, $data){
        //echo "Client Received: ".$data."\n";
    });
    $client->on("error", function($cli){
        echo "Clinet Error.\n";
    });
    $client->on("close", function($cli){
        //echo "Client Close.\n";
    });
    //发起网络连接
    $client->connect($host, $port, 0.5);

} else {

    $serv = new swoole_server($host, $port);
    $serv->set([
        'worker_num' => 1,
        'net_worker_num' => 1,
        'log_file' => '/dev/null',
        //'log_file' => __DIR__ . '/dev/null',
        'max_connection'    => 10240,
        'pipe_buffer_size'  => 1024 * 1024 * 1024,

        //'dispatch_mode'     => 3,
        'open_tcp_nodelay'  => 1,
        'open_cpu_affinity' => 1,
        'daemonize'         => 0,
        //'worker_num'        => 1,
        'max_request'       => 100000,
    ]);

    $serv->on('Connect', function ($serv, $fd){
        echo "Server: onConnected, client_fd=$fd\n";
    });

    $serv->on('Receive', function ($serv, $fd, $from_id, $data) use($pid) {
        echo "Server: Receive data: $data\n";
        //pcntl_waitpid($pid, $status);
        $serv->shutdown();
    });
    $serv->start();
}


?>

--EXPECT--
Server: onConnected, client_fd=1
Server: Receive data: Hello Server!