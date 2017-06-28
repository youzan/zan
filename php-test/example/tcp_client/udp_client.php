<?php
require_once __DIR__ . "/../../Bootstrap.php";

/*
$cli = new swoole_client(SWOOLE_SOCK_UDP, SWOOLE_SOCK_ASYNC);

$cli->set([
]);

$cli->on("connect", function(swoole_client $cli) {
    echo "udp client: connect.\n";
    var_dump($cli->isConnected());
    $cli->send("hello world.");
    //$cli->send(RandStr::gen(512, RandStr::ALL));
    // $cli->sendfile(__DIR__.'/client_file.txt');
    //var_dump($cli->getpeername()); //only support SWOOLE_SOCK_UDP or SWOOLE_SOCK_UDP6
    var_dump($cli->getsockname());
    var_dump($cli->getSocket());
});

$cli->on("receive", function(swoole_client $cli, $data){
    echo "receive: data$data";
    $recv_len = strlen($data);
    debug_log("receive: data len $recv_len");

    $cli->send(RandStr::gen(512, RandStr::ALL));
    //var_dump($cli->recv(8192));
    $cli->close();
    var_dump($cli->isConnected());
});

$cli->on("error", function(swoole_client $cli) {
    echo "error.\n";
});

$cli->on("close", function(swoole_client $cli) {
    echo "connection close.\n";
});

$cli->connect("127.0.0.1", 9502);
*/
$cli = new swoole_client(SWOOLE_SOCK_UDP, SWOOLE_SOCK_SYNC);

$cli->connect('127.0.0.1', 9502);
$cli->send("hello world");
echo $cli->recv()."\n";

$ret = $cli->sendto('127.0.0.1', 9502, "hello world");
$mess = $cli->recv();
echo "message:{$mess}\n";

$recv = $cli->recv();
echo "receive data: $recv\n";

?>
