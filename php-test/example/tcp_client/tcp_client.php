<?php
require_once __DIR__ . "/../../Bootstrap.php";


$cli = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);

$cli->set([
    //'open_eof_check' => true,
    //'package_eof' => "\r\n\r\n",
    //"socket_buffer_size" => 1,
/*
结束符检测：
 open_eof_check
 package_eof
 package_max_length

长度检测：
 open_length_check
 package_length_type
 package_length_offset
 package_body_offset
 package_max_length

Socket 缓冲区尺寸：
 socket_buffer_size

关闭Nagle合并算法：
 open_tcp_nodelay

SSL/TLS证书：
 ssl_cert_file
 ssl_key_file

绑定IP和端口：
 bind_address
 bind_port

Socks5代理设置：
 socks5_host
 socks5_port
 socks5_username
 socks5_password
 */
]);

//setConnectTimeout()
//setSendTimeout()

$cli->on("connect", function(swoole_client $cli) {
    echo "tcp client: connect.\n";
    var_dump($cli->isConnected());
    $cli->send(RandStr::gen(512, RandStr::ALL));
    // $cli->sendfile(__DIR__.'/client_file.txt');
    //var_dump($cli->getpeername()); //only support SWOOLE_SOCK_UDP or SWOOLE_SOCK_UDP6
    var_dump($cli->getsockname());
    var_dump($cli->getSocket());
});

$cli->on("receive", function(swoole_client $cli, $data){
    echo "Receive: $data";
    $recv_len = strlen($data);
    debug_log("receive: data len $recv_len");

    $cli->send(RandStr::gen(512, RandStr::ALL));
    //var_dump($cli->recv(8192));   

    /*for sync tcp  
    $filename = __DIR__ . "/client.txt";
    echo "send file name: $filename\n";
    $cli->sendfile($filename);
    echo "Receive file: $data";
    */

    $cli->close();
    var_dump($cli->isConnected());
});

$cli->on("error", function(swoole_client $cli) {
    echo "error.\n";
});

$cli->on("close", function(swoole_client $cli) {
    echo "connection close.\n";
});

$cli->connect("127.0.0.1", 9501);
?>
