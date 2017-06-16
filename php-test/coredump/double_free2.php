<?php

swoole_async_dns_lookup("www.baidu.com", function($host, $ip) {

    $cli = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);


    $cli->on("connect", function(swoole_client $cli) {
        echo "connected\n";
        swoole_timer_clear($cli->timeo_id);

        // TODO getSocket BUG
        // assert(is_resource($cli->getSocket()));
        /*
        $cli->getSocket();
        // Warning: swoole_client::getSocket(): unable to obtain socket family Error: Bad file descriptor[9].
        $cli->getSocket();
         */

        assert($cli->isConnected() === true);
        $cli->send("GET / HTTP/1.1\r\n\r\n");
    });

    $cli->on("receive", function(swoole_client $cli, $data){
        $recv_len = strlen($data);
        echo "receive: len $recv_len\n";
        echo $data, "\n";
        $cli->send("GET / HTTP/1.1\r\n\r\n");
        $cli->close();
        assert($cli->isConnected() === false);
    });

    $cli->on("error", function(swoole_client $cli) {
        swoole_timer_clear($cli->timeo_id);
        echo "error\n";
    });

    $cli->on("close", function(swoole_client $cli) {
        swoole_timer_clear($cli->timeo_id);
        echo "close\n";
    });

    $cli->connect($ip, 80);

    $cli->timeo_id = swoole_timer_after(1000, function() use($cli) {
        echo "connect timeout\n";
        $cli->close();
        assert($cli->isConnected() === false);
    });
});
