<?php

/**
 * swoole 3.0.4
 */



function send(\swoole_server $serv, $fd, $msg) {
    swoole_timer_after(100, function() use($serv, $fd, $msg) {
        $toSend = substr($msg, 0, 1);
        echo $toSend;
        $serv->send($fd, $toSend);
        $msg = substr($msg, 1);
        if (strlen($msg) > 0) {
            send($serv, $fd, $msg);
        }
    });
}


$serv = new \swoole_server("0.0.0.0", 8888);
$serv->set(["worker_num" => 1]);
$serv->on("receive", function(\swoole_server $serv, $fd) {
    $msg = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nA: B\r\n\r\nHELLO";
    send($serv, $fd, $msg);

//    $serv->send($fd, "HTTP/1.1 200 OK\r\n");
//    $serv->send($fd, "Content-Length: 5\r\n");
//    $serv->send($fd, "A: ");
//    swoole_timer_after(5000, function() use($serv, $fd) {
//        $serv->send($fd, "B\r\n\r\nHELLO");
//    });
});
$serv->start();