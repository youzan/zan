<?php
$link = new \mysqli();
$link->connect("127.0.0.1", "root", "", "information_schema", 3306);

swoole_mysql_query($link, "select sleep(100);", function(\mysqli $link, $result) {
    $fd = swoole_get_mysqli_sock($link);
    $res = fopen("php://fd/" . $fd, "r+");
    assert(is_resource($res));
    // assert(stream_set_blocking($res, 0));
    $sock = socket_import_stream($res);
    assert(socket_set_nonblock($sock));


//    $r = $w = $e = [$sock];
//    var_dump(socket_select($r, $w, $e, 0));
//    var_dump($r, $w, $e);

    var_dump(socket_recv($sock, $buf, 0, MSG_DONTWAIT));

    $errno = socket_get_option($sock, SOL_SOCKET, SO_ERROR);
    var_dump($errno);


//    $r = $w = $e = [$res];
//    var_dump(stream_select($r, $w, $e, 0));
//    var_dump($r, $w, $e);


//    var_dump(stream_socket_recvfrom($res, 1, null, $addr));
//    var_dump($addr);
});
