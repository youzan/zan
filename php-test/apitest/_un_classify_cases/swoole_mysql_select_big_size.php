<?php
$link = new \mysqli();
$link->connect("127.0.0.1", "root", "", "information_schema", 3306);

function normal(\mysqli $link)
{
    swoole_mysql_query($link, "select 1;", function($link, $ret) {
        var_dump(swoole_event_del(swoole_get_mysqli_sock($link)));
        swoole_mysql_query($link, "select 1", function($link, $ret) {
            var_dump($ret);
        });
    });
}

function bug(\mysqli $link)
{
    swoole_mysql_query($link, "select 1;", function($link, $ret) {
        $sock = swoole_get_mysqli_sock($link);
        // $link !== null
        var_dump(swoole_event_del($sock));
        // $link === null
        swoole_mysql_query($link, "select 1", function($link, $ret) {
            var_dump($ret);
        });
    });
}


//normal($link);
bug($link);