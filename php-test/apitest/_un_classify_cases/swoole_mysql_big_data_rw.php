<?php

function test() {
    global $argv;

// 一次
//    static $link;

    static $links = [];

    $bigData = str_repeat("x", $argv[1]);
    $sql = <<<SQL
INSERT INTO `feature_v2_core_test` VALUES ('44718556', '18059894', '0', '这是您的第一篇微杂志', '9e48fjil', '0', '0', '0', '0', '$bigData', '1', '2016-10-20 01:09:18', '2016-12-30 11:08:24', '0', '0', '1');
SQL;
    echo strlen($sql), "\n";

    $link = new \mysqli();
    $link->connect("127.0.0.1", "test_database", "test_database", "test_database", 3306);

    // 不加这一行会因为link丢失造成coredump
    $links[] = $link;

    // use 增加引用计数, 防止swoole引用计数bug
    swoole_mysql_query($link, $sql, function(mysqli $link, $result) use($link) {
        $sql = "select * from feature_v2_core_test where kdt_id = 18059894";
        swoole_mysql_query($link, $sql, function($link, $result) use($link) {
            echo count($result), "\n";
            test();
        });
    });
}

test();