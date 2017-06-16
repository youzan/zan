<?php
$bigData = str_repeat("x", 1024 * 1024 * 3.9);
$sql = <<<SQL
INSERT INTO `core_test` VALUES ('45600241', '18059894', '0', '$bigData', '1', '2016-11-09 14:49:52', '2016-11-09 15:04:09', '0', '0', '1');
SQL;

$link = new \mysqli();
$link->connect("127.0.0.1", "test_database", "test_database", "test_database", 3306);

// use 增加引用计数, 防止swoole引用计数bug
swoole_mysql_query($link, $sql, function($link, $result) use($link) {
    echo "SUCCESS";
});