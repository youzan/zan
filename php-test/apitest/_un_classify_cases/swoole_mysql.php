<?php
$link = new \mysqli();
$link->connect("127.0.0.1", "root", "", "information_schema", 3306);
swoole_mysql_query($link, "select 1;", function($link, $result) {
    var_dump($result);
});
