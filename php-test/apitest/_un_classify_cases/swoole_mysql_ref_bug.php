<?php

function bug($sql, $n)
{
    for ($i = 0; $i < $n; $i++) {
        echo "n$i\n";
        $link = new \mysqli();
        $link->connect("127.0.0.1", "user_fans", "BO2UbpMgUb8PTYMzuxUn", "db_koudaitong", 3306);
        $ret = swoole_mysql_query($link, $sql, function($link, $result) {
            echo count($result), "\n";
        });
        assert($ret === true);
    }
}

function fix($sql, $n)
{
    static $addRef = [];

    for ($i = 0; $i < $n; $i++) {
        echo "n$i\n";

        $link = new \mysqli();
        $link->connect("127.0.0.1", "user_fans", "BO2UbpMgUb8PTYMzuxUn", "db_koudaitong", 3306);
        $addRef[] = $link;

        $ret = swoole_mysql_query($link, $sql, function($link, $result) {
            echo count($result), "\n";
        });
        assert($ret === true);
    }
}

$sql = "select 1";
bug($sql, 20);
fix($sql, 20);