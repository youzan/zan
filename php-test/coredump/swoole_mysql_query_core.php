<?php

function mysql_cb_recursive_query()
{
    static $sock = null;

    if ($sock === null) {
        $sock = new \mysqli();
        $sock->connect('127.0.0.1', 'user_koudaitong', 'ocfLsVO7l2B3TMOPmpSX', 'db_koudaitong', '3007');
        $sock->autocommit(true);
    }

    $sql = "SELECT * FROM attachment WHERE mp_id = 1 limit 99";
    swoole_mysql_query($sock, $sql, function(\mysqli $sock, $ret) {
        echo "SUCCESS";
        mysql_cb_recursive_query();
    });
}

mysql_cb_recursive_query();