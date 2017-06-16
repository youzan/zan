<?php

require_once __DIR__ . "/../../Bootstrap.php";



$onQuery = function($swoole_mysql, $result) {
    assert($swoole_mysql->errno === 0);

    $swoole_mysql->query("select 1", function($swoole_mysql, $result) {
        assert($swoole_mysql->errno === 0);
        swoole_event_exit();
        fprintf(STDERR, "SUCCESS");
    });
};


$sql = "select 1";

$swoole_mysql = new \swoole_mysql();

$swoole_mysql->on("close", function() {
    echo "closed\n";
});

$swoole_mysql->conn_timeout = swoole_timer_after(1000, function() use($onQuery, $swoole_mysql) {
    $onQuery($swoole_mysql, "connecte timeout");
});

$onConnect = function(\swoole_mysql $swoole_mysql, $result) use($sql, $onQuery) {
    swoole_timer_clear($swoole_mysql->conn_timeout);

    if ($result) {
        $swoole_mysql->query_timeout = swoole_timer_after(1000, function() use($onQuery, $swoole_mysql) {
            $onQuery($swoole_mysql, "query timeout");
        });

        $swoole_mysql->query($sql, function(\swoole_mysql $swoole_mysql, $result) use($onQuery) {
            swoole_timer_clear($swoole_mysql->query_timeout);
            // TODO error error_no
            $onQuery($swoole_mysql, $result);
            // $swoole_mysql->close();
        });
    } else {
        echo "connect error [errno=$swoole_mysql->connect_errno, error=$swoole_mysql->connect_error]";
    }
};



$r = $swoole_mysql->connect([
    "host" => MYSQL_SERVER_HOST,
    "port" => MYSQL_SERVER_PORT,
    "user" => MYSQL_SERVER_USER,
    "password" => MYSQL_SERVER_PWD,
    "database" => MYSQL_SERVER_DB,
    "charset" => "utf8mb4",
], $onConnect);

$r = $swoole_mysql->connect([
    "host" => MYSQL_SERVER_HOST,
    "port" => MYSQL_SERVER_PORT,
    "user" => MYSQL_SERVER_USER,
    "password" => MYSQL_SERVER_PWD,
    "database" => MYSQL_SERVER_DB,
    "charset" => "utf8mb4",
], $onConnect);
