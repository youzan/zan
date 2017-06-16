--TEST--
swoole_conn_pool: create conn pool 3 - 3

--SKIPIF--
<?php require  __DIR__ . "/../inc/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php

require_once __DIR__ . "/../inc/zan.inc";

/**
 * Created by IntelliJ IDEA.
 * User: chuxiaofeng
 * Date: 17/5/22
 * Time: 下午9:15
 */


require_once __DIR__ . "/connSizeTest.php";

// 测试连接创建数量

$test = makeGroupConnSizeTest(\swoole_connpool::SWOOLE_CONNPOOL_MYSQL, [
    [
        "host" => MYSQL_SERVER_HOST,
        "port" => MYSQL_SERVER_PORT,
        "user" => MYSQL_SERVER_USER,
        "password" => MYSQL_SERVER_PWD,
        "database" => MYSQL_SERVER_DB,
        "charset" => "utf8mb4",
    ],
    [
        "host" => MYSQL_SERVER_HOST1,
        "port" => MYSQL_SERVER_PORT1,
        "user" => MYSQL_SERVER_USER1,
        "password" => MYSQL_SERVER_PWD1,
        "database" => MYSQL_SERVER_DB1,
        "charset" => "utf8mb4",
    ],
    [
        "host" => MYSQL_SERVER_HOST2,
        "port" => MYSQL_SERVER_PORT2,
        "user" => MYSQL_SERVER_USER2,
        "password" => MYSQL_SERVER_PWD2,
        "database" => MYSQL_SERVER_DB2,
        "charset" => "utf8mb4",
    ],
    [
        "host" => MYSQL_SERVER_HOST3,
        "port" => MYSQL_SERVER_PORT3,
        "user" => MYSQL_SERVER_USER3,
        "password" => MYSQL_SERVER_PWD3,
        "database" => MYSQL_SERVER_DB3,
        "charset" => "utf8mb4",
    ],
]);
$test();

?>

--EXPECT--
SUCCESS
