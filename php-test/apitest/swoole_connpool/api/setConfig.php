<?php
/**
 * Created by IntelliJ IDEA.
 * User: chuxiaofeng
 * Date: 17/5/22
 * Time: 下午6:10
 */

$tcp_pool = new \swoole_connpool(\swoole_connpool::SWOOLE_CONNPOOL_TCP);
$r = $tcp_pool->setConfig([
    "host" => "180.97.33.107", // baidu
    "port" => 80,
    // TODO
    'open_eof_check' => true,
    'package_eof' => "\r\n\r\n",
//    "socket_buffer_size" => 1,
]);
assert($r === true);

//$r = $tcp_pool->createConnPool(0, 0);


swoole_event_exit();