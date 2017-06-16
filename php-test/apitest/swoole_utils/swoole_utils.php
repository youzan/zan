<?php

//function swoole_get_local_ip() {}
//function swoole_strerror($errno) {}
//function swoole_errno() {}

require_once __DIR__ . "/../../Bootstrap.php";


$ip_list = swoole_get_local_ip();
print_r($ip_list);


echo swoole_errno(), "\n";
echo swoole_strerror(swoole_errno());