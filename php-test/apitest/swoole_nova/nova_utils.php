<?php

//function nova_get_sequence() {}
//function nova_get_time() {}
//function nova_get_ip() {}
//function is_nova_packet() {}


require_once __DIR__ . "/../../Bootstrap.php";


for ($i = 0; $i < 10; $i++) {
    assert(nova_get_sequence() === $i + 1);
}

assert(true === is_nova_packet(str_pad(str_repeat("\0", 4) . pack('n', 0xdabc), 37, "\0", STR_PAD_RIGHT)));
assert(false === is_nova_packet(str_repeat("\0", 37)));
assert(false === is_nova_packet(null));

assert(abs(nova_get_time() - time()) <= 1);
assert(in_array(nova_get_ip(), array_values(swoole_get_local_ip()), true));


//swoole_server::nova_config($zconfig) {}
//swoole_server::deny_request($worker_id) {}


