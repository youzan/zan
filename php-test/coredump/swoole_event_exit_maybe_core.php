<?php

swoole_async_dns_lookup("pay.api.youzan.com", function($host, $ip) {
    echo posix_getpid(), ": $ip\n";
    swoole_event_exit();
    // exit();
});
