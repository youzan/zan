<?php

// mac 下会产生死锁

$i = 5;
while($i--) {
    $pid = pcntl_fork();
    switch (true) {

        case $pid < 0:
            echo "fork error\n";
            exit(1);

        case $pid == 0:
            $j = 1000;
            $pid = posix_getpid();
            swoole_timer_tick(1, function($id) use(&$j, $pid) {
                $key = "hello"; // . $pid;
                apcu_add($key, 0);
                apcu_inc($key, 1);
                // apcu_dec($key, 1);
                $j--;
                echo "$pid: $j\n";
                if ($j <=0 ) {
                    swoole_timer_clear($id);
                    exit(0);
                }
            });
            // swoole_event_wait();
            exit(0);

        case $pid > 0:
            echo $pid, "\n";
            break;
    }
}

while(pcntl_wait($status) > 0) {}

echo "Done\n";
exit(0);