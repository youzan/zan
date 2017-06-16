<?php
/**
 * Created by IntelliJ IDEA.
 * User: chuxiaofeng
 * Date: 17/5/22
 * Time: 下午5:43
 */

// declare(strict_types=1);


for ($i = 0; $i < 100; $i++) {
    try {
        new \swoole_connpool($i);
        echo $i;
    } catch (\TypeError | \Exception $t) {

    }
}

swoole_timer_after(1, function() {
    swoole_event_exit();
});
