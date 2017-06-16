--TEST--
swoole_conn_pool: __construct

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
 * Time: 下午5:43
 */

// declare(strict_types=1);


for ($i = 0; $i < 100; $i++) {
    try {
        new \swoole_connpool($i);
    } catch (\TypeError | \Exception $t) {

    }
}

swoole_timer_after(1, function() {
    swoole_event_exit();
    echo "SUCCESS";
});

?>

--EXPECT--
SUCCESS