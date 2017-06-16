--TEST--
swoole_process: signal
--SKIPIF--
<?php require __DIR__ . "/../inc/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php


(new \swoole_process(function() {exit;}))->start();
swoole_process::signal(SIGCHLD, function() {
    swoole_event_exit();
    echo "SUCCESS";
});


?>
--EXPECT--
SUCCESS