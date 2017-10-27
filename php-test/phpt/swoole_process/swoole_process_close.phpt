--TEST--
swoole_process: close
--SKIPIF--
<?php require __DIR__ . "/../inc/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php
//$proc = new \swoole_process(function(\swoole_process $proc) {
//    $proc->close();
//});
//$proc->start();
//
//$proc = new \swoole_process(function(\swoole_process $proc) {
//    sleep(1);
//    // assert(false);
//});
//$proc->start();
//$proc->close();
//
//
//\swoole_process::wait(true);
//\swoole_process::wait(true);
echo "SUCCESS";
?>
--EXPECT--
SUCCESS