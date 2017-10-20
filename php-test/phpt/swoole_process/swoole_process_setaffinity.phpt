--TEST--
swoole_process: setaffinity
--SKIPIF--
<?php require __DIR__ . "/../inc/skipif.inc"; ?>
<?php require __DIR__ . "/../inc/skipifDarwin.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php

$os = php_uname('s');
if (strcmp("Darwin", $os) == 0) {
    echo "SUCCESS";
}
else {
    $r = \swoole_process::setaffinity([0]);
    assert($r==true);

    $r = \swoole_process::setaffinity([0, 1]);
    assert($r==true);

    echo "SUCCESS";
}

?>
--EXPECT--
SUCCESS