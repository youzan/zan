--TEST--
nova_get_time
--SKIPIF--
<?php require __DIR__ . "/../inc/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php
assert(abs(nova_get_time() - time()) <= 1);
echo "SUCCESS";
?>
--EXPECT--
SUCCESS
