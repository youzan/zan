--TEST--
nova_get_sequence
--SKIPIF--
<?php require __DIR__ . "/../inc/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php 
for ($i = 0; $i < 10; $i++) {
    assert(nova_get_sequence() === $i + 1);
}
echo "SUCCESS";
?>
--EXPECT--
SUCCESS