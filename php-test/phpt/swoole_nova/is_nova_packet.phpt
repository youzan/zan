--TEST--
is_nova_packet
--SKIPIF--
<?php require __DIR__ . "/../inc/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php
assert(true === is_nova_packet(str_pad(str_repeat("\0", 4) . pack('n', 0xdabc), 37, "\0", STR_PAD_RIGHT)));
assert(false === is_nova_packet(str_repeat("\0", 37)));
assert(false === is_nova_packet(null));

echo "SUCCESS";
?>
--EXPECT--
SUCCESS
