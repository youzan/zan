--TEST--
swoole_async: recursive write file

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

function recursiveWrite($dep = 0, $size = 1024 * 1024)
{
    static $data;
    if ($data === null) {
        $data = file_get_contents("/dev/urandom", null, null, null, $size);
    }

    $file = "tmp.file";

    swoole_async_write($file, $data, -1, function ($file, $len) use(&$recursiveWrite, $dep, $size) {
        if ($dep > 100) {
            echo "SUCCESS";
            unlink($file);
            return false;
        }

        assert($len === $size);
        recursiveWrite(++$dep);
        return true;
    });
}

recursiveWrite();
?>

--EXPECT--
SUCCESS