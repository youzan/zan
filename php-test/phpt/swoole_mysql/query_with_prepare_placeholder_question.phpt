--TEST--
swoole_mysql: query with prepare placeholder question
--SKIPIF--
<?php require __DIR__ . "/../inc/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php
require_once __DIR__ . "/../inc/zan.inc";

fork_exec(function() {
    require_once __DIR__ . "/../../apitest/swoole_mysql/swoole_mysql_query_with_prepare_placeholder_question.php";
});
?>
--EXPECT--
SUCCESS