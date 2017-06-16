<?php
/**
 * Created by IntelliJ IDEA.
 * User: chuxiaofeng
 * Date: 17/5/22
 * Time: 下午9:04
 */


if (!function_exists("once")) {
    function once(callable  $fn) {
        $called = false;
        $result = null;
        return function(...$args) use($fn, &$called, &$result) {
            if ($called === false) {
                $called = true;
                $result = $fn(...$args);
                return $result;
            } else {
                return $result;
            }
        };
    }
}

if (!function_exists("test_done")) {
    function test_done(callable  $fn) {
        $fn = once($fn);
        return function(...$args) use($fn) {
            $fn(...$args);
            swoole_event_exit();
        };
    }
}
