<?php
/**
 * Created by IntelliJ IDEA.
 * User: chuxiaofeng
 * Date: 17/5/22
 * Time: 下午10:11
 */
function r_dns()
{
    swoole_async_dns_lookup("www.youzan.com", function($_, $ip) {
        echo $ip;
        r_dns();
    });
}
// r_dns();
// xdebug: PHP Fatal error:  Maximum function nesting level of '256' reached, aborting!

function r_dns_async($i)
{
    swoole_async_dns_lookup("www.youzan.com", function($_, $ip) use($i) {
        swoole_event_defer(function() use($i) {
            if ($i > 10000) {
                swoole_event_exit();
            } else {
                r_dns_async($i + 1);
            }
        });
    });
}
r_dns_async(0);


// nodejs
//function ImmediateCall()
//{
//    console.log(".");
//    setImmediate(function() {
//        ImmediateCall();
//    });
//}
//ImmediateCall();

//swoole_timer_after(1, function() {
//    function deferCall() {
//        echo ".";
//        swoole_event_defer(function() {
//            deferCall();
//        });
//    }
//    deferCall();
//});
//return;