<?php
/**
 * Created by IntelliJ IDEA.
 * User: chuxiaofeng
 * Date: 17/5/24
 * Time: 下午4:33
 */

require_once __DIR__ . "/../tcpstat.php";


function makeConnSizeTest($connType, array $conf, $max = 20)
{
    return $yCombinator = function($n = 1) use(&$yCombinator, $max, $conf, $connType) {
        echo $conf["host"], ":", $conf["port"], " ", $n, "\n";

        $tcp_pool = new \swoole_connpool($connType);
        $r = $tcp_pool->setConfig($conf);
        assert($r === true);
        $r = $tcp_pool->createConnPool($n, $n);
        assert($r === true);

        $timeout = 1000;
        $timerId = swoole_timer_after($timeout + 100, function() use(&$got){
            assert(false);
            swoole_event_exit();
        });
        $tcp_pool->get($timeout, function(\swoole_connpool $pool, $cli) use($timerId, $n, $max, $conf, $yCombinator) {
            swoole_timer_clear($timerId);


            if ($cli instanceof \swoole_client || $cli instanceof \swoole_redis || $cli instanceof \swoole_mysql) {

                $info = $pool->getStatInfo();
                assert($info["all_conn_obj"] === $n);

                // FIXED coredump
                swoole_timer_after(100, function() use($n, $pool, $max, $conf, $yCombinator) {
                    $info = $pool->getStatInfo();
                    assert($info["idle_conn_obj"] === $n - 1);

                    $info = TcpStat::count($conf["host"], $conf["port"]);
                    if ($info["ESTABLISHED"] === $n) {
                        if ($n >= $max) {
                            swoole_event_exit();
                        } else {
                            $pool->destroy();
//                            $pool->__destruct(); // ~
                            $yCombinator($n + 1);
                        }
                    } else {
                        assert(false);
                        swoole_event_exit();
                    }
                });

            } else {
                assert(false);
                swoole_event_exit();
            }
        });
    };
}



function makeGroupConnSizeTest($connType, array $configGroup)
{
    $count = count($configGroup);
    return $yCombinator = function($index = 0) use(&$yCombinator, $connType, $configGroup, $count) {
        $n = ($index + 1) * 2;
        $config = $configGroup[$index];
        echo $config["host"], ":", $config["port"], " ", $n, "\n";

        $tcp_pool = new \swoole_connpool($connType);
        $r = $tcp_pool->setConfig($config);
        assert($r === true);

        $r = $tcp_pool->createConnPool($n, $n);
        assert($r === true);

        $timeout = 1000;
        $timerId = swoole_timer_after($timeout + 100, function() use(&$got){
            assert(false);
            swoole_event_exit();
        });
        $tcp_pool->get($timeout, function(\swoole_connpool $pool, $cli) use($timerId, $n, $index, $count, $configGroup, $yCombinator) {
            swoole_timer_clear($timerId);

            if ($cli instanceof \swoole_client || $cli instanceof \swoole_redis || $cli instanceof \swoole_mysql) {

                swoole_timer_after(100, function() use($configGroup, $index, $n, $count, $yCombinator, $pool) {
                    $info = TcpStat::count($configGroup[$index]["host"], $configGroup[$index]["port"]);
                    if ($info["ESTABLISHED"] === $n) {
                        if ($index >= $count - 1) {
                            swoole_event_exit();
                        } else {
                            $pool->destroy();
                            $yCombinator($index + 1);
                        }
                    } else {
                        assert(false);
                        swoole_event_exit();
                    }
                });
            } else {
                assert(false);
                swoole_event_exit();
            }
        });
    };
}
