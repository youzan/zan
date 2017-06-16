<?php

require_once __DIR__ . "/../../Bootstrap.php";


class Obj {}

$redis = new swoole_redis();
$redis->on("close", function() {
    echo "close";
});
$redis->on("message", function() { var_dump(func_get_args()); });

// $redis->connect(REDIS_SERVER_PATH, false, function() {}); TODO
$redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT, function(\swoole_redis $redis) {
    // echo "connected";

    $func = function() {
        if ($this->dep > $this->n) {
            $this->redis->close(); // !!! 会触发onClose回调
            swoole_event_exit();
            echo "SUCCESS";
            exit;
        }

        $this->redis->get($this->key, function(\swoole_redis $redis, $result) {
            assert($result === null);

            $this->value = RandStr::gen($this->valueSize, RandStr::ALPHA | RandStr::NUM | RandStr::CHINESE);

            $this->redis->set($this->key, $this->value, function(\swoole_redis $redis, $result) {
                assert($result === true);

                $this->redis->get($this->key, function(\swoole_redis $redis, $result) {
                    assert($result === $this->value);

                    $this->redis->del($this->key, function(\swoole_redis $redis, $result){
                        assert($result === 1);

                        $this->dep++;
                        $self = $this->func;
                        $self();
                    });
                });
            });
        });
    };

    $self = new Obj();
    $self->redis = $redis;
    $self->dep = 0;
    $self->n = 10;
    $self->valueSize = 1024;
    $self->key = "swoole:test:key_" . md5(microtime());
    $self->func = $func->bindTo($self);
    $closure = $self->func;
    $closure();
});
