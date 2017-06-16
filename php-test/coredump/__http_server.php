<?php

function debug_log($str, $handle = STDERR)
{
    if ($handle === STDERR) {
        $tpl = "\033[31m[%d %s] %s\033[0m\n";
    } else {
        $tpl = "[%d %s] %s\n";
    }
    if (is_resource($handle)) {
        fprintf($handle, $tpl, posix_getpid(), date("Y-m-d H:i:s", time()), $str);
    } else {
        printf($tpl, posix_getpid(), date("Y-m-d H:i:s", time()), $str);
    }
}



class HttpServer
{
    /**
     * @var \swoole_http_server
     */
    public $httpServ;

    public function __construct()
    {
        $this->httpServ = new \swoole_http_server("127.0.0.1", 9002, SWOOLE_PROCESS, SWOOLE_SOCK_TCP);

        $this->httpServ->set([
            "buffer_output_size" => 1024 * 1024 * 1024,

            "max_connection" => 10240,
            "pipe_buffer_size" => 1024 * 1024 * 1024,


            'user' => 'www-data',
            'group' => 'www-data',

            'dispatch_mode' => 3,
            'open_tcp_nodelay' => 1,
            'open_cpu_affinity' => 1,
            'daemonize' => 0,
            'reactor_num' => 1,
            'worker_num' => 2,
            'max_request' => 100000,
        ]);
        $this->httpServ->setglobal(HTTP_GLOBAL_ALL, HTTP_GLOBAL_GET | HTTP_GLOBAL_POST | HTTP_GLOBAL_COOKIE);
    }

    public function start()
    {
        $this->httpServ->on('start', [$this, 'onStart']);
        $this->httpServ->on('shutdown', [$this, 'onShutdown']);

        $this->httpServ->on('workerStart', [$this, 'onWorkerStart']);
        $this->httpServ->on('workerStop', [$this, 'onWorkerStop']);
        $this->httpServ->on('workerError', [$this, 'onWorkerError']);

        $this->httpServ->on('connect', [$this, 'onConnect']);
        $this->httpServ->on('request', [$this, 'onRequest']);

        $this->httpServ->on('close', [$this, 'onClose']);

        $this->httpServ->start();
    }

    public function onConnect()
    {
        debug_log("connecting ......");
    }

    public function onClose()
    {
        debug_log("closing .....");
    }

    public function onStart(swoole_server $swooleServer)
    {
        debug_log("server starting .....");
    }

    public function onShutdown(swoole_server $swooleServer)
    {
        debug_log("server shutdown .....");
    }

    public function onWorkerStart(swoole_server $swooleServer, $workerId)
    {
        debug_log("worker #$workerId starting .....");
    }

    public function onWorkerStop(swoole_server $swooleServer, $workerId)
    {
        debug_log("worker #$workerId stopping ....");
    }

    public function onWorkerError(swoole_server $swooleServer, $workerId, $workerPid, $exitCode, $sigNo)
    {
        debug_log("worker error happening [workerId=$workerId, workerPid=$workerPid, exitCode=$exitCode, signalNo=$sigNo]...");
    }

    public function onRequest(\swoole_http_request $request, \swoole_http_response $response)
    {
        $uri = $request->server["request_uri"];
        if ($uri === "/favicon.ico")  {
            $response->status(404);
            $response->end();
            return;
        }

        testSetCookie:
        {
            $name = "name";
            $value = "value";
            // $expire = $request->server["request_time"] + 3600;
            $expire = 0;
            $path = "/";
            $domain = "";
            $secure = false;
            $httpOnly = true;
            // string $name [, string $value = "" [, int $expire = 0 [, string $path = "" [, string $domain = "" [, bool $secure = false [, bool $httponly = false ]]]]]]
            $response->cookie($name, $value, $expire, $path, $domain, $secure, $httpOnly);
            $expect = "name=value; path=/; httponly";
            assert(in_array($expect, $response->cookie, true));
        }


        if ($uri === "/ping")  {
            $this->httpServ->send($request->fd, "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\npong\r\n");
            return;
        }

        if ($uri === "/info") {
            ob_start();
            print("request_uri: {$uri}\n");
            print("request_method: {$request->server['request_method']}\n");

            if (property_exists($request, "get")) {
                print("get:" . var_export($request->get, true) . "\n");
            }
            if (property_exists($request, "post")) {
                print("post:" . var_export($request->post, true) . "\n");
            }
            if (property_exists($request, "cookie")) {
                print("cookie:" . var_export($request->cookie, true) . "\n");
            }
            if (property_exists($request, "header")) {
                print("header:" . var_export($request->header, true) . "\n");
            }

            $response->end(nl2br(ob_get_clean()));
            return;
        }



        if ($uri === "/uri") {
            $response->end($request->server['request_uri']);
            return;
        }

        if ($uri === "/method") {
            $response->end($request->server['request_method']);
            return;
        }

        if ($uri === "/get") {
            if (property_exists($request, "get")) {
                $response->end(json_encode($request->get));
            } else {
                $response->end("{}");
            }
            return;
        }

        if ($uri === "/post") {
            if (property_exists($request, "post")) {
                $response->end(json_encode($request->post));
            } else {
                $response->end("{}");
            }
            return;
        }

        if ($uri === "/cookie") {
            if (property_exists($request, "cookie")) {
                $response->end(json_encode($request->cookie));
            } else {
                $response->end("{}");
            }
            return;
        }

        if ($uri === "/header") {
            if (property_exists($request, "header")) {
                $response->end(json_encode($request->header));
            } else {
                $response->end("{}");
            }
            return;
        }

        if ($uri === "/sleep") {
            swoole_timer_after(1000, function() use($response) {
                $response->end();
            });
            return;
        }




        if ($uri === "/404") {
            $response->status(404);
            $response->end();
            return;
        }

        if ($uri === "/302") {
            $response->header("Location", "http://www.youzan.com/");
            $response->status(302);
            $response->end();
            return;
        }

        if ($uri === "/file") {
            $response->header("Content-Type", "text");
            $response->header("Content-Disposition", "attachment; filename=\"test.php\"");
            $response->sendfile(__FILE__);
            $response->end();
            return;
        }

        if ($uri === "/code") {
            swoole_async_readfile(__FILE__, function($filename, $contents) use($response) {
                $response->end(highlight_string($contents, true));
            });
            return;
        }

        if ($uri === "/json") {
            $response->header("Content-Type", "application/json");
            $response->end(json_encode($request->server, JSON_PRETTY_PRINT));
            return;
        }


        $response->end("Hello World!");
    }
}


(new HttpServer())->start();