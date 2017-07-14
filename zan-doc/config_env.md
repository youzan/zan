##  Zan扩展配置项
 --enable-zan-debug     开启Zan扩展调试功能(开启SW_DEBUG宏)

 --enable-sockets       使用sockets扩展(默认打开)
                        注意需要安装PHP sockets扩展，否则configure时检查头文件php_sockets.h会出错

--enable-ringbuffer     使用ringbuffer内存池(宏SW_USE_RINGBUFFER）

--enable-async-redis    使用异步hiredis客户端(默认打开)

--enable-openssl        使用ssl功能

--enable-http2          使用http2.0功能，依赖nghttp2库

--enable-jemalloc       使用jemalloc内存管理器(较glibc malloc高效)，需安装jemalloc

--enable-tcmalloc       使用tcmalloc内存管理器

--with-zan              默认开启，扩展以动态共享库的形式

--enable-zan            同上

--with-openssl-dir=DIR  指定OpenSSL的路径，版本不低于0.9.6

--enable-mysqlnd        使用mysqlnd，依赖PHP的mysqlnd扩展。仅swoole_mysql_escape接口需要使用该配置项


依据系统定义属性宏

HAVE_CPU_AFFINITY       CPU亲和性

HAVE_REUSEPORT          socket端口复用

AC_COMPILE              检查系统编译器，如果clang，添加编译选项-std=gnu89

建议默认开启--enable-openssl配置项。

设置编译选项CFLAGS与链接选项LDFLAGS。

##  依赖的头文件、库、编译安装
检查运行时库
先检查是否有所需的外部库，再检查库的功能函数符号表，如果有则定义相应的宏供Zan扩展调用。
*  1.  检查C标准库的函数accept4／signalfd／timerfd_create／eventfd／epoll_create／sendfile／kqueue／backtrace
          ／daemon／mkostemp／inotify_init／inotify_init1  
*  2.  检查pthread库的函数pthread_rwlock_init／pthread_spin_lock／pthread_mutex_timedlock／pthread_barrier_init
*  3.  检查ssl库的函数SSL_library_init  注意开启openssl功能后，需确保ssl库被正确安装，否则Zan编译会报错。  
*  4.  检查hiredis库的函数redisConnect   注意确保hiredis库已安装
*  5.  检查nghttp2库的函数nghttp2_hd_inflate_new  需要使用nghttp2时生效。
*  6.  检查z库的函数gzgets，若有将该库链接到Zan扩展。
*  7.  系统平台相关的库使用

       mac:检查c标准库的clock_gettime／aio_read
           使用OPENSSL_DIR绝对路径，则分别添加该路径下的/lib到PHP库路径与/include到PHP头文件路径。

           同时添加crypto库。

           仅开启支持openssl,则添加默认的ssl库到zan扩展，同时也包含头文件及crypto库。

       非mac: 检查rt运行库的clock_gettime／aio_read，并将其添加到zan扩展中。

             使用OPENSSL_DIR绝对路径，则分别添加该路径下的/lib到PHP库环境变量与/include到PHP头文件路径。

             同时添加crypt/crypto库。

             仅开启支持openssl,则添加默认的ssl库到zan扩展，同时也包含头文件及crypto库。
*  8.  检查curl库及头文件，并将起加入到zan扩展。若按规则未找到正确的libcurl库，则config报错libcurl not installed

       找库顺序/usr /usr/local /usr/local/Cellar/curl/7.47.1，找头文件路径上三个路径下的include/curl/curl.h

       (注意，链接器约定会在lib下找库文件，去include下找头文件,且库文件命名必须为libXXX.so或libXXX.dylib
       如/usr/lib/libXXX.so，/usr/include/XXX.h)
*  9.  将pthread库加入到zan扩展

       若打开ASYNC_REDIS，对于linux将zan源码下已经编译好的hiredis_linux.a静态库链接到zan。

                         对于mac将zan源码下已经编译好的hiredis_mac.a静态库连链接到zan。

       若开HTTP2，添加库nghttp2到zan

       若开JEMALLOC，添加库jemalloc到zan

       若开TCMALLOC，添加库tcmalloc到zan


以在zan里使用jemalloc为例，库编译、zan安装过程：
```
安装jemalloc
官网 https://github.com/jemalloc/jemalloc
cd jemalloc
./configure --with-jemalloc-prefix=<prefix>
make
```
```
Zan编译使用
phpize
./configure --enable-jemalloc
make 
make install
```

## 常见配置、编译问题
Zan扩展配置、编译、安装步骤如下：
```
git clone https://github.com/youzan/zan.git
cd zan-extension
phpize
./configure
make 
make install
```
Zan编译安装常见问题：
1.  使用async-redis客户端及依赖sockets扩展默认打开，使用ssl功能默认不打开。
    1. 若不想使用async-redis客户端，可在configure时采用选项```--disable-async-redis```关闭。
    2. 使用async-redis客户端需要安装hiredis库，当前默认已提供x86下linux/mac的hiredis库。若需要支持arm等硬件平台，需要先安装hiredis库，然后在config.m4文件中添加```PHP_ADD_LIBRARY(hiredis, 1, ZAN_SHARED_LIBADD)```将其编译进ZAN扩展。
    3. 若想使用ssl功能，可在configure时采用选项```--enable-openssl```开启。
2.  若执行phpize报xxx/sed: No such file，请重装php或将/usr/bin/sed拷贝到xxx目录下。
3.  若执行phpize报Cannot find autoconf，请先安装autoconf工具。
4.  若执行configure时报错libcurl not installed，请重新安转curl库，并保证库与头文件名称与路径正确。
    1. 如库名称与路径/usr/lib/libcurl.so(通常带版本号的libxxx.so.xxx会软连接到libXXX.so供链接器识别)，对应头文件路径则为/usr/include/curl。
    2. 确认curl库正确安装后，请务必重新phpize && configure以保证新的配置生效。
    3. 若按1)、2)操作后仍然报错，则可修改config.m4中PHP_CURL的配置路径为你安装curl的路径。
5.  若执行configure时报错enable sockets support, sockets extension installed incorrectly，请确认PHP版本及sockets扩展正确安装。
    1. PHP版本需要在5.6以上版本。
    2. 在PHP的include路径下应该包含头文件ext/sockets/php_sockets.h。
    3. sockets扩展在zan之前加载(php.ini中的引入加载顺序)，以确保能引用符号表信息。
6.  若执行configure时报错Enable openssl support, require openssl library，请重新安装openssl库并保证能链接正确。
    1. 重新安装openssl库。
    2. 添加openssl库路径供链接器找lib，如将```-L/usr/local/opt/openssl/lib```补充到config.m4中的LDFLAGS。
    3. 添加openssl库依赖头文件路径，如将```-I/usr/local/opt/openssl/include```添加到config.m4中的CPPFLAGS。
    4. 依然需要重新配置，按编译扩展步骤安装，见上方。
