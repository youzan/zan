#!/bin/sh

PWD=`pwd`
cd zan-extension

$1/phpize -v
result=$?

if [ $result != 0 ]
then
    echo '请输入PHP的bin路径'
    exit
fi

case $2 in
    build)
        $1/phpize
        ./configure --enable-sockets  --enable-async-redis --enable-openssl --with-php-config=$1/php-config
        make
        ;;
    install)
        make install
        ;;
    clean)
        make clean
        ;;
    clean-all)
        make clean
        ./clean.sh
        ;;
    *)
        make clean
        ./clean.sh
        $1/phpize
        ./configure --enable-sockets --enable-async-redis --enable-openssl --with-php-config=$1/php-config
        make
        make install
        ;;
esac
cd $PWD
