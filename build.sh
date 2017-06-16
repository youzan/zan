#!/bin/sh

PWD=`pwd`
cd swoole-extension 
case $1 in
    build)
        phpize
        ./configure --enable-sockets  --enable-async-redis --enable-openssl
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
	phpize
        ./configure --enable-sockets --enable-async-redis --enable-openssl
        make clean
	make install
        ;;
esac
cd $PWD
