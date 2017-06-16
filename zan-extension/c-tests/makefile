vpath %.h include  
vpath %.c utests
vpath %.c utest_main

    objects = aio.o test_aio.o client.o test_client.o ds.o test_ds.o heap.o test_heap.o http.o test_http.o 
              mem.o test_mem.o pipe.o test_pipe.o pool.o test_pool.o ringbuffer.o test_ringbuffer.o server.o test_server.o
              
    test: test_main.c $(objects)
        gcc -I include $^ -o test -lswoole -lcheck

    all: $(objects)
    $(objects): %.o: %.c
        gcc -c -I include $< -o $@

    .PHONY: clean
    clean:
        rm *.o test