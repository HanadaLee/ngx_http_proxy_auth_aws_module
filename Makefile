CC ?= gcc
CFLAGS=-g -I${NGX_PATH}/src/os/unix -I${NGX_PATH}/src/core -I${NGX_PATH}/src/http -I${NGX_PATH}/src/http/modules -I${NGX_PATH}/src/event -I${NGX_PATH}/objs/ -I.


all:

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

.PHONY: all clean test nginx prepare-travis-env


NGX_PATH := $(shell echo `pwd`/nginx)

prepare-travis-env:
	wget --no-verbose https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz
	tar -xzf nginx-${NGINX_VERSION}.tar.gz
	ln -s nginx-${NGINX_VERSION} ${NGX_PATH}
	cd ${NGX_PATH} && ./configure --with-http_ssl_module --with-cc=$(CC) --add-module=/root/project

nginx:
	cd ${NGX_PATH} && rm -rf ${NGX_PATH}/objs/src/core/nginx.o && make

vendor/cmocka:
	cd /root/project && git submodule init && git submodule update

.cmocka_build:
	cd /root/project && git submodule init && git submodule update && mkdir .cmocka_build && cd .cmocka_build \
	&& cmake -DCMAKE_C_COMPILER=$(CC) -DCMAKE_MAKE_PROGRAM=make /root/project/vendor/cmocka \
	&& make && sudo make install

test: .cmocka_build | nginx
	strip -N main -o ${NGX_PATH}/objs/src/core/nginx_without_main.o ${NGX_PATH}/objs/src/core/nginx.o \
	&& mv ${NGX_PATH}/objs/src/core/nginx_without_main.o ${NGX_PATH}/objs/src/core/nginx.o \
	&& $(CC) ngx_http_proxy_auth_aws_test.c $(CFLAGS) -o ngx_http_proxy_auth_aws_test -lcmocka `find ${NGX_PATH}/objs -name \*.o` -ldl -lpthread -lcrypt -lssl -lpcre -lcrypto -lz \
	&& ./ngx_http_proxy_auth_aws_test

clean:
	rm -f *.o ngx_http_proxy_auth_aws_test

# vim: ft=make ts=8 sw=8 noet
