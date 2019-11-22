all: configure build
	echo "built nginx in /target"

build:
	cd nginx/ && make -j2
	cd nginx/ && make install

configure:
	cd nginx/ && ./auto/configure --prefix=../target --with-http_ssl_module --with-http_sub_module --with-pcre --with-pcre-jit --with-debug --add-module=../token --add-module=../jwt --with-openssl=../openssl/ --with-openssl-opt='zlib no-ssl3 no-threads no-weak-ssl-ciphers -DOPENSSL_USE_IPV6=0 enable-ec_nistp_64_gcc_128 --debug'

clean:
	cd nginx/ && make clean
