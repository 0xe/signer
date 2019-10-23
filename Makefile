all: configure build
	cp config/nginx.conf target/conf/nginx.conf
	echo "built nginx in /target"

build:
	cd nginx/ && make -j2
	cd nginx/ && make install

configure: # TODO(satish): remove things you don't need
	cd nginx/ && ./auto/configure --prefix=../target --without-select_module --without-poll_module --with-http_ssl_module --with-http_sub_module --without-http_charset_module --without-http_ssi_module --without-http_userid_module --without-http_geo_module --without-http_split_clients_module --without-http_fastcgi_module --without-http_uwsgi_module --without-http_scgi_module --without-http_memcached_module --without-http_empty_gif_module --without-http_browser_module --with-pcre --with-pcre-jit --with-debug --add-module=../token --with-openssl=../openssl/ --with-openssl-opt='zlib no-ssl3 no-threads no-weak-ssl-ciphers -DOPENSSL_USE_IPV6=0 enable-ec_nistp_64_gcc_128 enable-weak-ssl-ciphers --debug' #  -sse2

clean:
	cd nginx/ && make clean
