#!/bin/bash
yum install pcre-devel openssl-devel gcc make g++ curl lua-devel gcc-c++ automake -y
tar zxvf openresty-1.13.6.2.tar.gz
tar zxvf libmaxminddb-1.3.2.tar.gz
cd openresty-1.13.6.2
./configure --prefix=/opt/jxwaf && gmake && gmake install
cd ../libinjection/
chmod +x src/*.py
make all
cp src/libinjection.so /opt/jxwaf/lualib/
mv /opt/jxwaf/nginx/conf/nginx.conf  /opt/jxwaf/nginx/conf/nginx.conf.bak
cp ../conf/nginx.conf /opt/jxwaf/nginx/conf/
cp ../conf/full_chain.pem /opt/jxwaf/nginx/conf/
cp ../conf/private.key /opt/jxwaf/nginx/conf/
mkdir /opt/jxwaf/nginx/conf/jxwaf
cp ../conf/jxwaf_config.json /opt/jxwaf/nginx/conf/jxwaf/
cp ../conf/GeoLite2-Country.mmdb /opt/jxwaf/nginx/conf/jxwaf/
cp -r ../lib/resty/jxwaf  /opt/jxwaf/lualib/resty/
/opt/jxwaf/nginx/sbin/nginx -t


