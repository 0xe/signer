
## About ##

A nginx module to sign JSON Web Tokens (JWTs):  (https://tools.ietf.org/html/rfc7515 and https://tools.ietf.org/html/rfc7516).

## Hacking ##

- clone nginx and openssl into signer/nginx and signer/openssl
- install jansson-devel.x86_64 zlib-devel.x86_64 pcre-devel.x86_64 (for rhel/centos)
- install libjansson-dev libpcre3-dev zlib1g-dev (for debian)
- make
- pushd target; ./sbin/nginx -c conf/nginx.conf; popd

## Config ##

```
            location /sign {
              default_exp 3600;
              jwt_header {"typ": "JWT", "alg": "RS256", "kid": "14556143233"};
              keyfile "/rsa_2048";
              add_header Cache-control no-cache;
            }
```

## Test ##

- Generate the key: `ssh-keygen -t rsa -b 2048 -f rsa.key`
- `curl -XPOST http://127.0.0.1:3000/sign -d @../test/sample.json`
