
## About ##

A nginx module to sign JSON Web Tokens (JWTs):  (https://tools.ietf.org/html/rfc7515 and https://tools.ietf.org/html/rfc7516).

## Hacking ##

- clone nginx (from https://github.com/nginx/nginx) and openssl (from https://github.com/openssl/openssl) into signer/nginx and signer/openssl
- sed '/-Werror/d' nginx/auto/cc/gcc > nginx/auto/cc/gcc
- install jansson-devel.x86_64 zlib-devel.x86_64 pcre-devel.x86_64 (for rhel/centos)
- install libjansson-dev libpcre3-dev zlib1g-dev (for debian)
- make
- pushd target; ./sbin/nginx -c conf/nginx.conf; popd

## Example Config ##

```
     server {
            ...

            jwt_header_enc  'eyJ0eXAiOiAiSldUIiwgImFsZyI6ICJSUzI1NiIsICJraWQiOiAiMTU3MjUxMjQ1NyJ9';
	        jwt_jwks /code/jwks;
            jwt_skew 10;
	        jwt_exp 3600;
            jwt_enforce 0;
            jwt_issuer 'foobar.com';

            location /sign {
              keyfile "/code/pvt.pem";
              jwt_header '{"typ": "JWT", "alg": "RS256", "kid": "1572512457"}';
              default_exp 3600;
              add_header Cache-control no-cache;
            }

            location /foo {
              jwt_enforce 1;
              jwt_check_field role Admin;
              jwt_exp 500;
              proxy_pass http://127.0.0.1:8000/;
            }
     }
```

## Summary ##

### jwt module ###

This module is used verify JWT tokens.

`jwt_header_enc`: base64 encoded JWT header for a quick check.

`jwt_jwks`: path to jwks file.

`jwt_skew`: skew for `exp` claim.

`jwt_exp`: expiry to check for the jwt (in seconds).

`jwt_check_field`: claim name and values to check for in the JWT.

`jwt_enforce`: whether to enforce JWT validation.

`jwt_issuer`: issuer to check for in the JWT.

### token module ###

This module is used to sign JWT tokens.

`keyfile`: path to pvt key file used to sign the JWT token.

`jwt_header`: header for the JWT.

`default_exp`: default expiry value (in seconds).

`issuer`: issuer to sign the JWT with.

`exp` and `nbf` claims can be overridden by passing a `exp`,`nbf` param in the request.

## Test ##

- Generate the key: `ssh-keygen -t rsa -b 2048 -f rsa.key`
- `curl -XPOST http://127.0.0.1:3000/sign -d @../test/sample.json`
