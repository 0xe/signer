/*
Copyright 2018 Satish Srinivasan

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/*
 * Verify signed tokens in Authorization header
 */

#include <jansson.h>

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_hash.h>

/* crypto */
#include <openssl/x509v3.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

static ngx_int_t ngx_http_jwt_handler(ngx_http_request_t *r);
static void ngx_http_jwt_body_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_jwt_init(ngx_conf_t *cf);
static void *ngx_http_jwt_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_jwt_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static void ngx_http_jwt_deinit(ngx_cycle_t *cf);

typedef struct {
  ngx_str_t header;
  ngx_str_t jwks;
  ngx_str_t exp;
  ngx_str_t skew;
} jwt_loc_conf_t;

static ngx_command_t ngx_http_jwt_commands[] = {
  {
    ngx_string("header"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(jwt_loc_conf_t, header),
    NULL
  },
  {
    ngx_string("jwks"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(jwt_loc_conf_t, jwks),
    NULL
  },
  {
    ngx_string("exp"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(jwt_loc_conf_t, exp),
    NULL
  },
  {
    ngx_string("skew"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(jwt_loc_conf_t, skew),
    NULL
  },
  ngx_null_command
};

static ngx_http_module_t ngx_http_jwt_module_ctx = {
    NULL,                          /* preconfiguration */
    ngx_http_jwt_init,             /* postconfiguration */

    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */

    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */

    ngx_http_jwt_create_loc_conf,  /* create location configuration */
    ngx_http_jwt_merge_loc_conf    /* merge location configuration */
};

ngx_module_t  ngx_http_jwt_module = {
  NGX_MODULE_V1,
    &ngx_http_jwt_module_ctx,      /* module context */
    ngx_http_jwt_commands,         /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    ngx_http_jwt_deinit,           /* exit process */
    NULL,                          /* exit master */
  NGX_MODULE_V1_PADDING
};

static void ngx_http_jwt_body_handler(ngx_http_request_t *r)
{
}

static ngx_int_t ngx_http_jwt_handler(ngx_http_request_t *r)
{

  // fetch conf
  jwt_loc_conf_t *location_conf = ngx_http_get_module_loc_conf(r, ngx_http_jwt_module);

  r->request_body_in_single_buf = 1;
  ngx_int_t rc = ngx_http_read_client_request_body(r, ngx_http_jwt_body_handler);

  if (rc == NGX_AGAIN) {
    return NGX_DONE;
  }

  return rc;
}

static void *ngx_http_jwt_create_loc_conf(ngx_conf_t *cf) {
  jwt_loc_conf_t *conf;

  conf = ngx_pcalloc(cf->pool, sizeof(jwt_loc_conf_t));
  if (conf == NULL)
    return NULL;

  conf->header.data = NULL;
  conf->header.len = 0;
  conf->jwks.data = NULL;
  conf->jwks.len = 0;
  conf->exp.data = NULL;
  conf->exp.len = 0;
  conf->skew.data = NULL;
  conf->skew.len = 0;

  return conf;
}

static char *ngx_http_jwt_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
  jwt_loc_conf_t *prev = parent;
  jwt_loc_conf_t *conf = child;

  ngx_conf_merge_str_value(conf->header, prev->header, NULL);
  ngx_conf_merge_str_value(conf->jwks, prev->jwks, NULL);
  ngx_conf_merge_str_value(conf->exp, prev->exp, NULL);
  ngx_conf_merge_str_value(conf->skew, prev->skew, NULL);
  return NGX_CONF_OK;
}

static ngx_int_t ngx_http_jwt_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_jwt_handler;

    return NGX_OK;
}

static void ngx_http_jwt_deinit(ngx_cycle_t *cy)
{
  return;
}
