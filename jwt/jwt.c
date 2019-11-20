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
static ngx_int_t ngx_http_jwt_init(ngx_conf_t *cf);
static void *ngx_http_jwt_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_jwt_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

#define FIELDS_TO_CHECK 10
#define HEADER_LEN 68
#define BEARER_LEN 7

typedef struct {
  ngx_str_t enforce; /* enforce JWT validation */
  ngx_str_t header; /* jwt header for fast check */
  ngx_str_t jwks;   /* location of jwks file */
  ngx_str_t exp;    /* allowed expiry for jwt */
  ngx_str_t skew;   /* allowed skew in the jwt */
  ngx_array_t *fields;  /* array of fields to check jwt for */
} jwt_loc_conf_t;

static ngx_command_t ngx_http_jwt_commands[] = {
  {
    ngx_string("jwt_header_enc"),
    NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(jwt_loc_conf_t, header),
    NULL
  },
  {
    ngx_string("jwt_jwks"),
    NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(jwt_loc_conf_t, jwks),
    NULL
  },
  {
    ngx_string("jwt_exp"),
    NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(jwt_loc_conf_t, exp),
    NULL
  },
  {
    ngx_string("jwt_skew"),
    NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(jwt_loc_conf_t, skew),
    NULL
  },
  {
    ngx_string("jwt_enforce"),
    NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(jwt_loc_conf_t, enforce),
    NULL
  },
  {
    ngx_string("jwt_fields"),
    NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_ANY,
    ngx_conf_set_str_array_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(jwt_loc_conf_t, fields),
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
    NULL,                          /* exit process */
    NULL,                          /* exit master */
  NGX_MODULE_V1_PADDING
};

static ngx_int_t ngx_http_jwt_handler(ngx_http_request_t *r)
{
  unsigned char *incoming_jwt;

  // fetch conf
  jwt_loc_conf_t *location_conf = ngx_http_get_module_loc_conf(r, ngx_http_jwt_module);

  // decide to enforce, if no JWT present in the request
  if (!r->headers_in.authorization)
    if (!ngx_strncmp(location_conf->enforce.data, "0", 1))
      return NGX_OK;
    else
      return NGX_HTTP_UNAUTHORIZED;

  // fast header check first, if not bail out
  unsigned char *header = (unsigned char *) location_conf->header.data;

  if (r->headers_in.authorization->value.len > BEARER_LEN)
    incoming_jwt = (unsigned char *) r->headers_in.authorization->value.data + BEARER_LEN;
  else
    return NGX_HTTP_UNAUTHORIZED;

  const char *delim = ".";
  char *header_part = strtok(incoming_jwt, delim);

  if(strncmp(header_part, header, HEADER_LEN))
    return NGX_HTTP_UNAUTHORIZED;

  // TODO: full JWT check

  return NGX_OK;
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
  conf->enforce.data = NULL;
  conf->enforce.len = 0;
  conf->fields = ngx_array_create(cf->pool, FIELDS_TO_CHECK, sizeof(ngx_str_t));

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
  ngx_conf_merge_str_value(conf->enforce, prev->enforce, NULL);
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
