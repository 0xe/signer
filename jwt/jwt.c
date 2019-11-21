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
static void ngx_http_jwt_deinit(ngx_cycle_t *cf);

#define FIELDS_TO_CHECK 10
#define HEADER_LEN 68
#define BEARER_LEN 7

struct jwks {
  ngx_str_t keyname;
  EVP_PKEY *loaded_key;
};

EVP_PKEY *setup_jwks(ngx_str_t);
EVP_PKEY *fetch_jwks(ngx_str_t);

#define MAXHASH 10
static struct jwks *keytable[MAXHASH];


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
    NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(jwt_loc_conf_t, header),
    NULL
  },
  {
    ngx_string("jwt_jwks"),
    NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(jwt_loc_conf_t, jwks),
    NULL
  },
  {
    ngx_string("jwt_exp"),
    NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(jwt_loc_conf_t, exp),
    NULL
  },
  {
    ngx_string("jwt_skew"),
    NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
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
    ngx_http_jwt_deinit,           /* exit process */
    NULL,                          /* exit master */
  NGX_MODULE_V1_PADDING
};

static ngx_int_t ngx_http_jwt_handler(ngx_http_request_t *r)
{
  char *incoming_jwt;
  char *header, *signature, *body;
  const char *delim = "."; char *saveptr;
  char *encoded_header; char *jwks;

  // fetch conf
  jwt_loc_conf_t *location_conf = ngx_http_get_module_loc_conf(r, ngx_http_jwt_module);

  // decide to enforce, if no JWT present in the request
  if (!r->headers_in.authorization) {
    if (!ngx_strncmp(location_conf->enforce.data, "0", 1))
      return NGX_OK;
    else
      return NGX_HTTP_UNAUTHORIZED;
  }

  // fast header check first, if not bail out
  encoded_header = (char *) location_conf->header.data;

  if (r->headers_in.authorization->value.len > BEARER_LEN)
    incoming_jwt = (char *) r->headers_in.authorization->value.data + BEARER_LEN;
  else
    return NGX_HTTP_UNAUTHORIZED;

  // parse the jwt to extract the components
  header = strtok_r(incoming_jwt, delim, &saveptr);
  body = strtok_r(NULL, delim, &saveptr);
  signature = saveptr;

  if(strncmp(header, encoded_header, HEADER_LEN))
    return NGX_HTTP_UNAUTHORIZED;

  EVP_PKEY *pubkey = fetch_jwks(location_conf->jwks);

  if (pubkey == NULL) {
      // TODO: better error handling
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "jwt: invalid jwks. aborted.");
      return NGX_ERROR;
  }

  // verify signature
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

EVP_PKEY *setup_jwks(ngx_str_t jwks_file)
{
  RSA *rsakey;
  EVP_PKEY *pkey;

  const char *extracted_pubkey_modulus;
  char *pubkey;
  FILE *fp;

  fp = fopen((const char * __restrict__) jwks_file.data, "r");

  if (!fp)
    return NULL;

  json_t *jwks; json_error_t jerr;
  jwks = json_loadfd(fileno(fp), JSON_DECODE_ANY, &jerr);

  // attempt to read a KeySet, if that fails, see if you can read a Key
  json_t *keys, *key_1, *n;
  keys = json_object_get(jwks, "keys");

  if (keys == NULL) {
    n = json_object_get(jwks, "n");
  } else { // XXX: just the first key for now
    key_1 = json_array_get(keys, 0);
    n = json_object_get(key_1, "n");
  }

  extracted_pubkey_modulus = json_string_value(n);
  fclose(fp);

  // TODO: convert modulus to pubkey

  /* { */
  /*   rsakey = EVP_PKEY_get1_RSA(pkey); */

  /*   if(!RSA_check_key(rsakey)) */
  /*     return NULL; */
  /* } */

  return pkey;
}

EVP_PKEY *fetch_jwks(ngx_str_t jwks)
{
  unsigned long hv = ((unsigned long) ngx_hash_key_lc(jwks.data, jwks.len) % MAXHASH);

  if (keytable[hv] == NULL) {
    keytable[hv] = malloc(sizeof(struct jwks));
    keytable[hv]->keyname = jwks;
    keytable[hv]->loaded_key = setup_jwks(jwks);
  }

  return keytable[hv]->loaded_key;
}

static void ngx_http_jwt_deinit(ngx_cycle_t *cy)
{
  { int i;
    for(i = 0; i<MAXHASH; i++) free(keytable[i]); }

  return;
}
