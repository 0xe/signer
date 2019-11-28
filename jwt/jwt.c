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
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

static ngx_int_t ngx_http_jwt_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_jwt_init(ngx_conf_t *cf);
static void *ngx_http_jwt_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_jwt_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static void ngx_http_jwt_deinit(ngx_cycle_t *cf);
static int verify(char *msg, size_t mlen, char *sig, size_t slen, EVP_PKEY *key, ngx_http_request_t *r);

#define HEADER_LEN 68
#define BEARER_LEN 7

struct jwks {
  ngx_str_t keyname;
  EVP_PKEY *loaded_key;
};

EVP_PKEY *setup_jwks(ngx_str_t);
EVP_PKEY *fetch_jwks(ngx_str_t);
EVP_PKEY *extract_pubkey(const char *exp, const char *modulus);

#define MAXHASH 10
static struct jwks *keytable[MAXHASH];

int asprintf(char **strp, const char *fmt, ...);

typedef struct {
  ngx_str_t enforce; /* enforce JWT validation */
  ngx_str_t header; /* jwt header for fast check */
  ngx_str_t jwks;   /* location of jwks file */
  ngx_str_t exp;    /* allowed expiry for jwt */
  ngx_str_t skew;   /* allowed skew in the jwt */
  ngx_str_t issuer; /* iss claim for the jwt */
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
    ngx_string("jwt_check_field"),
    NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
    ngx_conf_set_keyval_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(jwt_loc_conf_t, fields),
    NULL
  },
  {
    ngx_string("jwt_issuer"),
    NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(jwt_loc_conf_t, issuer),
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

static int verify(char *msg, size_t mlen, char *sig, size_t slen, EVP_PKEY *pkey, ngx_http_request_t *r)
{
  int result = -1;
  EVP_MD_CTX* ctx = NULL;
  const EVP_MD* md;
  int rc;

  if(!msg || !mlen || !sig || !slen || !pkey) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to load key: %d\n", result);
    return result;
  }

  ctx = EVP_MD_CTX_create();
  if(ctx == NULL) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "EVP_MD_CTX_create failed, error 0x%lx\n", ERR_get_error());
    return 1;
  }

  md = EVP_get_digestbyname("SHA256");
  if(md == NULL) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "EVP_get_digestbyname failed, error 0x%lx\n", ERR_get_error());
    return 1; /* failed */
  }

  rc = EVP_DigestInit_ex(ctx, md, NULL);
  if(rc != 1) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "EVP_DigestInit_ex failed, error 0x%lx\n", ERR_get_error());
    return 1; /* failed */
  }

  rc = EVP_DigestVerifyInit(ctx, NULL, md, NULL, pkey);
  if(rc != 1) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "EVP_DigestVerifyInit failed, error 0x%lx\n", ERR_get_error());
    return 1; /* failed */
  }

  rc = EVP_DigestVerifyUpdate(ctx, msg, mlen);
  if(rc != 1) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "EVP_DigestVerifyUpdate failed, error 0x%lx\n", ERR_get_error());
    return 1; /* failed */
  }

  ERR_clear_error();

  rc = EVP_DigestVerifyFinal(ctx, sig, slen);
  if(rc != 1) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "EVP_DigestVerifyFinal failed (1), error 0x%lx\n", ERR_get_error());
    return 1; /* failed */
  }

  result = 0;

  if(ctx) {
    EVP_MD_CTX_destroy(ctx);
    ctx = NULL;
  }

  return result;
}

static ngx_int_t ngx_http_jwt_handler(ngx_http_request_t *r)
{
  char *incoming_jwt;
  char *header, *signature, *body;
  const char *delim = "."; char *saveptr;
  char *encoded_header;
  int rc;
  char *msg;
  json_t *jwt_body; json_error_t jerr;

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

  asprintf((char **) &msg, "%s.%s", header, body);

  size_t slen = strlen((const char *) signature);
  size_t mlen = strlen((const char *) msg);

  ngx_str_t be_sig, bd_sig;
  ngx_str_t be_body, bd_body;
  be_sig.data = signature;
  be_sig.len = slen;

  bd_sig.len = ngx_base64_decoded_length(be_sig.len);
  bd_sig.data = calloc(bd_sig.len+1, sizeof(unsigned char));

  ngx_decode_base64url(&bd_sig, &be_sig);

  // verify signature
  rc = verify(msg, mlen, bd_sig.data, bd_sig.len, pubkey, r);

  if (rc != 0)
    return NGX_HTTP_UNAUTHORIZED;

  // parse body json
  be_body.data = body;
  be_body.len = strlen(body);

  bd_body.len = ngx_base64_decoded_length(be_body.len);
  bd_body.data = calloc(bd_body.len+1, sizeof(unsigned char));

  ngx_decode_base64url(&bd_body, &be_body);

  // check issuer
  jwt_body = json_loads((const char*)bd_body.data, 0, &jerr);

  if(jwt_body == NULL)
    return NGX_HTTP_UNAUTHORIZED;

  json_t *iss = json_object_get(jwt_body, "iss");
  const char *issuer;
  issuer = json_string_value(iss);

  if(strncmp(issuer, location_conf->issuer.data, location_conf->issuer.len))
    return NGX_HTTP_UNAUTHORIZED;

  // check expiry
  json_t *exp = json_object_get(jwt_body, "exp");
  unsigned long long expiry = (unsigned long long) json_integer_value(exp);
  unsigned long long current_time = (unsigned long long) time(NULL);
  int skew = strtoll((const char *) location_conf->skew.data, NULL, 10);

  if(current_time > (expiry + skew))
    return NGX_HTTP_UNAUTHORIZED;

  // check custom claims
  ngx_array_t *custom = location_conf->fields;
  int i; ngx_keyval_t *kv; json_t *claim; const char *claim_val;

  for(i = 0; i < custom->nelts; i++)
  {
    kv = (ngx_keyval_t *) &custom->elts[i];

    if ((kv->key != NULL) && (kv->val != NULL)) {

      // XXX: only first level for now
      claim = json_object_get(jwt_body, kv->key.data);

      if (claim == NULL)
        return NGX_HTTP_UNAUTHORIZED;

      claim_val = json_string_value(claim);

      if (strncmp(claim_val, kv->value.data, kv->value.len))
        return NGX_HTTP_UNAUTHORIZED;
    }
  }

  // XXX: should deallocate when erroring out early
  free(msg); free(bd_sig.data); free(bd_body.data); json_decref(jwt_body);

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
  conf->issuer.data = NULL;
  conf->issuer.len = 0;

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
  ngx_conf_merge_str_value(conf->issuer, prev->issuer, NULL);

  if (conf->fields == NULL) {
    conf->fields = prev->fields;
  }

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

EVP_PKEY *extract_pubkey(const char *exp, const char *modulus)
{
  ngx_str_t bd_modulus; ngx_str_t bd_exp;
  ngx_str_t be_modulus; ngx_str_t be_exp;
  BIGNUM *n, *e;

  be_modulus.data = (unsigned char *) modulus;
  be_modulus.len = strlen(modulus);

  bd_modulus.len = ngx_base64_decoded_length(be_modulus.len);
  bd_modulus.data = calloc(bd_modulus.len+1, sizeof(unsigned char));

  ngx_decode_base64url(&bd_modulus, &be_modulus);
  bd_modulus.data[bd_modulus.len+1] = '\0';

  be_exp.data = (unsigned char *) exp;
  be_exp.len = strlen(exp);

  bd_exp.len = ngx_base64_decoded_length(be_exp.len);
  bd_exp.data = calloc(bd_exp.len+1, sizeof(unsigned char));

  ngx_decode_base64url(&bd_exp, &be_exp);
  bd_exp.data[bd_exp.len+1] = '\0';

  n = BN_bin2bn(bd_modulus.data, bd_modulus.len, NULL);
  e = BN_bin2bn(bd_exp.data, bd_exp.len, NULL);

  free(bd_modulus.data); free(bd_exp.data);

  EVP_PKEY *pkey = EVP_PKEY_new();
  RSA *rsa = RSA_new();
  RSA_set0_key(rsa, n, e, NULL); // only pub key

  EVP_PKEY_assign_RSA(pkey, rsa);
  return pkey;
}

EVP_PKEY *setup_jwks(ngx_str_t jwks_file)
{
  EVP_PKEY *pkey;

  const char *modulus;
  const char *exponent;

  json_t *jwks; json_error_t jerr;
  jwks = json_load_file(jwks_file.data, JSON_DECODE_ANY, &jerr);

  // attempt to read a KeySet, if that fails, see if you can read a Key
  json_t *keys, *key_1, *n, *e;
  keys = json_object_get(jwks, "keys");

  if (keys == NULL) {
    n = json_object_get(jwks, "n");
    e = json_object_get(jwks, "e");
  } else { // XXX: just the first key for now
    key_1 = json_array_get(keys, 0);
    n = json_object_get(key_1, "n");
    e = json_object_get(key_1, "e");
  }

  exponent = json_string_value(e);
  modulus = json_string_value(n);

  // convert exponent and modulus to RSA key
  pkey = extract_pubkey(exponent, modulus);
  json_decref(jwks);

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
