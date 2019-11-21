/*
Copyright 2018 Satish Srinivasan

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/*
 * Implements signing using openssl
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

static ngx_int_t ngx_http_token_handler(ngx_http_request_t *r);
static void ngx_http_token_body_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_token_init(ngx_conf_t *cf);
static void *ngx_http_token_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_token_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static void ngx_http_token_deinit(ngx_cycle_t *cf);

EVP_PKEY *setup_rsa_key(ngx_str_t);
EVP_PKEY *fetch_rsa_key(ngx_str_t);

struct key {
  ngx_str_t keyname;
  EVP_PKEY *loaded_key;
};

#define MAXHASH 10
static struct key *keytable[MAXHASH];

int asprintf(char **strp, const char *fmt, ...);

// config for the RSA key in location
typedef struct {
  ngx_str_t keyfile; /* keyfile to sign the jwt token */
  ngx_str_t jwt_header; /* jwt header */
  ngx_str_t default_exp; /* default expiry to use (in seconds) */
} token_loc_conf_t;

static ngx_command_t ngx_http_token_commands[] = {
  {
    ngx_string("keyfile"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(token_loc_conf_t, keyfile),
    NULL
  },
  {
    ngx_string("jwt_header"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(token_loc_conf_t, jwt_header),
    NULL
  },
  {
    ngx_string("default_exp"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(token_loc_conf_t, default_exp),
    NULL
  },
  ngx_null_command
};

static ngx_http_module_t ngx_http_token_module_ctx = {
    NULL,                          /* preconfiguration */
    ngx_http_token_init,           /* postconfiguration */

    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */

    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */

    ngx_http_token_create_loc_conf,  /* create location configuration */
    ngx_http_token_merge_loc_conf    /* merge location configuration */
};

ngx_module_t  ngx_http_token_module = {
  NGX_MODULE_V1,
    &ngx_http_token_module_ctx,    /* module context */
    ngx_http_token_commands,       /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    ngx_http_token_deinit,         /* exit process */
    NULL,                          /* exit master */
  NGX_MODULE_V1_PADDING
};

int sign(const unsigned char* msg, size_t mlen, unsigned char** sig, size_t* slen, EVP_PKEY* pkey, ngx_http_request_t *r)
{

  /* Returned to caller */
  int result = 1;
  EVP_MD_CTX* ctx = NULL;
  const EVP_MD* md;
  int rc; size_t req;

  if(!msg || !mlen || !sig || !pkey) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to load key: %d\n", result);
    return result;
  }

  if(*sig) OPENSSL_free(*sig);

  *sig = NULL;
  *slen = 0;

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

  rc = EVP_DigestSignInit(ctx, NULL, md, NULL, pkey);
  if(rc != 1) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "EVP_DigestSignInit failed, error 0x%lx\n", ERR_get_error());
    return 1; /* failed */
  }

  rc = EVP_DigestSignUpdate(ctx, msg, mlen);
  if(rc != 1) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "EVP_DigestSignUpdate failed, error 0x%lx\n", ERR_get_error());
    return 1; /* failed */
  }

  req = 0;
  rc = EVP_DigestSignFinal(ctx, NULL, &req);
  if(rc != 1) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "EVP_DigestSignFinal failed (1), error 0x%lx\n", ERR_get_error());
    return 1; /* failed */
  }

  if(!(req > 0)) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "EVP_DigestSignFinal failed (2), error 0x%lx\n", ERR_get_error());
    return 1; /* failed */
  }

  *sig = OPENSSL_malloc(req);
  if(*sig == NULL) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "OPENSSL_malloc failed, error 0x%lx\n", ERR_get_error());
    return 1; /* failed */
  }

  *slen = req;
  rc = EVP_DigestSignFinal(ctx, *sig, slen);
  if(rc != 1) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "EVP_DigestSignFinal failed (3), return code %d, error 0x%lx\n", rc, ERR_get_error());
    return 1; /* failed */
  }

  if(rc != 1) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "EVP_DigestSignFinal failed, mismatched signature sizes %ld, %ld", req, *slen);
    return 1; /* failed */
  }

  result = 0;

  if(ctx) {
    EVP_MD_CTX_destroy(ctx);
    ctx = NULL;
  }

  return result;
}

static void ngx_http_token_body_handler(ngx_http_request_t *r)
{
  unsigned char *jwt, *sjwt;
  int jwt_len, body_len, sjwt_len;

  unsigned long long exp_l = 0, nbf_l = 0;

  unsigned char *body = NULL;
  unsigned char *sig = NULL;
  unsigned char *json_body = NULL;

  int json_body_len;
  size_t slen = 0;
  ngx_buf_t *b; ngx_chain_t out;

  int rc; unsigned char *outb;

  // setup rsa key from location config
  token_loc_conf_t *location_conf = ngx_http_get_module_loc_conf(r, ngx_http_token_module);
  EVP_PKEY *key = fetch_rsa_key(location_conf->keyfile);

  ngx_str_t be_header, be_buf, be_sig;
  ngx_str_t bd_header, bd_buf, bd_sig;

  if (r->request_body == NULL || r->request_body->bufs == NULL) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
      "token: empty buffer found. aborted.");
    ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
    return;
  }

  // read query params for nbf and exp (current time in epoch secs)
  // token behavior: if exp is provided use exp OR use (current time + default_exp))
  //                 if nbf is provided use nbf or use current time

  ngx_str_t exp = {0, NULL}, nbf = {0, NULL};

  ngx_http_arg(r, (u_char *) "nbf", 3, &nbf);
  ngx_http_arg(r, (u_char *) "exp", 3, &exp);

  if(nbf.data != NULL) {
    nbf_l = strtoll((const char *) nbf.data, NULL, 10);
  } else {
    nbf_l = (unsigned long long) time(NULL);
  }

  if(exp.data != NULL) {
    exp_l = nbf_l + strtoll((const char *) exp.data, NULL, 10);
  } else {
    exp_l = nbf_l + strtoll((const char *) location_conf->default_exp.data, NULL, 10);
  }

  // read body from the ngx buffer
  body_len = (r->request_body->bufs->buf->last - r->request_body->bufs->buf->start + 1);
  body = ngx_pcalloc(r->pool, body_len * sizeof(unsigned char));
  strncpy((char *) body, (const char *) r->request_body->bufs->buf->start, body_len);
  body[body_len-1] = '\0';

  // set exp, nbf, iat
  json_t *klaims; json_error_t jerr;
  klaims = json_loads((const char *)body, 0, &jerr);

  // validate if the json presented is not malformed
  if(klaims == NULL) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
      "token: invalid json presented. aborted.");
    ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
    return;
  }

  json_object_set_new(klaims, "exp", json_integer((json_int_t) exp_l));
  json_object_set_new(klaims, "nbf", json_integer((json_int_t) nbf_l));
  json_object_set_new(klaims, "iat", json_integer((json_int_t) nbf_l));

  json_body = (unsigned char *) json_dumps(klaims, JSON_COMPACT);
  json_body_len = strlen((const char *) json_body);

  // setup structures for base64 encoding
  bd_header = location_conf->jwt_header;
  bd_buf.len = json_body_len; bd_buf.data = json_body;

  be_header.len = ngx_base64_encoded_length(bd_header.len);
  be_header.data = ngx_pcalloc(r->pool, be_header.len * sizeof(unsigned char));

  be_buf.len = ngx_base64_encoded_length(bd_buf.len);
  be_buf.data = ngx_pcalloc(r->pool, be_buf.len * sizeof(unsigned char));

  ngx_encode_base64url(&be_header, &bd_header);
  ngx_encode_base64url(&be_buf, &bd_buf);

  asprintf((char **) &jwt, "%s.%s", be_header.data, be_buf.data);
  jwt_len = strlen((const char *) jwt);

  // sign the jwt
  rc = sign(jwt, jwt_len, &sig, &slen, key, r);

  if(rc != 0) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
      "token: unable to sign blob.");
    ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
  }

  bd_sig.len = slen; bd_sig.data = sig;

  be_sig.len = ngx_base64_encoded_length(bd_sig.len);
  be_sig.data = ngx_pcalloc(r->pool, be_sig.len * sizeof(unsigned char));

  ngx_encode_base64url(&be_sig, &bd_sig);

  // setup the signed jwt
  asprintf((char **) &sjwt, "%s.%s", jwt, be_sig.data);
  sjwt_len = strlen((const char *) sjwt);

  outb = ngx_palloc(r->pool, sjwt_len);
  ngx_memcpy(outb, sjwt, sjwt_len);

  free(sig); free(sjwt); free(jwt); json_decref(klaims);

  // send it to caller
  b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
  out.buf = b; out.next = NULL;

  b->pos = outb;
  b->last = outb + sjwt_len;

  b->memory = 1;
  b->last_buf = 1; /* there will be no more buffers in the request */

  r->headers_out.status = NGX_HTTP_OK;
  r->headers_out.content_length_n = sjwt_len;

  ngx_str_t content_type = ngx_string("text/plain");
  r->headers_out.content_type = content_type;

  ngx_http_send_header(r);
  ngx_http_output_filter(r, &out);
  return;
}

static ngx_int_t ngx_http_token_handler(ngx_http_request_t *r)
{
  // fetch conf
  token_loc_conf_t *location_conf = ngx_http_get_module_loc_conf(r, ngx_http_token_module);

  // don't process the request if keyfile is not present (not our request)
  if (location_conf->keyfile.data == NULL) {
    return NGX_DECLINED;
  }

  if (!(r->method == NGX_HTTP_POST)) {
    return NGX_HTTP_NOT_ALLOWED;
  }

  r->request_body_in_single_buf = 1;
  ngx_int_t rc = ngx_http_read_client_request_body(r, ngx_http_token_body_handler);

  if (rc == NGX_AGAIN) {
    return NGX_DONE;
  }

  return rc;
}

EVP_PKEY *fetch_rsa_key(ngx_str_t keyfile)
{
  unsigned long hv = ((unsigned long) ngx_hash_key_lc(keyfile.data, keyfile.len) % MAXHASH);
  if (keytable[hv] == NULL) {
    keytable[hv] = malloc(sizeof(struct key));
    keytable[hv]->keyname = keyfile;
    keytable[hv]->loaded_key = setup_rsa_key(keyfile);
  }

  return keytable[hv]->loaded_key;
}

EVP_PKEY *setup_rsa_key(ngx_str_t keyfile)
{
  RSA *rsakey;
  EVP_PKEY *pkey;
  FILE *fp;

  pkey = EVP_PKEY_new();
  fp = fopen((const char * __restrict__) keyfile.data, "r");

  if (!fp)
    return NULL;

  PEM_read_PrivateKey(fp, &pkey, NULL, NULL);
  fclose(fp);

  {
    rsakey = EVP_PKEY_get1_RSA(pkey);

    if(!RSA_check_key(rsakey))
      return NULL;
  }

  return pkey;
}

static void *ngx_http_token_create_loc_conf(ngx_conf_t *cf) {
  token_loc_conf_t *conf;

  conf = ngx_pcalloc(cf->pool, sizeof(token_loc_conf_t));
  if (conf == NULL)
    return NULL;

  conf->keyfile.data = NULL;
  conf->keyfile.len = 0;

  return conf;
}

static char *ngx_http_token_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
  token_loc_conf_t *prev = parent;
  token_loc_conf_t *conf = child;

  ngx_conf_merge_str_value(conf->keyfile, prev->keyfile, NULL);
  return NGX_CONF_OK;
}

static ngx_int_t ngx_http_token_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_token_handler;

    return NGX_OK;
}

static void ngx_http_token_deinit(ngx_cycle_t *cy)
{
  { int i;
    for(i = 0; i<MAXHASH; i++) free(keytable[i]); }

  return;
}
