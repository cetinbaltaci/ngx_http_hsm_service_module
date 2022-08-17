#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <stdarg.h>

#include "json-c/json.h"

#include "hsm.h"

typedef struct {
    ngx_str_t user;
    ngx_str_t pass;
    ngx_str_t slotname;
    ngx_str_t encdecKey;
    ngx_str_t signKey;
    ngx_str_t verifyKey;
    ngx_uint_t slotId;
} hsm_service_loc_conf_t;

typedef struct {
    ngx_str_t libname;
    ngx_str_t confname;
} hsm_service_main_conf_t;

typedef struct {
    unsigned long long int transaction_id ;
    unsigned long type ;
    char *body_data ;
} reponse_data_t ;

const char *ENCDEC_PATH_NAME = "/encdec" ;
const char *SIGNVER_PATH_NAME = "/signver" ;

typedef enum {
    OP_TYPE_NONE,
    OP_TYPE_ENCDEC,
    OP_TYPE_SIGNVER
} OP_TYPE_e ;

#define LOG_TAG " {HSMSERVICE} "

#define my_ngx_log_error(level, log, err, fmt, ...)                                        \
    ngx_log_error_core(NGX_LOG_DEBUG, log, err, LOG_TAG # fmt, ##__VA_ARGS__)

static char *ngx_http_hsm_service(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_hsm_service_handler(ngx_http_request_t *r);

static void *ngx_http_hsm_service_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_hsm_service_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) ;


static void *ngx_http_hsm_service_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_hsm_service_init_main_conf (ngx_conf_t *cf, void *cnf);

static ngx_int_t ngx_http_hsm_service_encrypt_decrypt_data(ngx_http_request_t *r, unsigned long slotId, const char* user, const char* pass,
    const char* keyName, ngx_str_t in_base64str, ngx_str_t *outStr, ngx_int_t *resCode, char type);

static ngx_int_t ngx_http_hsm_service_sign_verify_data(ngx_http_request_t *r, unsigned long slotId, const char* user, const char* pass,
                const char* keyName, ngx_str_t in_base64str, ngx_str_t *outStr, ngx_int_t *resCode, char type) ;

static ngx_command_t ngx_http_hsm_service_commands[] = {

    { 
        ngx_string("hsm_service"), 
        NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS, 
        ngx_http_hsm_service,
        0,
        0,
        NULL
    },

    {
        ngx_string("hsm_service_user"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(hsm_service_loc_conf_t, user),
        NULL
    },

    {
        ngx_string("hsm_service_pass"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(hsm_service_loc_conf_t, pass),
        NULL
    },

    {
        ngx_string("hsm_service_slotname"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(hsm_service_loc_conf_t, slotname),
        NULL
    },


    {
        ngx_string("hsm_service_encdec_key"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(hsm_service_loc_conf_t, encdecKey),
        NULL
    },

    {
        ngx_string("hsm_service_sign_key"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(hsm_service_loc_conf_t, signKey),
        NULL
    },

    {
        ngx_string("hsm_service_verify_key"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(hsm_service_loc_conf_t, verifyKey),
        NULL
    },
    
    {
        ngx_string("hsm_service_lib"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(hsm_service_main_conf_t, libname),
        NULL
    },


    {
        ngx_string("hsm_service_conf"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(hsm_service_main_conf_t, confname),
        NULL
    },


    ngx_null_command 
};


static ngx_http_module_t ngx_http_hsm_service_module_ctx = {
    NULL, /* preconfiguration */
    NULL, /* postconfiguration */

    ngx_http_hsm_service_create_main_conf, /* create main configuration */
    ngx_http_hsm_service_init_main_conf, /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    ngx_http_hsm_service_create_loc_conf, /* create location configuration */
    ngx_http_hsm_service_merge_loc_conf /* merge location configuration */
};

/* Module definition. */
ngx_module_t ngx_http_hsm_service_module = {
    NGX_MODULE_V1,
    &ngx_http_hsm_service_module_ctx, /* module context */
    ngx_http_hsm_service_commands, /* module directives */
    NGX_HTTP_MODULE, /* module type */
    NULL, /* init master */
    NULL, /* init module */
    NULL, /* init process */
    NULL, /* init thread */
    NULL, /* exit thread */
    NULL, /* exit process */
    NULL, /* exit master */
    NGX_MODULE_V1_PADDING
};

ngx_buf_t *body_buf = NULL;


char *getValueFromArgs(char *args, const char *key) 
{
    char *token = strtok(args, "=") ;
    char *value = NULL;

    while(token) {
        if (strcmp(token, key ) == 0 ) {
            value = strtok(NULL, "=") ;
            break ;
        }
        strtok(NULL, "=") ; 
        token = strtok(NULL, "=") ;
    }
    return value ;
}

static reponse_data_t *getReqBodyString(OP_TYPE_e opType, ngx_http_request_t *r) 
{
    ngx_chain_t *in = NULL;
    int len = 0;

    if (r->request_body == NULL) {
        return NULL;
    }

    for (in = r->request_body->bufs; in; in = in->next) {
        len += ngx_buf_size(in->buf);
    }

    if (len == 0 ) return NULL ;

    u_char *p = (u_char *)ngx_pcalloc(r->connection->pool, len + 1);
    char *rbody = (char *)p ;

    for (in = r->request_body->bufs; in; in = in->next) {
        len = in->buf->last - in->buf->pos;
        p = ngx_cpymem(p, in->buf->pos, len) ;
    }

    struct json_object *jobj;
    jobj = json_tokener_parse(rbody);
    if (!jobj) {
        my_ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "JSON Parse error!" ) ;
        return NULL ;
    }
    
    struct json_object *tranIdObj;
    json_object_object_get_ex(jobj, "transactionId", &tranIdObj);
    if (!tranIdObj){
        my_ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "JSON Error! 'transactionId' not found" ) ;
        return NULL ;
    }
    
    struct json_object *typeIdObj;
    json_object_object_get_ex(jobj, "type", &typeIdObj);
    if (!typeIdObj) {
        my_ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "JSON Error! 'type' not found" ) ;
        return NULL ;
    }

    struct json_object *dataObj;
    json_object_object_get_ex(jobj, "data", &dataObj);
    if (!dataObj) {
        my_ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "JSON Error! 'data' not found" ) ;
        return NULL ;
    }
    len = json_object_get_string_len(dataObj);
    if (!len){
        my_ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "JSON Error! 'data' is empty" ) ;
        return NULL ;
    }

    reponse_data_t *reponse_data = (reponse_data_t *)ngx_pcalloc(r->connection->pool, sizeof(reponse_data_t));
    reponse_data->type = json_object_get_uint64(typeIdObj);
    reponse_data->transaction_id = json_object_get_uint64(tranIdObj) ;
    reponse_data->body_data = (char *)ngx_pcalloc(r->connection->pool, len + 1 );
    ngx_memcpy(reponse_data->body_data, json_object_get_string(dataObj), len) ;

    my_ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "getReqBodyString, type: %d transaction_id:%d dataLen: %d" , reponse_data->type, reponse_data->transaction_id, len) ;

    ngx_pfree(r->connection->pool, rbody) ;
    return reponse_data ;
}

static ngx_chain_t *prepareResponse(ngx_http_request_t *r, const char* msg) 
{
    const char RESP_CONTENT_TYPE[] = "application/json";
    
    ngx_buf_t *b;
    ngx_chain_t *out;
    
    r->headers_out.content_type.len = sizeof(RESP_CONTENT_TYPE) - 1;
    r->headers_out.content_type.data = (u_char *) RESP_CONTENT_TYPE;

    b = ngx_pcalloc(r->connection->pool, sizeof(ngx_buf_t));

    out = ngx_pcalloc(r->connection->pool, sizeof(ngx_chain_t));
    out->buf = b;
    out->next = NULL;



    b->pos = (u_char *)msg;
    b->last = (u_char *)msg + strlen(msg) ; 

    b->memory = 1;
    b->last_buf = 1;

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = strlen(msg) ;

    return out ;
}

static ngx_int_t ngx_http_hsm_service_sign_verify_data(ngx_http_request_t *r, unsigned long slotId, const char* user, const char* pass,
                const char* keyName, ngx_str_t in_base64str, ngx_str_t *outStr, ngx_int_t *resCode, char type) 
{
    ngx_int_t ret = NGX_ERROR ;
    ngx_str_t in_str ;

    in_str.len = ngx_base64_decoded_length(in_base64str.len);
    in_str.data = (u_char *) ngx_pcalloc(r->connection->pool, in_str.len + 1  ) ;
    
    ret = ngx_decode_base64(&in_str, &in_base64str);
    my_ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "ngx_http_hsm_service_sign_verify_data -> Base64 Decode Ret: %d", ret); 
    
    *resCode = ret ;

    if (ret == NGX_OK) {
        CK_RV ret_hsm = CKR_GENERAL_ERROR ;
        if (type == 0) {
            ngx_str_t outBuf = ngx_null_string;
            ret_hsm = HSMSign(slotId, user, pass, keyName, in_str.data, in_str.len, &(outBuf.data), &(outBuf.len)); 
            if (ret_hsm == CKR_OK &&  outBuf.len > 0 && outBuf.data ) {
                outStr->len = ngx_base64_encoded_length(outBuf.len) ;
                outStr->data = ngx_pcalloc(r->connection->pool, outStr->len + 1 ) ;
                ngx_encode_base64(outStr, &outBuf) ;
            } else 
                ret = NGX_ERROR ;
            
            if (outBuf.data) free(outBuf.data);
        }else if (type == 1) {
            ngx_str_t sign_str ;
            sign_str.len = 256 ;
            in_str.len -= sign_str.len ;
            sign_str.data = &in_str.data[in_str.len] ;
            ret_hsm = HSMVerify(slotId, user, pass, keyName, in_str.data, in_str.len, sign_str.data, sign_str.len);
            
            if (ret_hsm == CKR_OK) {
                ngx_str_set(outStr, "Verify: OK");
            } else {
                ngx_str_set(outStr, "Verify: Failed");
            }     
        }else 
            ret = NGX_ERROR ;
        
        *resCode = (ngx_int_t)ret_hsm ;
        my_ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "%s KeyLabel: %s HSMRet: %d NGX_ret: %d", 
                        (type == 0) ? "HSMSign" :  (type == 1) ? "HSMVerify" : "UNKNOWN" , 
                        keyName, ret_hsm, ret); 
    } 

    ngx_pfree(r->connection->pool, in_str.data );

    return ret ;
}

static ngx_int_t ngx_http_hsm_service_encrypt_decrypt_data(ngx_http_request_t *r, unsigned long slotId, const char* user, const char* pass,
    const char* keyName, ngx_str_t in_base64str, ngx_str_t *outStr, ngx_int_t *resCode, char type) 
{
    
    ngx_int_t ret = NGX_ERROR ;
    ngx_str_t in_str ;

    in_str.len = ngx_base64_decoded_length(in_base64str.len);
    in_str.data = (u_char *) ngx_pcalloc(r->connection->pool, in_str.len + 1  ) ;

    ret = ngx_decode_base64(&in_str, &in_base64str);
    my_ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "ngx_http_hsm_service_encrypt_decrypt_data -> Base64 Decode Ret: %d",  ret); 
    *resCode = ret ;
    if (ret == NGX_OK) {
        ngx_str_t outBuf = ngx_null_string;
        CK_RV ret_hsm = CKR_GENERAL_ERROR ;
        if (type == 'E')
            ret_hsm = HSMEncryptWithAES(slotId, user, pass, keyName,
                in_str.data, in_str.len, &(outBuf.data), &(outBuf.len)); 
        else if (type == 'D')
            ret_hsm = HSMDecryptWithAES(slotId, user, pass, keyName,
                in_str.data, in_str.len, &(outBuf.data), &(outBuf.len)); 
        else 
            ret = NGX_ERROR ;
        
        if (ret_hsm == CKR_OK &&  outBuf.len > 0 && outBuf.data ) {
            outStr->len = ngx_base64_encoded_length(outBuf.len) ;
            outStr->data = ngx_pcalloc(r->connection->pool, outStr->len + 1 ) ;
            ngx_encode_base64(outStr, &outBuf) ;
            ret = NGX_OK ;
        } else 
            ret = NGX_ERROR ;
        if (outBuf.data) free(outBuf.data);
        *resCode = (ngx_int_t)ret_hsm ;
        my_ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "%s KeyLabel: %s HSMRet: %d NGX_ret: %d", 
                        (type == 'E') ? "HSMEncryptWithAES" :  (type == 'D') ? "HSMDecryptWithAES" : "UNKNOWN" , 
                        keyName, ret_hsm, ret);
    }

    ngx_pfree(r->connection->pool, in_str.data );

    return ret ;
}

static OP_TYPE_e getOpType(ngx_http_request_t *r) {
    char *pathName = (char *) ngx_pcalloc( r->connection->pool, (r->uri_end - r->uri_start) + 1 ) ;
    ngx_memcpy(pathName, r->uri_start,  (r->uri_end - r->uri_start)) ;
    const char *opName = strrchr(pathName, '/') ;
    my_ngx_log_error(NGX_LOG_INFO,  r->connection->log, 0, "opName: %s", opName);
    
    OP_TYPE_e opType = OP_TYPE_NONE ;

    if (strcmp(opName, ENCDEC_PATH_NAME) == 0 )
        opType = OP_TYPE_ENCDEC ;
    else if (strcmp(opName, SIGNVER_PATH_NAME) == 0 )
        opType = OP_TYPE_SIGNVER;  

    ngx_pfree(r->connection->pool, pathName) ;

    return opType ;
}

static void ngx_http_hsm_service_parse_send(ngx_http_request_t *r) 
{
    hsm_service_loc_conf_t *loc_conf = (hsm_service_loc_conf_t*) ngx_http_get_module_loc_conf(r, ngx_http_hsm_service_module) ;

    if (!loc_conf) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (loc_conf->slotname.data && loc_conf->slotname.len > 0 && loc_conf->slotId == NGX_CONF_UNSET_UINT) {
        loc_conf->slotId = HSMGetSlotID((const char*)loc_conf->slotname.data );
        my_ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "Slot Name: %s ID:%d", loc_conf->slotname.data, loc_conf->slotId);
    }

    if (loc_conf->slotId == NGX_CONF_UNSET_UINT){
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        my_ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "Wrong SlotName: %s", loc_conf->slotname.data);
        return;
    }

    OP_TYPE_e opType =  getOpType(r);
    if (opType == OP_TYPE_NONE) {
        ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
        my_ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "Wrong Operator Type: %d", (int)opType);
        return;
    }

    reponse_data_t *resData = getReqBodyString(opType, r) ;
    if (!resData) {
        ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
        my_ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "Body is NULL");
        return;
    }

    ngx_str_t dest = ngx_null_string;
    ngx_str_t in_base64str  = {.len = strlen(resData->body_data), .data = (u_char*) resData->body_data};
    ngx_int_t ret = NGX_OK ;
    ngx_int_t hsm_ret = NGX_ERROR ;

    if (opType == OP_TYPE_ENCDEC) {
        my_ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "OP_TYPE_ENCDEC , Type: %d, keyLabel: %s",  resData->type, (const char *)loc_conf->encdecKey.data );
        ret = ngx_http_hsm_service_encrypt_decrypt_data(r, (unsigned long)loc_conf->slotId, (const char *)loc_conf->user.data, 
                (const char *)loc_conf->pass.data, (const char *)loc_conf->encdecKey.data, in_base64str, &dest, &hsm_ret, resData->type) ;
    } else if (opType == OP_TYPE_SIGNVER) {

        const char *key_label = (resData->type == 0  ) ? (const char *)loc_conf->signKey.data : 
                                (resData->type == 1 ) ? (const char *)loc_conf->verifyKey.data : NULL ;
        
        my_ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "OP_TYPE_SIGNVER , Type: %d, keyLabel: %s",  resData->type, key_label );
        ret = ngx_http_hsm_service_sign_verify_data(r, (unsigned long)loc_conf->slotId, (const char *)loc_conf->user.data, 
                (const char *)loc_conf->pass.data, key_label, in_base64str, &dest, &hsm_ret, resData->type) ;
    } else {
        ngx_str_set(&dest, "Err: Wrong Op Type") ;
    }
    
    ngx_chain_t *out = NULL;
    if (ret == NGX_OK && dest.len > 0 && dest.data) {
        json_object *root = json_object_new_object();
        json_object_object_add(root, "transactionId", json_object_new_uint64(resData->transaction_id));
        json_object_object_add(root, "resCode", json_object_new_int( hsm_ret));
        json_object_object_add(root, "data", json_object_new_string( (const char*) dest.data));
        out = prepareResponse(r, json_object_to_json_string(root))  ;
        ngx_pfree(r->connection->pool,  dest.data) ;
        json_object_object_del(root, "transactionId") ;
        json_object_object_del(root, "resCode") ;
        json_object_object_del(root, "data") ;
    }

    ngx_pfree(r->connection->pool, resData->body_data) ;
    ngx_pfree(r->connection->pool, resData);

    if (!out)  {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
    } else {
        ngx_http_send_header(r);
        ngx_int_t rc = ngx_http_output_filter(r, out);  

        ngx_http_finalize_request(r, rc);

        ngx_pfree(r->connection->pool, out->buf);
        ngx_pfree(r->connection->pool, out);
    }
}


static ngx_int_t ngx_http_hsm_service_handler(ngx_http_request_t *r)
{
    if ( !(r->method & NGX_HTTP_POST) ) {
		return NGX_HTTP_NOT_ALLOWED;
	}

    ngx_int_t rc = ngx_http_read_client_request_body(r, ngx_http_hsm_service_parse_send);

    if (rc == NGX_ERROR) {
        return rc;
    }

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
#if (nginx_version < 1002006) ||                                             \
        (nginx_version >= 1003000 && nginx_version < 1003009)
            r->main->count--;
#endif       
        return rc;
    }

    return NGX_DONE;
}

static char *ngx_http_hsm_service(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf; 
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_hsm_service_handler;

    return NGX_CONF_OK;
}

static void *ngx_http_hsm_service_create_loc_conf(ngx_conf_t *cf)
{
    hsm_service_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(hsm_service_loc_conf_t));
    if (conf == NULL) return NULL;

    conf->slotId = NGX_CONF_UNSET_UINT ;

    return conf;
}

static char *ngx_http_hsm_service_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    hsm_service_loc_conf_t *prev = (hsm_service_loc_conf_t *)parent;
    hsm_service_loc_conf_t *conf = (hsm_service_loc_conf_t *)child;

    ngx_conf_merge_str_value(conf->user, prev->user, "");
    ngx_conf_merge_str_value(conf->pass, prev->pass, "");
    ngx_conf_merge_str_value(conf->slotname, prev->slotname, "");
    ngx_conf_merge_str_value(conf->encdecKey, prev->encdecKey, "");
    ngx_conf_merge_str_value(conf->signKey, prev->signKey, "");
    ngx_conf_merge_str_value(conf->verifyKey, prev->verifyKey, "");
    
    return NGX_CONF_OK;
}

static void *ngx_http_hsm_service_create_main_conf(ngx_conf_t *cf) 
{
    hsm_service_main_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(hsm_service_main_conf_t));
    if (conf == NULL)
        return NULL;

    return conf;
}

static char *ngx_http_hsm_service_init_main_conf (ngx_conf_t *cf, void *cnf) 
{
    hsm_service_main_conf_t *conf = (hsm_service_main_conf_t *)cnf;

    my_ngx_log_error(NGX_LOG_NOTICE,  cf->log, 0, "LibName : %s",  (const char *)conf->libname.data);
    my_ngx_log_error(NGX_LOG_NOTICE,  cf->log, 0, "ConfName : %s", (const char *)conf->confname.data);

    long int rv =  HSMOpen((const char *)conf->libname.data, (const char *)conf->confname.data);
    my_ngx_log_error(NGX_LOG_NOTICE,  cf->log, 0, "HSMOpen -> ret : %d",rv);

    return NGX_CONF_OK; 
}
