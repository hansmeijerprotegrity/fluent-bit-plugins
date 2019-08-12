/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2018 Treasure Data Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_time.h>
#include "mbedtls/aes.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/pkcs5.h"
#if defined(WIN32) || defined (_WIN64)
#include <io.h>
#include <direct.h>
#include <share.h>
#else
#include <unistd.h>
#include <dirent.h>
#endif
#include <ctype.h>
typedef  FILE* P_FILE;

#include <errno.h>
#include <msgpack.h>
#include "filter_securedcnt.h"

#define PLUGIN_NAME "filter_securedcnt"
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_entropy_context entropy;

/* convert hex character to binary value */
int hexchartobin(const char chexvalue, char *out)
{
	if (out == NULL)
		return 0;

	if (chexvalue >= '0' && chexvalue <= '9') {
		*out = chexvalue - '0';
	} else if (chexvalue >= 'A' && chexvalue <= 'F') {
		*out = chexvalue - 'A' + 10;
	} else if (chexvalue >= 'a' && chexvalue <= 'f') {
		*out = chexvalue - 'a' + 10;
	} else {
		return 0;
	}

	return 1;
}

/* convert binary value to hex value */
int binarytohex(const unsigned char * bIndata, int indatalen, char * bOutdata, int outdatalen)
{
	int  i;

	if (bIndata == NULL || indatalen == 0)
		return 0;
	if ( (indatalen * 2 + 1) > outdatalen )
		return 0;

	for (i=0; i<indatalen; i++) {
		bOutdata[i*2]   = "0123456789ABCDEF"[bIndata[i] >> 4];
		bOutdata[i*2+1] = "0123456789ABCDEF"[bIndata[i] & 0x0F];
	}
	bOutdata[indatalen*2] = '\0';

	return 1;
}

/* convert hex string to binary value */
size_t hexstrtobin(const char *hexstr, int hexlen, unsigned char *pszout, int outLen)
{
	size_t iLen;
	char   b1;
	char   b2;
	size_t i;

	if (hexstr == NULL || *hexstr == '\0' || pszout == NULL)
  {
    flb_error("Error at start or string");  
		return 0;
  }

	iLen = strlen(hexstr);
	if (iLen % 2 != 0)
  {
    flb_error("Len is not modula 2");  
		return 0;
  }
  if(iLen != hexlen)
  {
    flb_error("Length is not equal to hexlen");  
		return 0;
  }
	iLen /= 2;

	for (i=0; i<iLen; i++) {
		if (!hexchartobin(hexstr[i*2], &b1) || !hexchartobin(hexstr[i*2+1], &b2)) {
			return 0;
		}
		(pszout)[i] = (b1 << 4) | b2;
	}
	return iLen;
}

static inline bool helper_msgpack_object_matches_str(msgpack_object * obj,
                                                     char *str, int len)
{
    char *key;
    int klen;

    if (obj->type == MSGPACK_OBJECT_BIN) {
        key = (char *) obj->via.bin.ptr;
        klen = obj->via.bin.size;
    }
    else if (obj->type == MSGPACK_OBJECT_STR) {
        key = (char *) obj->via.str.ptr;
        klen = obj->via.str.size;
    }
    else {
        return false;
    }

    return ((len == klen) && (strncmp(str, key, klen) == 0));
}

static inline bool kv_key_matches_str(msgpack_object_kv * kv,
                                      char *str, int len)
{
    return helper_msgpack_object_matches_str(&kv->key, str, len);
}

static inline int map_count_keys_matching_str(msgpack_object * map,
                                              char *str, int len)
{
    int i;
    int count = 0;

    for (i = 0; i < map->via.map.size; i++) {
        if (kv_key_matches_str(&map->via.map.ptr[i], str, len)) {
            count++;
        }
    }
    return count;
}

/* generate new aes key to protect the securedcnt value with */
static int generate_aes_key(struct securedcnt_ctx *ctx)
{
    int  ret = 0;
    mbedtls_entropy_init( &entropy );
    mbedtls_ctr_drbg_init( &ctr_drbg );  
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
        (unsigned char *) ctx->securedcnt_seed, strlen( ctx->securedcnt_seed ) ) ) != 0 )
    {
        flb_info(" failed\n ! mbedtls_ctr_drbg_init returned -0x%04x\n", -ret);
        flb_errno();
        return -1;
    }

    if( ( ret = mbedtls_ctr_drbg_random( &ctr_drbg, ctx->securedcnt_key, 32 ) ) != 0 )
    {
        flb_info(" failed\n ! mbedtls_ctr_drbg_init returned -0x%04x\n", -ret);
        flb_errno();
        return -1;
    }
    
    return ret;
    
}


/* try to read the key file, if it doesnt exist, we create a new key and file, also
   let the other function to generate a new securedcnt file also by setting new_securedcnt_file to 1 */
static int read_key_file(struct securedcnt_ctx *ctx)
{
    FILE* filehandle;
    char mode[10] = "r+";
    char modeW[10] = "w+";
    
    unsigned long fileLen;    
    int ret = -1;
    
    ctx->new_securedcnt_file = 0;
#if (defined(WIN32) || defined (_WIN64)) && (_MSC_VER >= 1400)
    errno_t nErrNo = 0;
#else
    int nErrNo = 0;
#endif

#if (defined(WIN32) || defined (_WIN64)) && (_MSC_VER >= 1400) /* VS 2005 */
    filehandle = _fsopen( ctx->securedcnt_key_file, mode, _SH_DENYWR );
    nErrNo = errno;
#else
    filehandle = fopen( ctx->securedcnt_key_file, mode );
    nErrNo = errno;
#endif
    if( 0 == filehandle )
    {
      ctx->new_securedcnt_file = 1;
      flb_info("Failed to read key file: %s, generating new keys", ctx->securedcnt_key_file);
      switch(nErrNo)
      {
          case EPERM:
              flb_info("Operation not permitted");
              break;
          case ENOENT:
              flb_info("File not found");
              break;
          case EACCES:
              flb_info("Permission denied");
              break;
          case ENAMETOOLONG:
              flb_info("Filename is too long");
              break;
          default:
              flb_info("Unknown error");
      }
      ret = generate_aes_key(ctx);
      if(ret == 0)
      {
#if (defined(WIN32) || defined (_WIN64)) && (_MSC_VER >= 1400) /* VS 2005 */
         filehandle = _fsopen( ctx->securedcnt_key_file, modeW, _SH_DENYWR );
         nErrNo = errno;
#else
         filehandle = fopen( ctx->securedcnt_key_file, modeW );
         nErrNo = errno;
#endif
         if( 0 != filehandle || 0 != ferror( filehandle ) )
         {
            fwrite(ctx->securedcnt_key, 1, 32, filehandle);
            fclose( filehandle );
            filehandle = 0;
         }
      }
    }
    else
    {
      fseek(filehandle, 0, SEEK_END);
      fileLen=ftell(filehandle);
      fseek(filehandle, 0, SEEK_SET);
      memset(ctx->securedcnt_key, 0, sizeof(ctx->securedcnt_key));
      fread(ctx->securedcnt_key, fileLen, 1, filehandle);
      fclose( filehandle );
      filehandle = 0;
      ret = 0;
    }
    return ret;
}

static int configure(struct securedcnt_ctx *ctx,
                         struct flb_filter_instance *f_ins)
{
    int ret;
    struct mk_list *head = NULL;
    struct mk_list *split;
    struct flb_config_prop *prop = NULL;
    /*struct modifier_key    *mod_key;*/
    struct modifier_record *mod_record;
    struct flb_split_entry *sentry;
    const char *str = NULL;

    str = flb_filter_get_property("securedcnt_key_file", f_ins);
    if(str != NULL)
    {
      flb_info("Using SECUREDCNT file: %s", str);
      strcpy(ctx->securedcnt_key_file, str);
    }
    else
    {
      flb_info("Using default securedcnt key file : %s", SECUREDCNT_KEY_FILE_DEFAULT);
      strcpy(ctx->securedcnt_key_file, SECUREDCNT_KEY_FILE_DEFAULT);
    }

    ret = read_key_file(ctx);
    if (ret != 0) {
        flb_free(ctx);
        return -1;
    }
        
    str = flb_filter_get_property("securedcnt_file", f_ins);
    if(str != NULL)
    {
      flb_info("Using SECUREDCNT file: %s", str);
      strcpy(ctx->securedcnt_file, str);
    }
    else
    {
      flb_info("Using default SECUREDCNT file: %s", SECUREDCNT_FILE_DEFAULT);
      strcpy(ctx->securedcnt_file, SECUREDCNT_FILE_DEFAULT);
    }

    str = flb_filter_get_property("securedcnt_field", f_ins);
    if(str != NULL)
    {
      flb_info("Using SECUREDCNT field: %s", str);
      strcpy(ctx->securedcnt_field, str);
    }
    else
    {
      flb_info("Using default SECUREDCNT field: %s", SECUREDCNT_FIELD_DEFAULT);
      strcpy(ctx->securedcnt_field, SECUREDCNT_FIELD_DEFAULT);
    }

    str = flb_filter_get_property("securedcnt_seed", f_ins);
    if(str != NULL)
    {
      flb_debug("Using this seed value for key generation: %s", str);
      strcpy(ctx->securedcnt_seed, str);
    }
    else
    {
      flb_debug("Using default seed value for key generation: %s", SECUREDCNT_FIELD_DEFAULT);
      strcpy(ctx->securedcnt_field, SECUREDCNT_FIELD_DEFAULT);
    }

    ctx->records_num = 0;

    /* Iterate all filter properties */
    mk_list_foreach(head, &f_ins->properties) {
        prop = mk_list_entry(head, struct flb_config_prop, _head);

        if (!strcasecmp(prop->key, "record")) {
            mod_record = flb_malloc(sizeof(struct modifier_record));
            if (!mod_record) {
                flb_errno();
                continue;
            }
            split = flb_utils_split(prop->val, ' ', 1);
            if (mk_list_size(split) != 2) {
                flb_error("[%s] invalid record parameters, expects 'KEY VALUE'",
                          PLUGIN_NAME);
                flb_free(mod_record);
                flb_utils_split_free(split);
                continue;
            }
            /* Get first value (field) */
            sentry = mk_list_entry_first(split, struct flb_split_entry, _head);
            mod_record->key = flb_strndup(sentry->value, sentry->len);
            mod_record->key_len = sentry->len;

            sentry = mk_list_entry_last(split, struct flb_split_entry, _head);
            mod_record->val = flb_strndup(sentry->value, sentry->len);
            mod_record->val_len = sentry->len;

            flb_utils_split_free(split);
            mk_list_add(&mod_record->_head, &ctx->records);
            ctx->records_num++;
        }
    }

    flb_debug("Records to add : %d", ctx->records_num);

    return 0;
}

static int delete_list(struct securedcnt_ctx *ctx)
{
    struct mk_list *tmp;
    struct mk_list *head;
    /*struct modifier_key *key;*/
    struct modifier_record *record;

    mk_list_foreach_safe(head, tmp, &ctx->records) {
        record = mk_list_entry(head, struct modifier_record,  _head);
        flb_free(record->key);
        flb_free(record->val);
        mk_list_del(&record->_head);
        flb_free(record);
    }

    return 0;
}


static int cb_securedcnt_init(struct flb_filter_instance *f_ins,
                                struct flb_config *config,
                                void *data)
{
    struct securedcnt_ctx *ctx = NULL;
    
    /* Create context */
    ctx = flb_malloc(sizeof(struct securedcnt_ctx));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    mk_list_init(&ctx->records);

    if ( configure(ctx, f_ins) < 0 ){
        delete_list(ctx);
        return -1;
    }

    flb_filter_set_context(f_ins, ctx);
    return 0;
}

static int make_bool_map(struct securedcnt_ctx *ctx, msgpack_object *map,
                             bool_map_t *bool_map, int map_num)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct mk_list *check = NULL;
    msgpack_object_kv *kv;
    struct modifier_key *mod_key;

    msgpack_object *key;
    int ret = map_num;
    int i;

    for (i=0; i<map_num; i++) {
        bool_map[i] = TO_BE_REMAINED;
    }
    bool_map[map_num] = TAIL_OF_ARRAY;/* tail of map */

    if (check != NULL){
        kv = map->via.map.ptr;
        for(i=0; i<map_num; i++){
            key = &(kv+i)->key;

            mk_list_foreach_safe(head, tmp, check) {
                mod_key = mk_list_entry(head, struct modifier_key,  _head);
                if (key->via.bin.size != mod_key->key_len &&
                    key->via.str.size != mod_key->key_len &&
                    mod_key->dynamic_key == FLB_FALSE) {
                    continue;
                }
                if (key->via.bin.size < mod_key->key_len &&
                    key->via.str.size < mod_key->key_len &&
                    mod_key->dynamic_key == FLB_TRUE) {
                    continue;
                }
                if ((key->type == MSGPACK_OBJECT_BIN &&
                     !strncasecmp(key->via.bin.ptr, mod_key->key,
                                  mod_key->key_len)) ||
                    (key->type == MSGPACK_OBJECT_STR &&
                     !strncasecmp(key->via.str.ptr, mod_key->key,
                                  mod_key->key_len))
                    ) {
                    break;
                }
            }
        }
    }

    return ret;
}


long long add64(long long b, long long c) {
  long long a = b + c;
  return a;
}


static int cb_securedcnt_filter(const void *data, size_t bytes,
                         const char *tag, int tag_len,
                         void **out_buf, size_t *out_size,
                         struct flb_filter_instance *f_ins,
                         void *context,  
                         struct flb_config *config)
{
    struct securedcnt_ctx *ctx = context;
    char is_modified = FLB_FALSE;
    size_t off = 0;
    int i;
    int removed_map_num  = 0;
    int map_num          = 0;
    bool_map_t bool_map[128];
    (void) f_ins;
    (void) config;
    struct flb_time tm;
    struct modifier_record *mod_rec;
    msgpack_sbuffer tmp_sbuf;
    msgpack_packer tmp_pck;
    msgpack_unpacked result;
    msgpack_object  *obj;
    msgpack_object_kv *kv;
    struct mk_list *tmp;
    struct mk_list *head;
    mbedtls_aes_context aes_enc, aes_dec;

    char szText[256];
    char texthex[256];
                    
    unsigned char iv[16];

    unsigned long fileLen;
    int  retcryptoop = 0;

#if (defined(WIN32) || defined (_WIN64)) && (_MSC_VER >= 1400)
    errno_t nErrNo = 0;
#else
    int nErrNo = 0;
#endif
    char mode[10] = "r+";
    char modeW[10] = "w+";
    FILE* filehandle;
    FILE* filehandleTmp;
    unsigned char line[MAX_FILE_BUF];
    int iMatch_securedcnt = 0;

    /*mbedtls_aes_init(&aes);*/
    mbedtls_aes_setkey_enc( &aes_enc, ctx->securedcnt_key, 256 );
    mbedtls_aes_setkey_dec( &aes_dec, ctx->securedcnt_key, 256 );

#if (defined(WIN32) || defined (_WIN64)) && (_MSC_VER >= 1400) /* VS 2005 */
    filehandle = _fsopen( ctx->securedcnt_file, mode, _SH_DENYWR );
    nErrNo = errno;
#else
    filehandle = fopen( ctx->securedcnt_file, mode );
    nErrNo = errno;
#endif
    if( 0 == filehandle || ctx->new_securedcnt_file == 1 )
    {
      if(ctx->new_securedcnt_file == 1)
      {
        flb_info("Generating new securedcnt file due to new key");
      }
      if( ENOENT == nErrNo )
      {
        flb_debug("No SECUREDCNT file found: %s, will try to create", ctx->securedcnt_file);
      }
      else if( EACCES == errno )
      {
        flb_debug("Access denied to SECUREDCNT file: %s", ctx->securedcnt_file);
      }
      else if( 0 != ferror( filehandle ) )
      {
        flb_info("Failed to access SECUREDCNT file: %s", ctx->securedcnt_file);
        ctx->dRecord = 0;
      }
    }
    else
    {
      fseek(filehandle, 0, SEEK_END);
      fileLen=ftell(filehandle);
      fseek(filehandle, 0, SEEK_SET);
      memset(line, 0, sizeof(line));
      memset(texthex, 0, sizeof(texthex));
      fread(texthex, fileLen, 1, filehandle);
      fclose( filehandle );
      filehandle = 0;
      memset(iv, 0 ,sizeof(iv));
      hexstrtobin(texthex, strlen(texthex), line, sizeof(line));

      retcryptoop = mbedtls_aes_crypt_cbc(&aes_dec, MBEDTLS_AES_DECRYPT, 16, iv, line, (unsigned char*)&ctx->dRecord );

      if(0 != retcryptoop )
      { 
         flb_info("Decrypt of SECUREDCNT file failed rc = %d", retcryptoop);
      }
      else
      {
         flb_info("Decrypt of SECUREDCNT file ok ");
      }
      flb_info("Record counter: %.f", ctx->dRecord);
    }
    flb_info("Record counter after decrypt: %.f", ctx->dRecord);
    /* Create temporal msgpack buffer */
    msgpack_sbuffer_init(&tmp_sbuf);
    msgpack_packer_init(&tmp_pck, &tmp_sbuf, msgpack_sbuffer_write);

    /* Iterate each item to know map number */
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off)) {
        map_num = 0;
        removed_map_num = 0;
        if (result.data.type != MSGPACK_OBJECT_ARRAY) {
            continue;
        }

        flb_time_pop_from_msgpack(&tm, &result, &obj);

        /* grep keys */
        iMatch_securedcnt = map_count_keys_matching_str(obj, ctx->securedcnt_field, strlen(ctx->securedcnt_field));
        if (obj->type == MSGPACK_OBJECT_MAP) {
            map_num = obj->via.map.size;
            removed_map_num = make_bool_map(ctx, obj,
                                            bool_map, obj->via.map.size);
        }
        else {
            continue;
        }

        if (removed_map_num != map_num) {
            is_modified = FLB_TRUE;
        }

        removed_map_num += ctx->records_num + 1;
        if (removed_map_num <= 0) {
            continue;
        }

        msgpack_pack_array(&tmp_pck, 2);
        flb_time_append_to_msgpack(&tm, &tmp_pck, 0);

        msgpack_pack_map(&tmp_pck, removed_map_num);
        kv = obj->via.map.ptr;
        for(i=0; bool_map[i] != TAIL_OF_ARRAY; i++) {
            if (bool_map[i] == TO_BE_REMAINED) {
                msgpack_pack_object(&tmp_pck, (kv+i)->key);
                msgpack_pack_object(&tmp_pck, (kv+i)->val);
            }
        }

        /* append record */
        if (ctx->records_num > 0) {
            is_modified = FLB_TRUE;
            mk_list_foreach_safe(head, tmp, &ctx->records) {
                mod_rec = mk_list_entry(head, struct modifier_record,  _head);
                msgpack_pack_str(&tmp_pck, mod_rec->key_len);
                flb_debug("Adding : %s -> %s", mod_rec->key, mod_rec->val);
                msgpack_pack_str_body(&tmp_pck,
                                      mod_rec->key, mod_rec->key_len);
                msgpack_pack_str(&tmp_pck, mod_rec->val_len);
                msgpack_pack_str_body(&tmp_pck,
                                      mod_rec->val, mod_rec->val_len);

            }
        }

        if(iMatch_securedcnt == 0)
        {
          is_modified = FLB_TRUE;
          msgpack_pack_str(&tmp_pck, strlen(ctx->securedcnt_field));
          flb_debug("Adding : %s -> %.f", ctx->securedcnt_field, ctx->dRecord);
          msgpack_pack_str_body(&tmp_pck,
                             ctx->securedcnt_field, strlen(ctx->securedcnt_field));
          msgpack_pack_uint64(&tmp_pck, ctx->dRecord);
          if(ctx->dRecord + 1 > MAX_SECUREDCNT_VALUE ) /* no garanties it is the correct ... */
          {
#if (defined(WIN32) || defined (_WIN64)) && (_MSC_VER >= 1400) /* VS 2005 */
             filehandleTmp = _fsopen( "switched_value.txt", modeW, _SH_DENYWR );
             nErrNo = errno;
#else
             filehandleTmp = fopen( "switched_value.txt", modeW );
             nErrNo = errno;
#endif
             if( 0 != filehandleTmp || 0 != ferror( filehandleTmp ) )
             {
                printf("trying to write ...\n");
                fprintf(filehandleTmp, "%f", ctx->dRecord);
                fclose( filehandleTmp );
                filehandleTmp = 0;
             }
             ctx->dRecord = 0;
          }
          else
          {
            ctx->dRecord++;
          }
        }

    }
    if (is_modified != FLB_TRUE) {
        /* Destroy the buffer to avoid more overhead */
        msgpack_sbuffer_destroy(&tmp_sbuf);
        return FLB_FILTER_NOTOUCH;
    }

    /* link new buffers */
    *out_buf  = tmp_sbuf.data;
    *out_size = tmp_sbuf.size;
 
#if (defined(WIN32) || defined (_WIN64)) && (_MSC_VER >= 1400) /* VS 2005 */
     filehandle = _fsopen( ctx->securedcnt_file, modeW, _SH_DENYWR );
     nErrNo = errno;
#else
     filehandle = fopen( ctx->securedcnt_file, modeW );
     nErrNo = errno;
#endif
     if( 0 != filehandle || 0 != ferror( filehandle ) )
     {
        memset(line,0,sizeof(line));
        memset(iv, 0 ,sizeof(iv));
        if(0 != mbedtls_aes_crypt_cbc(&aes_enc, MBEDTLS_AES_ENCRYPT, 16, iv, (unsigned char*)&ctx->dRecord, line ) )
          flb_info("Failed to encrypto SECUREDCNT value");
        memset(iv, 0 ,sizeof(iv));
        memset(szText,0,sizeof(szText));
        retcryptoop = mbedtls_aes_crypt_cbc(&aes_dec, MBEDTLS_AES_DECRYPT, 32, iv, (unsigned char*)line, (unsigned char*)szText );
        binarytohex(line, 16, texthex, sizeof(texthex));
        fwrite(texthex, 1, 32, filehandle);
        fclose( filehandle );
        filehandle = 0;
     }
    mbedtls_aes_free(&aes_enc);
    mbedtls_aes_free(&aes_dec);
    return FLB_FILTER_MODIFIED;
}

static int cb_securedcnt_exit(void *data, struct flb_config *config)
{
    struct securedcnt_ctx *ctx = data;

    if (ctx != NULL) {
        delete_list(ctx);
        flb_free(ctx);
    }
    return 0;
}

struct flb_filter_plugin filter_securedcnt_plugin = {
    .name         = "securedcnt",
    .description  = "Adds a record counter to field, and protects it",
    .cb_init      = cb_securedcnt_init,
    .cb_filter    = cb_securedcnt_filter,
    .cb_exit      = cb_securedcnt_exit,
    .flags        = 0
};
