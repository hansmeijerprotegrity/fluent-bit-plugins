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

#ifndef FLB_FILTER_SECUREDCNT_H
#define FLB_FILTER_SECUREDCNT_H
#define SECUREDCNT_PKCS5_FILE_DEFAULT "securedcnt.cnt"
#define SECUREDCNT_KEY_FILE_DEFAULT "key.bin"
#define SECUREDCNT_FILE_DEFAULT "securedcnt.cnt"
#define SECUREDCNT_FIELD_DEFAULT "securedcnt_cnt"
#define SECUREDCNT_SEED_DEFAULT "fluent-bit"
#define MAX_FILE_BUF 1024
#define MAX_SECUREDCNT_VALUE 9007199254740992
unsigned char securedcnt_key[32];

struct modifier_record {
    char *key;
    char *val;
    int  key_len;
    int  val_len;
    struct mk_list _head;
};

struct modifier_key {
    char *key;
    int   key_len;
    int   dynamic_key;
    struct mk_list _head;
};

struct securedcnt_ctx {
    int records_num;
    double dRecord;
    char szRecord[20];
    char securedcnt_key_file[2048];
    char securedcnt_file[2048];
    char securedcnt_field[256];
    char securedcnt_seed[256];
    int  new_securedcnt_file;
    unsigned char securedcnt_key[32];
    struct mk_list records;
};

typedef enum {
    TO_BE_REMOVED = 0,
    TO_BE_REMAINED = 1,
    TAIL_OF_ARRAY = 2
} bool_map_t;


#endif /* FLB_FILTER_SECUREDCNT_H */
