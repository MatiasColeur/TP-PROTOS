#ifndef USER_MGMT_H
#define USER_MGMT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char user[64];
    char pass_hash[128];   
    char role[32];
} user_record;

bool user_store_load(const char *csv_path);                
bool user_store_save(const char *csv_path);                
bool user_store_add(const user_record *rec);               
bool user_store_update(const char *user, const user_record *rec); 
bool user_store_delete(const char *user);                  
const user_record *user_store_find(const char *user);     
size_t user_store_list(user_record *out, size_t max_out); 
void user_store_close(void);                               
bool user_store_reload_if_modified(const char *csv_path);

#endif
