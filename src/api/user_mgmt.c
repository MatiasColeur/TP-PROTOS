#include "../../include/user_mgmt.h"

typedef struct node {
    user_record rec;
    struct node *next;
} node;

static node *head = NULL;
static int dirty = 0;

static void clear_list(void) {
    for (node *n = head; n;) { node *tmp = n->next; free(n); n = tmp; }
    head = NULL;
}

bool user_store_load(const char *path) {
    clear_list();
    FILE *f = fopen(path, "r");
    if (!f) return false;
    char line[256];
    while (fgets(line, sizeof line, f)) {
        user_record rec = {0};
        char *u = strtok(line, ",\r\n");
        char *p = strtok(NULL, ",\r\n");
        char *r = strtok(NULL, ",\r\n");
        if (!u || !p || !r) continue;
        strncpy(rec.user, u, sizeof rec.user - 1);
        strncpy(rec.pass_hash, p, sizeof rec.pass_hash - 1);
        strncpy(rec.role, r, sizeof rec.role - 1);
        node *n = calloc(1, sizeof *n);
        if (!n) { fclose(f); return false; }
        n->rec = rec; n->next = head; head = n;
    }
    fclose(f);
    dirty = 0;
    return true;
}

static bool write_all(const char *path) {
    FILE *f = fopen(path, "w");
    if (!f) return false;
    for (node *n = head; n; n = n->next) {
        if (fprintf(f, "%s,%s,%s\n", n->rec.user, n->rec.pass_hash, n->rec.role) < 0) {
            fclose(f); return false;
        }
    }
    if (fclose(f) != 0) return false;
    dirty = 0;
    return true;
}

bool user_store_save(const char *path) {
    if (!dirty) return true;
    return write_all(path);
}

static node *find_node(const char *user) {
    for (node *n = head; n; n = n->next)
        if (strcmp(n->rec.user, user) == 0) return n;
    return NULL;
}

bool user_store_add(const user_record *rec) {
    if (!rec || find_node(rec->user)) return false;
    node *n = calloc(1, sizeof *n);
    if (!n) return false;
    n->rec = *rec; n->next = head; head = n; dirty = 1;
    return true;
}

bool user_store_update(const char *user, const user_record *rec) {
    node *n = find_node(user);
    if (!n || !rec) return false;
    n->rec = *rec; dirty = 1; return true;
}

bool user_store_delete(const char *user) {
    node **pp = &head;
    while (*pp) {
        if (strcmp((*pp)->rec.user, user) == 0) {
            node *dead = *pp; *pp = dead->next; free(dead); dirty = 1; return true;
        }
        pp = &(*pp)->next;
    }
    return false;
}

const user_record *user_store_find(const char *user) {
    node *n = find_node(user);
    return n ? &n->rec : NULL;
}

size_t user_store_list(user_record *out, size_t max_out) {
    size_t count = 0;
    for (node *n = head; n && count < max_out; n = n->next)
        out[count++] = n->rec;
    return count;
}

void user_store_close(void) { clear_list(); dirty = 0; }
