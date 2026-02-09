#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../../include/user_mgmt.h"

#define USER_LINE_MAX 512

typedef struct node {
    user_record rec;
    struct node *next;
} node;

static node *head = NULL;
static int dirty = 0;
static struct stat user_db_stat = {0};
static bool user_db_stat_valid = false;

static void clear_list(void) {
    for (node *n = head; n;) { node *tmp = n->next; free(n); n = tmp; }
    head = NULL;
}

static bool parse_mapped_users(const char *data, size_t len) {
    const char *ptr = data;
    const char *end = data + len;

    while (ptr < end) {
        const char *line_end = memchr(ptr, '\n', end - ptr);
        size_t line_len = line_end ? (size_t)(line_end - ptr) : (size_t)(end - ptr);
        while (line_len > 0 && (ptr[line_len - 1] == '\r' || ptr[line_len - 1] == '\n')) {
            line_len--;
        }

        if (line_len == 0) {
            ptr = line_end ? line_end + 1 : end;
            continue;
        }

        char line[USER_LINE_MAX];
        size_t copy_len = line_len < sizeof(line) ? line_len : sizeof(line) - 1;
        memcpy(line, ptr, copy_len);
        line[copy_len] = '\0';

        char *u = strtok(line, ",\r\n");
        char *p = strtok(NULL, ",\r\n");
        char *r = strtok(NULL, ",\r\n");
        if (!u || !p || !r) {
            ptr = line_end ? line_end + 1 : end;
            continue;
        }

        user_record rec = {0};
        strncpy(rec.user, u, sizeof rec.user - 1);
        strncpy(rec.pass_hash, p, sizeof rec.pass_hash - 1);
        strncpy(rec.role, r, sizeof rec.role - 1);

        node *n = calloc(1, sizeof *n);
        if (!n) return false;
        n->rec = rec;
        n->next = head;
        head = n;

        ptr = line_end ? line_end + 1 : end;
    }

    return true;
}

bool user_store_load(const char *path) {
    clear_list();
    if (path == NULL) return false;

    int fd = open(path, O_RDONLY);
    if (fd < 0) return false;

    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        return false;
    }

    bool ok = true;
    if (st.st_size > 0) {
        void *map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (map == MAP_FAILED) {
            ok = false;
        } else {
            ok = parse_mapped_users((const char *)map, (size_t)st.st_size);
            munmap(map, st.st_size);
        }
    }

    close(fd);

    if (!ok) {
        clear_list();
        return false;
    }

    dirty = 0;
    user_db_stat = st;
    user_db_stat_valid = true;
    return true;
}

static bool write_all(const char *path) {
    FILE *f = fopen(path, "w");
    if (!f) return false;
    for (node *n = head; n; n = n->next) {
        if (fprintf(f, "%s,%s,%s\n", n->rec.user, n->rec.pass_hash, n->rec.role) < 0) {
            fclose(f);
            return false;
        }
    }
    if (fclose(f) != 0) return false;
    dirty = 0;
    return true;
}

bool user_store_reload_if_modified(const char *path) {
    if (path == NULL) return false;
    struct stat st;
    if (stat(path, &st) != 0) return false;
    if (user_db_stat_valid &&
        st.st_mtime == user_db_stat.st_mtime &&
        st.st_ctime == user_db_stat.st_ctime &&
        st.st_size == user_db_stat.st_size) {
        return true;
    }
    return user_store_load(path);
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
    n->rec = *rec;
    n->next = head;
    head = n;
    dirty = 1;
    return true;
}

bool user_store_update(const char *user, const user_record *rec) {
    node *n = find_node(user);
    if (!n || !rec) return false;
    n->rec = *rec;
    dirty = 1;
    return true;
}

bool user_store_delete(const char *user) {
    node **pp = &head;
    while (*pp) {
        if (strcmp((*pp)->rec.user, user) == 0) {
            node *dead = *pp;
            *pp = dead->next;
            free(dead);
            dirty = 1;
            return true;
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

void user_store_close(void) {
    clear_list();
    dirty = 0;
    user_db_stat_valid = false;
}
