#include "zfscrypt_utils.h"

#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

// public functions

void free_ptr(void* data) {
    free(*(void**) data);
}

void close_file(FILE** file) {
    if (*file != NULL) {
        const int err = fclose(*file);
        assert(err == 0);
    }
}

void close_fd(int const* fd) {
    if (*fd >= 0) {
        const int err = close(*fd);
        assert(err == 0);
    }
}

bool streq(const char* a, const char* b) {
    return strcmp(a, b) == 0;
}

bool strnq(const char* a, const char* b) {
    return strcmp(a, b) != 0;
}

char* strfmt(const char* format, ...) {
    va_list list;

    va_start(list, format);
    const size_t size = vsnprintf(NULL, 0, format, list) + 1;
    va_end(list);

    char* result = malloc(size);
    if (result == NULL) {
        return NULL;
    }

    va_start(list, format);
    vsprintf(result, format, list);
    va_end(list);

    return result;
}

int make_private_dir(const char* path) {
    int err = mkdir(path, 0700);
    if (err < 0 && errno != EEXIST)
        return -errno;
    err = chown(path, 0, 0);
    if (err < 0)
        return -errno;
    err = chmod(path, 0700);
    if (err < 0)
        return -errno;
    return 0;
}

int open_exclusive(const char* path, const int flags) {
    const int fd = open(path, flags, 0600);
    if (fd < 0)
        return -errno;
    const int err = flock(fd, LOCK_EX);
    if (err < 0)
        return -errno;
    return fd;
}

int free_reclaimable_inodes() {
    sync();
    defer(close_file) FILE* file = fopen("/proc/sys/vm/drop_caches", "w");
    if (file == NULL)
        return -errno;
    const int err = fprintf(file, "%s", "2");
    return err < 0 ? -errno : 0;
}

void secure_free(void* data, size_t size) {
    explicit_bzero(data, size);
    munlock(data, size);
    free(data);
}

void secure_cleanup(unused pam_handle_t* handle, void* data, unused int error_status) {
    const size_t size = strlen(data) + 1;
    secure_free(data, size);
}

void* secure_malloc(const size_t size) {
    void* data = malloc(size);
    if (data == NULL)
        return NULL;
    const int err = mlock(data, size);
    if (err == 0) {
        return data;
    } else {
        free(data);
        return NULL;
    }
}

void* secure_dup(void const* const data) {
    const size_t size = strlen(data) + 1;
    void* copy = secure_malloc(size);
    if (copy == NULL)
        return NULL;
    return memcpy(copy, data, size);
}
