#pragma once
#include <security/pam_modules.h>
#include <stdbool.h>
#include <stdio.h>

// public macros

// A poor mans RAII.
#define defer(destructor) __attribute__((__cleanup__(destructor)))

#define unused __attribute__((unused))

// public functions

void free_ptr(void* data);
void close_file(FILE** file);
void close_fd(int const* fd);

bool streq(const char* a, const char* b);
bool strnq(const char* a, const char* b);

char* strfmt(const char* format, ...);

// Creates new directory that only root can access.
int make_private_dir(const char* path);

// Opens file with exclusive lock.
int open_exclusive(const char* path, const int flags);

// Instructs kernel to free the reclaimable inodes and dentries.
// This has the effect of making encrypted directories whose keys are
// not present no longer accessible. Requires root privileges.
//
// Also see https://www.kernel.org/doc/Documentation/sysctl/vm.txt
int drop_filesystem_cache();

void* secure_malloc(const size_t size);

// Duplicates data into new memory region thats locked in RAM.
void* secure_dup(const void* const data);

// Overwrites the given memory region with zeros before unlocking and freeing it.
void secure_free(void* data, size_t size);

// Overwrites data with zeros before unlocking and freeing it.
void secure_cleanup(pam_handle_t* handle, void* data, int error_status);
