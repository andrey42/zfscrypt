#include "zfscrypt_context.h"

#include <libzfs.h>
#include <security/pam_appl.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <security/pam_modutil.h>
#include <string.h>
#include <syslog.h>

#include "zfscrypt_config.h"
#include "zfscrypt_err.h"
#include "zfscrypt_utils.h"

// public methods

zfscrypt_err_t zfscrypt_context_begin(zfscrypt_context_t* self, pam_handle_t* handle, unused int flags, int argc, const char** argv) {
    self->pam = handle;
    self->libzfs = libzfs_init();
    self->debug = false;
    self->runtime_dir = ZFSCRYPT_DEFAULT_RUNTIME_DIR;
    self->user = NULL;
    // taken from PAM_MODUTIL_DEF_PRIVS macro from <security/pam_modutil.h>
    self->privs = (struct pam_modutil_privs) {
        .grplist = self->groups,
        .number_of_groups = PAM_MODUTIL_NGROUPS,
        .allocated = 0,
        .old_gid = -1,
        .old_uid = -1,
        .is_dropped = 0
    };
    zfscrypt_parse_args(self, argc, argv);
    zfscrypt_err_t err = zfscrypt_context_pam_get_user(self, &self->user);
    zfscrypt_context_log_err(self, err);
    return err;
}

int zfscrypt_context_end(zfscrypt_context_t* self, zfscrypt_err_t err) {
    libzfs_fini(self->libzfs);
    return zfscrypt_err_for_pam(err);
}

void zfscrypt_context_log(zfscrypt_context_t* self, const int level, const char* format, ...) {
    if (self->pam == NULL)
        return;
    va_list args;
    va_start(args, format);
    pam_vsyslog(self->pam, level, format, args);
    va_end(args);
}

zfscrypt_err_t zfscrypt_context_log_err(zfscrypt_context_t* self, zfscrypt_err_t err) {
    const int level = err.value == 0 ? LOG_DEBUG : LOG_ERR;
    if (level == LOG_DEBUG && !self->debug)
        return err;
    const char* domain = NULL;
    switch (err.type) {
        case ZFSCRYPT_ERR_OS:
            domain = "OS";
            break;
        case ZFSCRYPT_ERR_PAM:
            domain = "PAM";
            break;
        case ZFSCRYPT_ERR_ZFS:
            domain = "ZFS";
            break;
        default:
            domain = "UNKNOWN";
            break;
    }
    zfscrypt_context_log(
        self, level, "%s: %s: %s (%s:%d:%s)",
        domain, err.message, err.description, err.file, err.line, err.function
    );
    return err;
}

zfscrypt_err_t zfscrypt_context_persist_token(zfscrypt_context_t* self) {
    const char* token = NULL;
    zfscrypt_err_t err = zfscrypt_context_pam_items_get_token(self, &token);
    if (!err.value)
        token = secure_dup(token);
    if (!err.value && token == NULL)
        err = zfscrypt_err_os(errno, "Memory allocation failed");
    if (!err.value)
        err = zfscrypt_context_pam_data_set_token(self, token);
    zfscrypt_context_log_err(self, err);
    return err;
}

zfscrypt_err_t zfscrypt_context_restore_token(zfscrypt_context_t* self, const char** token) {
    const zfscrypt_err_t err = zfscrypt_context_pam_data_get_token(self, token);
    zfscrypt_context_log_err(self, err);
    return err;
}

zfscrypt_err_t zfscrypt_context_clear_token(zfscrypt_context_t* self) {
    const zfscrypt_err_t err = zfscrypt_context_pam_data_clear_token(self);
    zfscrypt_context_log_err(self, err);
    return err;
}

zfscrypt_err_t zfscrypt_context_get_tokens(zfscrypt_context_t* self, const char** old_token, const char** new_token) {
    zfscrypt_err_t err = zfscrypt_context_pam_items_get_old_token(self, old_token);
    if (!err.value)
        err = zfscrypt_context_pam_items_get_token(self, new_token);
    zfscrypt_context_log_err(self, err);
    return err;
}

zfscrypt_err_t zfscrypt_context_drop_privs(zfscrypt_context_t* self) {
    const struct passwd* const pwd = pam_modutil_getpwnam(self->pam, self->user);
    zfscrypt_err_t err = zfscrypt_err_pam(0, "Dropping privileges");
    if (pwd == NULL)
        err = zfscrypt_err_pam(PAM_SESSION_ERR, "Could not get passwd entry for user");
    if (!err.value)
        err = zfscrypt_err_pam(
            pam_modutil_drop_priv(self->pam, &self->privs, pwd),
            "Dropping privileges"
        );
    zfscrypt_context_log_err(self, err);
    return err;
}

zfscrypt_err_t zfscrypt_context_regain_privs(zfscrypt_context_t* self) {
    const int status = pam_modutil_regain_priv(self->pam, &self->privs);
    const zfscrypt_err_t err = zfscrypt_err_pam(status, "Regaining privileges");
    zfscrypt_context_log_err(self, err);
    return err;
}

// private methods

void zfscrypt_parse_args(zfscrypt_context_t* self, const int argc, const char** argv) {
    for (int i = 0; i < argc; ++i) {
        const char* item = argv[i];
        if (streq(item, ZFSCRYPT_CONTEXT_ARG_DEBUG)) {
            self->debug = true;
            zfscrypt_context_log(self, LOG_DEBUG, "Debug mode on");
        } else if (strncmp(item, ZFSCRYPT_CONTEXT_ARG_RUNTIME_DIR, ZFSCRYPT_CONTEXT_ARG_RUNTIME_DIR_LEN) == 0) {
            self->runtime_dir = &item[ZFSCRYPT_CONTEXT_ARG_RUNTIME_DIR_LEN];
            zfscrypt_context_log(self, LOG_DEBUG, "Using runtime dir %s", self->runtime_dir);
        } else {
            zfscrypt_context_log(self, LOG_WARNING, "Unknown module argument %s", item);
        }
    }
}

zfscrypt_err_t zfscrypt_context_pam_get_user(zfscrypt_context_t* self, const char** user) {
    const int err = pam_get_user(self->pam, user, NULL);
    assert(err || user != NULL);
    return zfscrypt_err_pam(err, "Getting user name from pam");
}

zfscrypt_err_t zfscrypt_context_pam_items_get_token(zfscrypt_context_t* self, const char** token) {
    const int err = pam_get_item(self->pam, PAM_AUTHTOK, (const void**) token);
    assert(err || token != NULL);
    return zfscrypt_err_pam(err, "Getting current password from pam");
}

zfscrypt_err_t zfscrypt_context_pam_items_get_old_token(zfscrypt_context_t* self, const char** token) {
    const int err = pam_get_item(self->pam, PAM_OLDAUTHTOK, (const void**) token);
    assert(err || token != NULL);
    return zfscrypt_err_pam(err, "Getting old token from pam items");
}

zfscrypt_err_t zfscrypt_context_pam_ask_token(zfscrypt_context_t* self, const char** token) {
    const int err = pam_get_authtok(self->pam, PAM_AUTHTOK, token, "Decryption key:");
    assert(err || token != NULL);
    return zfscrypt_err_pam(err, "Asking pam for token");
}

zfscrypt_err_t zfscrypt_context_pam_data_set_token(zfscrypt_context_t* self, const char* token) {
    const int err = pam_set_data(self->pam, ZFSCRYPT_CONTEXT_PAM_DATA_TOKEN, (void*) token, secure_cleanup);
    return zfscrypt_err_pam(err, "Storing token in pam data");
}

zfscrypt_err_t zfscrypt_context_pam_data_get_token(zfscrypt_context_t* self, const char** token) {
    const int err = pam_get_data(self->pam, ZFSCRYPT_CONTEXT_PAM_DATA_TOKEN, (const void**) token);
    assert(err || token != NULL);
    return zfscrypt_err_pam(err, "Getting token from pam data");
}

zfscrypt_err_t zfscrypt_context_pam_data_clear_token(unused zfscrypt_context_t* self) {
    const int err = pam_set_data(self->pam, ZFSCRYPT_CONTEXT_PAM_DATA_TOKEN, NULL, NULL);
    return zfscrypt_err_pam(err, "Clearing token from pam data");
}

// private constants

const char ZFSCRYPT_CONTEXT_ARG_DEBUG[] = "debug";
const char ZFSCRYPT_CONTEXT_ARG_RUNTIME_DIR[] = "runtime_dir=";
// -1 to remove trailing null byte
const size_t ZFSCRYPT_CONTEXT_ARG_RUNTIME_DIR_LEN = sizeof(ZFSCRYPT_CONTEXT_ARG_RUNTIME_DIR) - 1;
const char ZFSCRYPT_CONTEXT_PAM_DATA_TOKEN[] = "zfsrypt_token";
