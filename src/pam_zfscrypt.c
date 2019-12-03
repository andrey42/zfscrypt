#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <security/pam_modutil.h>
#include <string.h>
#include <syslog.h>

#include "zfscrypt_context.h"
#include "zfscrypt_dataset.h"
#include "zfscrypt_err.h"
#include "zfscrypt_session.h"
#include "zfscrypt_utils.h"

/*
 * Gets ephemeral authentication token (aka user password) from pam and stores it in pam data
 * to retrieve it later in pam_sm_open_session.
 */
extern int pam_sm_authenticate(pam_handle_t* handle, int flags, int argc, const char** argv) {
    zfscrypt_context_t context;
    zfscrypt_err_t err = zfscrypt_context_begin(&context, handle, flags, argc, argv);
    if (!err.value)
        err = zfscrypt_context_drop_privs(&context);
    if (!err.value)
        err = zfscrypt_context_persist_token(&context);
    if (context.privs.is_dropped)
        (void) zfscrypt_context_regain_privs(&context);
    return zfscrypt_context_end(&context, err);
}

/*
 * In this function we check that the user is allowed in the system. We already know
 * that he's authenticated, but we could apply restrictions based on time of the day,
 * resources in the system etc. For zfscrypt this is a no-op.
 */
extern int pam_sm_acct_mgmt(unused pam_handle_t* handle, unused int flags, unused int argc, unused const char** argv) {
    return PAM_IGNORE;
}

/*
 * We could have many more information of the user other then username and password.
 * For example, get a kerberos ticket. For zfscrypt this is a no-op.
 */
extern int pam_sm_setcred(unused pam_handle_t* handle, unused int flags, unused int argc, unused const char** argv) {
    return PAM_IGNORE;
}

/*
 * Counts active sessions. Executes zfs load-key and zfs mount on all user datasets
 * if it's the first session.
 */
extern int pam_sm_open_session(pam_handle_t* handle, int flags, int argc, const char** argv) {
    zfscrypt_context_t context;
    zfscrypt_err_t err = zfscrypt_context_begin(&context, handle, flags, argc, argv);
    int counter = 0;
    if (!err.value)
        err = zfscrypt_context_log_err(
            &context,
            zfscrypt_session_counter_update(&counter, context.runtime_dir, context.user, +1)
        );
    if (counter == 1) {
        // This is the first session for the user. Unlock and mount the filesystems.
        const char* token = NULL;
        if (!err.value)
            err = zfscrypt_context_drop_privs(&context);
        if (!err.value)
            err = zfscrypt_context_restore_token(&context, &token);
        if (!err.value)
            err = zfscrypt_dataset_unlock_all(&context, token);
        if (context.privs.is_dropped)
            (void) zfscrypt_context_regain_privs(&context);
    }
    (void) zfscrypt_context_clear_token(&context);
    return zfscrypt_context_end(&context, err);
}

/*
 * Counts active sessions. Executes zfs umount and zfs unload-key if it's the last session.
 */
extern int pam_sm_close_session(pam_handle_t* handle, int flags, int argc, char const** argv) {
    zfscrypt_context_t context;
    zfscrypt_err_t err = zfscrypt_context_begin(&context, handle, flags, argc, argv);
    int counter = 0;
    if (!err.value)
        err = zfscrypt_context_log_err(
            &context,
            zfscrypt_session_counter_update(&counter, context.runtime_dir, context.user, -1)
        );
    if (counter == 0) {
        // The last session has been closed. Unmount and lock the filesystems.
        if (!err.value)
            err = zfscrypt_context_drop_privs(&context);
        if (!err.value)
            err = zfscrypt_dataset_lock_all(&context);
        if (context.privs.is_dropped)
            (void) zfscrypt_context_regain_privs(&context);
        if (context.free_inodes)
            (void) free_reclaimable_inodes();
    }
    return zfscrypt_context_end(&context, err);
}

/*
 * Reads old and new authentication token from pam and executes zfs change-key on all user datasets
 * in order to keep encryption key and login password in sync.
 */
extern int pam_sm_chauthtok(pam_handle_t* handle, int flags, int argc, char const** argv) {
    if (flags & PAM_PRELIM_CHECK) {
        // Should return PAM_TRY_AGAIN if not all pre requirements for changing the password are met
        return PAM_SUCCESS;
    }
    if (flags & PAM_UPDATE_AUTHTOK) {
        zfscrypt_context_t context;
        zfscrypt_err_t err = zfscrypt_context_begin(&context, handle, flags, argc, argv);
        const char* old_token = NULL;
        const char* new_token = NULL;
        if (!err.value)
            err = zfscrypt_context_drop_privs(&context);
        if (!err.value)
            err = zfscrypt_context_get_tokens(&context, &old_token, &new_token);
       // Unfortunately we cant prevent a password change here. All we can do is warn the user.
        if (!err.value && strlen(new_token) < 8)
            pam_error(
                context.pam,
                "Warning: Password to short for ZFS encryption. "
                "Minimum length of eight characters required. "
                "Login password and encryption key are out of sync."
            );
            err = zfscrypt_err_pam(PAM_AUTHTOK_ERR, "password to short");
        if (!err.value)
            err = zfscrypt_dataset_update_all(&context, old_token, new_token);
        if (context.privs.is_dropped)
            (void) zfscrypt_context_regain_privs(&context);
        return zfscrypt_context_end(&context, err);
    }
    return PAM_SERVICE_ERR;
}
