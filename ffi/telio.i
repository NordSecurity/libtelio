%module libtelio

%{
#include "../../telio.h"
%}

%rename("%(camelcase)s") "";
%rename("$ignore", fullname=1) __telio_force_export;
%rename("$ignore", fullname=1) __telio_generate_thread_panic;
%rename("$ignore", fullname=1) __telio_generate_stack_panic;


#if SWIGJAVA || SWIGCSHARP
%rename("$ignore", regexmatch$name=".*_cb") "";
%rename("$ignore", regexmatch$name=".*_fn") "";
#endif

#if SWIGJAVA
%rename("%(strip:[TELIO_])s", %$isenumitem) "";
#endif

#if SWIGCSHARP
/* XXX: This will break in some future release: https://github.com/swig/swig/issues/1806
 *
 * TL;DR: popen(3) invokes sh(1) to run the command, which is exactly what SWIG
 *        uses. However, Debian (and, in particular, derivatives) use dash as
 *        /bin/sh, where bash-isms (<<< here strings) don’t work:
 *
 *            sh: 1: Syntax error: redirection unexpected
 *
 * There is currently no good replacement other than writing unwieldy regular
 * expressions.
 */
%rename("%(command:cs_rename<<<)s", %$isenumitem) "";
#endif

%include "telio_types.h";

%include "teliogo.i"
%include "teliojava.i"
%include "teliocs.i"

struct telio {};

%extend telio {
    static enum telio_adapter_type get_default_adapter();


#if defined(__ANDROID__)
    telio(const char* features, telio_event_cb events, enum telio_log_level level, telio_logger_cb logger, telio_protect_cb protect) {
        telio *t;
        if (TELIO_RES_OK != telio_new_with_protect(&t, features, events, level, logger, protect)) {
            return NULL;
        }
        return t;
    }
#else
    telio(const char* features, telio_event_cb events, enum telio_log_level level, telio_logger_cb logger) {
        telio *t;
        if (TELIO_RES_OK != telio_new(&t, features, events, level, logger)) {
            return NULL;
        }
        return t;
    }
#endif

    ~telio() {
        telio_destroy($self);
    }

    enum telio_result start(const char *private_key,
                            enum telio_adapter_type adapter);

    enum telio_result start_named(const char *private_key,
                            enum telio_adapter_type adapter,
                            const char *name);


#if !defined(_WIN32)
    enum telio_result start_with_tun(const char *private_key,
                                           enum telio_adapter_type adapter,
                                           int tun);
#endif

    enum telio_result enable_magic_dns(const char *forward_servers);

    enum telio_result disable_magic_dns();

    enum telio_result stop();

    unsigned long long get_adapter_luid();

    enum telio_result set_private_key(const char *private_key);

    const char* get_private_key();

#if defined(__linux__)
    enum telio_result set_fwmark(unsigned int fwmark);
#endif

    enum telio_result notify_network_change(const char *notify_info);

    enum telio_result connect_to_exit_node(const char *public_key,
                                           const char *allowed_ips,
                                           const char *endpoint);

    enum telio_result disconnect_from_exit_node(const char *public_key);

    enum telio_result disconnect_from_exit_nodes();

    enum telio_result set_meshnet(const char *cfg);

    enum telio_result set_meshnet_off();

    %newobject generate_secret_key;
    const char* generate_secret_key();

    %newobject generate_public_key;
    const char* generate_public_key(const char *secret_key);

    %newobject get_status_map;
    const char* get_status_map();

    %newobject get_last_error;
    const char* get_last_error();

    %newobject get_version_tag;
    static char* get_version_tag();

    %newobject get_commit_sha;
    static char* get_commit_sha();
};

