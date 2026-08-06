#pragma once
/*
 * Minimal auth-client stub for unit testing.
 * Provides only the types and constants used by mail_alert_manager.hpp
 * and mail_alert_manager.cpp. Not a complete libESMTP auth-client implementation.
 */

typedef void* auth_context_t;

typedef struct auth_client_request
{
    unsigned int flags;
    const char*  prompt;
} auth_client_request, *auth_client_request_t;

#define AUTH_USER           0x0001u
#define AUTH_PASS           0x0002u
#define AUTH_PLUGIN_PLAIN   1
#define AUTH_PLUGIN_XOAUTH2 2

/* Callback typedef matching authinteract() signature in mail_alert_manager.cpp */
typedef int (*auth_interact_t)(auth_client_request_t request, char** result,
                                int fields, void* arg);

#ifdef __cplusplus
extern "C"
{
#endif

void           auth_client_init(void);
void           auth_client_exit(void);
auth_context_t auth_create_context(void);
void           auth_destroy_context(auth_context_t ctx);
int  auth_set_mechanism_flags(auth_context_t ctx, int mechanism, int flags);
int  auth_set_interact_cb(auth_context_t ctx, auth_interact_t cb, void* arg);

#ifdef __cplusplus
}
#endif
