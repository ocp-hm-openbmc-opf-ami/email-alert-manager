#include "auth-client.h"
#include "libesmtp.h"

/*
 * No-op stubs for libesmtp and auth-client functions.
 * Allows mail_alert_manager.cpp to compile and link without the real
 * libesmtp library. smtp_start_session return value is controlled by
 * setSmtpStartSessionResult() for testing success/failure paths.
 */

static int g_smtpStartResult = 0; /* default: failure */

void setSmtpStartSessionResult(int success)
{
    g_smtpStartResult = success;
}

smtp_session_t smtp_create_session(void)
{
    return nullptr;
}

void smtp_destroy_session(smtp_session_t /*session*/) {}

smtp_message_t smtp_add_message(smtp_session_t /*session*/)
{
    return nullptr;
}

void smtp_set_monitorcb(smtp_session_t /*session*/, smtp_monitorcb_t /*cb*/,
                        void* /*arg*/, int /*headers*/)
{}

int smtp_set_timeout(smtp_session_t /*session*/, int /*which*/, long /*value*/)
{
    return 1;
}

int smtp_starttls_enable(smtp_session_t /*session*/, smtp_starttls_t /*how*/)
{
    return 1;
}

int smtp_starttls_set_ctx(smtp_session_t /*session*/, void* /*ssl_ctx*/)
{
    return 1;
}

int smtp_set_server(smtp_session_t /*session*/, const char* /*hostport*/)
{
    return 1;
}

void smtp_set_eventcb(smtp_session_t /*session*/, smtp_eventcb_t /*cb*/,
                      void* /*arg*/)
{}

void smtp_auth_set_context(smtp_session_t /*session*/, void* /*authctx*/) {}

int smtp_set_reverse_path(smtp_message_t /*message*/, const char* /*mailbox*/)
{
    return 1;
}

int smtp_set_header(smtp_message_t /*message*/, const char* /*header*/, ...)
{
    return 1;
}

int smtp_set_header_option(smtp_message_t /*message*/, const char* /*header*/,
                           int /*option*/, ...)
{
    return 1;
}

void smtp_set_message_str(smtp_message_t /*message*/, void* /*str*/) {}

int smtp_start_session(smtp_session_t /*session*/)
{
    return g_smtpStartResult;
}

const smtp_status_t* smtp_message_transfer_status(smtp_message_t /*message*/)
{
    return nullptr;
}

void smtp_enumerate_recipients(smtp_message_t /*message*/,
                               smtp_enumerate_recipients_cb_t /*cb*/,
                               void* /*arg*/)
{}

smtp_recipient_t smtp_add_recipient(smtp_message_t /*message*/,
                                    const char* /*mailbox*/)
{
    return nullptr;
}

const smtp_status_t* smtp_recipient_status(smtp_recipient_t /*recipient*/)
{
    return nullptr;
}

void auth_client_init(void) {}

void auth_client_exit(void) {}

auth_context_t auth_create_context(void)
{
    return nullptr;
}

void auth_destroy_context(auth_context_t /*ctx*/) {}

int auth_set_mechanism_flags(auth_context_t /*ctx*/, int /*mechanism*/,
                             int /*flags*/)
{
    return 1;
}

int auth_set_interact_cb(auth_context_t /*ctx*/, auth_interact_t /*cb*/,
                         void* /*arg*/)
{
    return 1;
}
