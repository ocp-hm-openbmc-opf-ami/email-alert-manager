#pragma once
/*
 * Minimal libesmtp stub for unit testing.
 * Provides only the types and constants used by mail_alert_manager.hpp
 * and mail_alert_manager.cpp. Not a complete libESMTP implementation.
 */

typedef void* smtp_session_t;
typedef void* smtp_message_t;
typedef void* smtp_recipient_t;

typedef struct smtp_status
{
    int         code;
    const char* text;
} smtp_status_t;

/*
 * Named enums (not typedefs) so that 'enum notify_flags' tag usage in
 * mail_alert_manager.hpp compiles correctly in C++.
 */
enum notify_flags
{
    Notify_NOTSET = 0
};

enum smtp_timeout
{
    Timeout_GREETING  = 0,
    Timeout_CONNECTED = 1
};

enum smtp_starttls_t
{
    Starttls_DISABLED = 0,
    Starttls_ENABLED  = 1,
    Starttls_REQUIRED = 2
};

/* Event codes */
#define SMTP_EV_CONNECT                  1
#define SMTP_EV_MAILSTATUS               2
#define SMTP_EV_RCPTSTATUS               3
#define SMTP_EV_MESSAGEDATA              4
#define SMTP_EV_MESSAGESENT              5
#define SMTP_EV_DISCONNECT               6
#define SMTP_EV_WEAK_CIPHER              7
#define SMTP_EV_STARTTLS_OK              8
#define SMTP_EV_INVALID_PEER_CERTIFICATE 9
#define SMTP_EV_NO_PEER_CERTIFICATE      10
#define SMTP_EV_WRONG_PEER_CERTIFICATE   11
#define SMTP_EV_NO_CLIENT_CERTIFICATE    12

/* Monitor callback writing flag */
#define SMTP_CB_HEADERS 1

/* Header option flags */
#define Hdr_OVERRIDE 1

/* Callback typedefs that match the signatures used in mail_alert_manager.cpp */
typedef void (*smtp_monitorcb_t)(const char* buf, int buflen, int writing,
                                 void* arg);
typedef void (*smtp_eventcb_t)(smtp_session_t session, int event_no,
                               void* arg, ...);
typedef void (*smtp_enumerate_recipients_cb_t)(smtp_recipient_t recipient,
                                               const char*      mailbox,
                                               void*            arg);

#ifdef __cplusplus
extern "C"
{
#endif

smtp_session_t smtp_create_session(void);
void           smtp_destroy_session(smtp_session_t session);
smtp_message_t smtp_add_message(smtp_session_t session);
void smtp_set_monitorcb(smtp_session_t session, smtp_monitorcb_t cb,
                        void* arg, int headers);
int  smtp_set_timeout(smtp_session_t session, int which, long value);
int  smtp_starttls_enable(smtp_session_t session, smtp_starttls_t how);
int  smtp_starttls_set_ctx(smtp_session_t session, void* ssl_ctx);
int  smtp_set_server(smtp_session_t session, const char* hostport);
void smtp_set_eventcb(smtp_session_t session, smtp_eventcb_t cb, void* arg);
void smtp_auth_set_context(smtp_session_t session, void* authctx);
int  smtp_set_reverse_path(smtp_message_t message, const char* mailbox);
int  smtp_set_header(smtp_message_t message, const char* header, ...);
int  smtp_set_header_option(smtp_message_t message, const char* header,
                            int option, ...);
void             smtp_set_message_str(smtp_message_t message, void* str);
int              smtp_start_session(smtp_session_t session);
const smtp_status_t* smtp_message_transfer_status(smtp_message_t message);
void smtp_enumerate_recipients(smtp_message_t message,
                               smtp_enumerate_recipients_cb_t cb, void* arg);
smtp_recipient_t     smtp_add_recipient(smtp_message_t message,
                                        const char*    mailbox);
const smtp_status_t* smtp_recipient_status(smtp_recipient_t recipient);

/* Test control: set whether smtp_start_session should succeed */
void setSmtpStartSessionResult(int success);

#ifdef __cplusplus
}
#endif
