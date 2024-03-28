#pragma once

#define _XOPEN_SOURCE 500

#include "xyz/openbmc_project/Logging/Entry/server.hpp"

#include <auth-client.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <libesmtp.h>
#include <openssl/ssl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <nlohmann/json.hpp>
#include <phosphor-logging/log.hpp>
#include <vector>
#include <xyz/openbmc_project/Common/error.hpp>
#include <xyz/openbmc_project/Logging/SEL/error.hpp>

#define ENABLE_VERBOSE_DEBUG (0)
constexpr const uint8_t SMTP_TOTAL_SERVERS = 2;

constexpr const std::string AUTH_1 {"535 5.7.8"};
constexpr const std::string AUTH_2 {"501 5.7.0"};

enum class smtpStatus : int16_t
{
    SMTP_ERROR   = -1,
    SMTP_AUTH_FAIL = -2,
    SMTP_SUCCESS = 0,
    DBUS_SUCCESS = 1,
};

constexpr const char* primaryconfigFilePath =
    "/var/lib/alert/primary_smtp_config.json";
constexpr const char* secondaryconfigFilePath =
    "/var/lib/alert/secondary_smtp_config.json";
constexpr const char* certificatePath[SMTP_TOTAL_SERVERS] = 
    {"/etc/ssl/certs/primary_server.crt", "/etc/ssl/certs/secondary_server.crt"};
constexpr const char* privatekeyPath[SMTP_TOTAL_SERVERS] = 
    {"/etc/ssl/private/primary_server.key" , "/etc/ssl/private/secondary_server.key"};
constexpr const char* CAcertificatePath[SMTP_TOTAL_SERVERS] = 
    {"/etc/ssl/certs/primary_cacert.pem" , "/etc/ssl/certs/secondary_cacert.pem"};

using ::phosphor::logging::entry;
using ::phosphor::logging::level;
using ::phosphor::logging::log;


enum class currentServer
{
    SMTP_PRIMARY_SERVER = 0,
    SMTP_SECONDARY_SERVER,
};

namespace mail
{
namespace alert
{
namespace manager
{
using Json = nlohmann::json;

struct credentials
{
    std::string username;
    std::string password;
    uint8_t authError;
};

struct mail_server
{
    bool enable;
    bool AuthEnable;
    bool TLSEnable;
    uint16_t port;
    std::string host;
    std::string sender;
    std::vector<std::string> recipient;
    struct credentials user_credntial;
};

class smtp
{

  public:
    smtp_session_t session;
    smtp_message_t message;
    auth_context_t authctx;
    currentServer curr_server = currentServer::SMTP_PRIMARY_SERVER;
    enum notify_flags notify = Notify_NOTSET;
    struct credentials credential;
    struct sigaction sa;
    struct mail_server clientcfg[SMTP_TOTAL_SERVERS];
    const smtp_status_t* status;
    uint8_t cur_smtpCfg = 0;

    std::filesystem::directory_entry pri_server_cert{certificatePath[0]};
    std::filesystem::directory_entry pri_private_key{privatekeyPath[0]};
    std::filesystem::directory_entry pri_CA_cert{CAcertificatePath[0]};

    std::filesystem::directory_entry sec_server_cert{certificatePath[1]};
    std::filesystem::directory_entry sec_private_key{privatekeyPath[1]};
    std::filesystem::directory_entry sec_CA_cert{CAcertificatePath[1]};

    void init_smtp(void);
    smtpStatus setsmtpconfig(struct mail_server& servers,
                           currentServer select_server);
    smtpStatus getSmtpConfig(struct mail_server& ms, currentServer server_select);
    uint16_t sendmail(const std::string& subject, const std::string& msg);
    smtpStatus initializeSmtpcfg(currentServer curr_server);
    smtpStatus send_mail(const std::string& subject, const std::string& msg, currentServer server);
};
} // namespace manager
} // namespace alert
} // namespace mail
