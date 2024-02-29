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

constexpr const char* primaryconfigFilePath =
    "/var/lib/alert/primary_smtp_config.json";
constexpr const char* secondaryconfigFilePath =
    "/var/lib/alert/secondary_smtp_config.json";
constexpr const char* certificatePath = "/etc/ssl/certs/server.crt";
constexpr const char* privatekeyPath = "/etc/ssl/private/server.key";
constexpr const char* CAcertificatePath = "/etc/ssl/certs/cacert.pem";

constexpr const int totalSmtpServers = 2;
constexpr const uint16_t SMTP_ERROR = -1;
constexpr const uint16_t SMTP_SUCCESS = 0;
constexpr const uint16_t DBUS_SUCCESS = 1;

using ::phosphor::logging::entry;
using ::phosphor::logging::level;
using ::phosphor::logging::log;

enum class currentServer
{
    SMTP_PRIMARY_SERVER = 0,
    SMTP_SECONDARY_SERVER,
};

enum class ipVersion
{
    SMTP_IP_ERROR = 0,
    SMTP_IPV4_MODEL = 4,
    SMTP_IPV6_MODEL = 6,
    SMTP_DNS_MODEL,
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
    struct mail_server clientcfg[totalSmtpServers];
    const smtp_status_t* status;

    std::filesystem::directory_entry server_cert{certificatePath};
    std::filesystem::directory_entry private_key{privatekeyPath};
    std::filesystem::directory_entry CA_cert{CAcertificatePath};

    void init_smtp(void);
    ipVersion ip_version(const char* src);
    uint16_t setsmtpconfig(struct mail_server& servers,
                           currentServer select_server);
    uint16_t getSmtpConfig(struct mail_server& ms, currentServer server_select);
    uint16_t sendmail(const std::string& subject, const std::string& msg);
    int initializeSmtpcfg(currentServer curr_server);
};
} // namespace manager
} // namespace alert
} // namespace mail
