#include "mail_alert_manager.hpp"

#include <arpa/inet.h>
#include <assert.h>
#include <openssl/ssl.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <fstream>
#include <iostream>

#include <sys/socket.h>
#include <netdb.h>
#include <sys/types.h>


namespace mail
{
namespace alert
{
namespace manager
{
void monitor_cb(const char* buf, int buflen, int writing, void* arg)
{

    if (writing == SMTP_CB_HEADERS)
    {
#if (ENABLE_VERBOSE_DEBUG == 1)
        std::cerr << "HEADER: " << buf << std::endl;
#endif
        return;
    }
    if (writing)
    {
#if (ENABLE_VERBOSE_DEBUG == 1)
        std::cerr << "CTRL: " << buf << std::endl;
#endif
    }
    else
    {
#if (ENABLE_VERBOSE_DEBUG == 1)
        std::cerr << "STAT: " << buf << std::endl;
#endif
    }
}

int authinteract(auth_client_request_t request, char** result, int fields,
                 void* arg)
{
    struct credentials* cread = (struct credentials*)arg;

    if ((!cread->username.empty()) || (!cread->password.empty()))
    {
        return 0;
    }

    for (int i = 0; i < fields; i++)
    {
        if (request[i].flags & AUTH_USER)
        {
            result[i] = (char*)cread->username.c_str();
        }
        else if (request[i].flags & AUTH_PASS)
        {
            result[i] = (char*)cread->password.c_str();
        }
    }
    return 1;
}

int tlsinteract(char* buf, int buflen, int rwflag, void* arg)
{
    char* pw;
    int len;

    pw = buf;
    len = strlen(pw);
    if (len + 1 > buflen)
        return 0;
    strcpy(buf, pw);
    return len;
}

int handle_invalid_peer_certificate(long vfy_result)
{
    const char* k = "rare error";
    switch (vfy_result)
    {
        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
            k = "X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT";
            break;
        case X509_V_ERR_UNABLE_TO_GET_CRL:
            k = "X509_V_ERR_UNABLE_TO_GET_CRL";
            break;
        case X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE:
            k = "X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE";
            break;
        case X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE:
            k = "X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE";
            break;
        case X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
            k = "X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY";
            break;
        case X509_V_ERR_CERT_SIGNATURE_FAILURE:
            k = "X509_V_ERR_CERT_SIGNATURE_FAILURE";
            break;
        case X509_V_ERR_CRL_SIGNATURE_FAILURE:
            k = "X509_V_ERR_CRL_SIGNATURE_FAILURE";
            break;
        case X509_V_ERR_CERT_NOT_YET_VALID:
            k = "X509_V_ERR_CERT_NOT_YET_VALID";
            break;
        case X509_V_ERR_CERT_HAS_EXPIRED:
            k = "X509_V_ERR_CERT_HAS_EXPIRED";
            break;
        case X509_V_ERR_CRL_NOT_YET_VALID:
            k = "X509_V_ERR_CRL_NOT_YET_VALID";
            break;
        case X509_V_ERR_CRL_HAS_EXPIRED:
            k = "X509_V_ERR_CRL_HAS_EXPIRED";
            break;
        case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
            k = "X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD";
            break;
        case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
            k = "X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD";
            break;
        case X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD:
            k = "X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD";
            break;
        case X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD:
            k = "X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD";
            break;
        case X509_V_ERR_OUT_OF_MEM:
            k = "X509_V_ERR_OUT_OF_MEM";
            break;
        case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
            k = "X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT";
            break;
        case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
            k = "X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN";
            break;
        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
            k = "X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY";
            break;
        case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
            k = "X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE";
            break;
        case X509_V_ERR_CERT_CHAIN_TOO_LONG:
            k = "X509_V_ERR_CERT_CHAIN_TOO_LONG";
            break;
        case X509_V_ERR_CERT_REVOKED:
            k = "X509_V_ERR_CERT_REVOKED";
            break;
        case X509_V_ERR_INVALID_CA:
            k = "X509_V_ERR_INVALID_CA";
            break;
        case X509_V_ERR_PATH_LENGTH_EXCEEDED:
            k = "X509_V_ERR_PATH_LENGTH_EXCEEDED";
            break;
        case X509_V_ERR_INVALID_PURPOSE:
            k = "X509_V_ERR_INVALID_PURPOSE";
            break;
        case X509_V_ERR_CERT_UNTRUSTED:
            k = "X509_V_ERR_CERT_UNTRUSTED";
            break;
        case X509_V_ERR_CERT_REJECTED:
            k = "X509_V_ERR_CERT_REJECTED";
            break;
    }
#if (ENABLE_VERBOSE_DEBUG == 1)
    std::cout << "SMTP_EV_INVALID_PEER_CERTIFICATE: " << vfy_result << k
              << std::endl;
#endif
    return 1; /* Accept the problem */
}

void event_cb(smtp_session_t session, int event_no, void* arg, ...)
{
    va_list alist;
    int* ok;

    va_start(alist, arg);
    switch (event_no)
    {
        case SMTP_EV_CONNECT: {
#if (ENABLE_VERBOSE_DEBUG == 1)
            log<level::INFO>("SMTP_EV_CONNECT \r\n");
#endif
            break;
        }
        case SMTP_EV_MAILSTATUS: {
#if (ENABLE_VERBOSE_DEBUG == 1)
            log<level::INFO>("SMTP_EV_MAILSTATUS \r\n");
#endif
            break;
        }
        case SMTP_EV_RCPTSTATUS: {
#if (ENABLE_VERBOSE_DEBUG == 1)
            log<level::INFO>("SMTP_EV_RCPTSTATUS \r\n");
#endif
            break;
        }
        case SMTP_EV_MESSAGEDATA: {
#if (ENABLE_VERBOSE_DEBUG == 1)
            log<level::INFO>("SMTP_EV_MESSAGEDATA \r\n");
#endif
            break;
        }
        case SMTP_EV_MESSAGESENT: {
#if (ENABLE_VERBOSE_DEBUG == 1)
            log<level::INFO>("SMTP_EV_MESSAGESENT \r\n");
#endif
            break;
        }
        case SMTP_EV_DISCONNECT: {
#if (ENABLE_VERBOSE_DEBUG == 1)
            log<level::INFO>("SMTP_EV_DISCONNECT \r\n");
#endif
            break;
        }
        case SMTP_EV_WEAK_CIPHER: {
            int bits;
            bits = va_arg(alist, long);
            ok = va_arg(alist, int*);
            printf("SMTP_EV_WEAK_CIPHER, bits=%d - accepted.\n", bits);
            *ok = 1;
            break;
        }
        case SMTP_EV_STARTTLS_OK:
#if (ENABLE_VERBOSE_DEBUG == 1)
            log<level::INFO>("SMTP_EV_STARTTLS_OK - TLS started here. \r\n");
#endif
            break;
        case SMTP_EV_INVALID_PEER_CERTIFICATE: {
            long vfy_result;
            vfy_result = va_arg(alist, long);
            ok = va_arg(alist, int*);
            *ok = handle_invalid_peer_certificate(vfy_result);
            break;
        }
        case SMTP_EV_NO_PEER_CERTIFICATE: {
            ok = va_arg(alist, int*);
#if (ENABLE_VERBOSE_DEBUG == 1)
            log<level::INFO>("SMTP_EV_NO_PEER_CERTIFICATE - accepted. \r\n");
#endif
            *ok = 1;
            break;
        }
        case SMTP_EV_WRONG_PEER_CERTIFICATE: {
            ok = va_arg(alist, int*);
#if (ENABLE_VERBOSE_DEBUG == 1)
            log<level::INFO>("SMTP_EV_WRONG_PEER_CERTIFICATE - accepted. \r\n");
#endif
            *ok = 1;
            break;
        }
        case SMTP_EV_NO_CLIENT_CERTIFICATE: {
            ok = va_arg(alist, int*);
#if (ENABLE_VERBOSE_DEBUG == 1)
            log<level::INFO>("SMTP_EV_NO_CLIENT_CERTIFICATE - accepted. \r\n");
#endif
            *ok = 1;
            break;
        }
#if (ENABLE_VERBOSE_DEBUG == 1)
        default:
            log<level::INFO>("Got event: ",
                             entry("%d - ignored \r\n", event_no));
#endif
    }
    va_end(alist);
}

void print_recipient_status(smtp_recipient_t recipient, const char* mailbox,
                            void* arg)
{
    const smtp_status_t* status;
    status = smtp_recipient_status(recipient);
#if (ENABLE_VERBOSE_DEBUG == 0)
    std::cerr << "Recipient Status: " << status->code << " " << status->text
              << std::endl;
#endif
}

void smtp::init_smtp(void)
{
    session = smtp_create_session();
}

uint16_t smtp::sendmail(const std::string& subject, const std::string& msg)
{
    smtpStatus ret_status = send_mail(subject, msg, curr_server);

    if(ret_status != smtpStatus::SMTP_ERROR)
    {
        log<level::INFO>("SMTP Mail sent.......\r\n");
    }
    else
    {
        if(curr_server == currentServer::SMTP_PRIMARY_SERVER)
           curr_server = currentServer::SMTP_SECONDARY_SERVER;
        else
           curr_server = currentServer::SMTP_PRIMARY_SERVER;

        if(send_mail(subject, msg, curr_server) == smtpStatus::SMTP_ERROR)
        {
            return int(smtpStatus::SMTP_ERROR);
        }
        else
        {
            return int(smtpStatus::SMTP_SUCCESS);
        }
    }
    return static_cast<int>(ret_status);
}

smtpStatus smtp::send_mail(const std::string& subject, const std::string& msg, currentServer server)
{
    char service[5] = {0};
    smtpStatus ret = smtpStatus::SMTP_SUCCESS;

    auth_client_init();

    session = smtp_create_session();

    uint8_t cur_smtpCfg = int(server);
   
    if (clientcfg[cur_smtpCfg].enable == true)
    {
        if ((clientcfg[cur_smtpCfg].host.empty()) ||
            (clientcfg[cur_smtpCfg].port == 0) ||
            (clientcfg[cur_smtpCfg].sender.empty()))
        {
            log<level::ERR>("Host/Port/Sender is empty \r\n");
            return smtpStatus::SMTP_ERROR;
        }

        credential = clientcfg[cur_smtpCfg].user_credntial;

        if (clientcfg[cur_smtpCfg].AuthEnable == true)
        {
            if ((credential.username.empty()) || (credential.password.empty()))
            {
                log<level::ERR>(
                    "Authentication: username/password is empty \r\n");
                return smtpStatus::SMTP_ERROR;
            }
        }
        else
        {
           log<level::INFO>("Authentication not enabled \r\n");
        }
        message = smtp_add_message(session);

        smtp_set_monitorcb(session, monitor_cb, stdout, 0);

        if (!smtp_set_timeout(session, (int)Timeout_GREETING, 3))
        {
            log<level::INFO>("Timeout setting not working \r\n");
        }

        if (clientcfg[cur_smtpCfg].TLSEnable == true)
        {
            log<level::INFO>("TLS is enabled \r\n");

            if(cur_smtpCfg == 0)
            {
                if ((!pri_server_cert.exists()) || (!pri_private_key.exists()) ||
                    (!pri_CA_cert.exists()))
                {
                    log<level::ERR>("Please Provide Certificates \r\n");
                    return smtpStatus::SMTP_ERROR;
                }
            }   
            else
            {   if ((!sec_server_cert.exists()) || (!sec_private_key.exists()) ||
                (!sec_CA_cert.exists()))
                {
                    log<level::ERR>("Please Provide Certificates \r\n");
                    return smtpStatus::SMTP_ERROR;
                }
            }

            if (!(smtp_starttls_enable(session, Starttls_ENABLED)))
            {
                log<level::ERR>("startTLS enable Failed \r\n");
            }
            if (!(smtp_starttls_enable(session, Starttls_REQUIRED)))
            {
                log<level::ERR>("startTLS Required Failed\r\n");
            }

            SSL_CTX* smtpcli_sslctx = NULL;
            smtpcli_sslctx = SSL_CTX_new(SSLv23_method());

            if (!smtpcli_sslctx)
            {
                log<level::ERR>("Error creating SSL context\r\n");
                return smtpStatus::SMTP_ERROR;
            }

            const char *private_key_Cert = privatekeyPath[cur_smtpCfg];
            const char *Cert_Certificate = certificatePath[cur_smtpCfg];
            const char *CA_Certificate = CAcertificatePath[cur_smtpCfg];

            /* Load private key */
            if (SSL_CTX_use_PrivateKey_file(smtpcli_sslctx, private_key_Cert,
                                            SSL_FILETYPE_PEM) != 1)
            {
                log<level::ERR>("Cannot load key file \r\n");
            }

            /* Load certificate chain */
            if (SSL_CTX_use_certificate_chain_file(smtpcli_sslctx,
                                                   Cert_Certificate) != 1)
            {
                log<level::ERR>("Cannot load certificate file \r\n");
            }

            /* Check private key validity */
            if (!SSL_CTX_check_private_key(smtpcli_sslctx))
            {
                log<level::ERR>("Private Key is invalid \r\n");
            }

            /* Load trust file */
            if (SSL_CTX_load_verify_locations(smtpcli_sslctx, CA_Certificate,
                                              NULL) != 1)
            {
                log<level::ERR>("Cannot load trust file \r\n");
            }

            /* If any of the above conditions failed, free the SSL_CTX and */
            if (!smtpcli_sslctx)
            {
                SSL_CTX_free(smtpcli_sslctx);
                smtpcli_sslctx = NULL;
                return smtpStatus::SMTP_ERROR;
            }
            SSL_CTX_set_verify(smtpcli_sslctx, SSL_VERIFY_PEER, NULL);
            SSL_CTX_set_verify_depth(smtpcli_sslctx, 4);
            SSL_CTX_free(smtpcli_sslctx);
        }
        else
        {
            log<level::INFO>("TLS is Disabled \r\n");
            smtp_starttls_enable(session, Starttls_DISABLED);
        }

        for (const auto& single_recipient : clientcfg[cur_smtpCfg].recipient)
        {
            smtp_set_header(message, "To", NULL, single_recipient.c_str());
            smtp_add_recipient(message, single_recipient.c_str());
        }

        sa.sa_handler = SIG_IGN;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;
        sigaction(SIGPIPE, &sa, NULL);

        std::string smtpPort = clientcfg[cur_smtpCfg].host + "-" +
                                std::to_string(clientcfg[cur_smtpCfg].port);

        if (smtp_set_server(session, (const char*)smtpPort.c_str()) == 0)
        {
            log<level::ERR>("Server not available: Could not establish "
                            "connection \r\n");
            return smtpStatus::SMTP_ERROR;
        }

        smtp_set_eventcb(session, event_cb, session);

        if (clientcfg[cur_smtpCfg].AuthEnable == true)
        {
            authctx = auth_create_context();
            if (authctx != NULL)
            {
                auth_set_mechanism_flags(authctx, AUTH_PLUGIN_PLAIN, 0);
                auth_set_interact_cb(authctx, authinteract, (void*)&credential);
                smtp_auth_set_context(session, authctx);
            }
            log<level::INFO>("Auth Enabled\r\n");
        }
        else
        {
            smtp_auth_set_context(session, NULL);
            log<level::INFO>("Auth Disabled\r\n");
        }

        if (!smtp_set_reverse_path(message,
                                   clientcfg[cur_smtpCfg].sender.c_str()))
        {
            log<level::ERR>("Set reverse path: Failed\r\n");
            return smtpStatus::SMTP_ERROR;
        }
        if (!smtp_set_header(message, "Subject", subject.c_str()))
        {
            log<level::ERR>("Set header: Failed to set subject\r\n");
            return smtpStatus::SMTP_ERROR;
        }
        if (!smtp_set_header_option(message, "Subject", Hdr_OVERRIDE, 1))
        {
            log<level::ERR>("Set header: Failed to set message\r\n");
            return smtpStatus::SMTP_ERROR;
        }

        std::string smtp_msg = "\r\n" + msg + "\r\n";
        smtp_set_message_str(message, (void*)smtp_msg.c_str());

        syslog(LOG_INFO, "Session Starting %d \r\n", cur_smtpCfg);

        if (!smtp_start_session(session))
        {         
            ret = smtpStatus::SMTP_ERROR;               
        }
        else
        {
            status = smtp_message_transfer_status(message);
            smtp_enumerate_recipients(message, print_recipient_status, NULL);
        }
    }
    else
    {
        log<level::INFO>(
            "Please make Enable property to true to send the mail \r\n");
        return smtpStatus::SMTP_ERROR;
    }
    auth_client_exit();

    return ret;
}

smtpStatus smtp::setsmtpconfig(struct mail_server& servers,
                             currentServer select_server)
{
    std::ofstream configFile;
    if (select_server == currentServer::SMTP_PRIMARY_SERVER)
    {
        configFile.open(primaryconfigFilePath, std::ios::out | std::ios::trunc);
    }
    else
    {
        configFile.open(secondaryconfigFilePath,
                        std::ios::out | std::ios::trunc);
    }

    Json privData, jsonData;
    privData["Enabled"] = servers.enable;
    privData["Host"] = servers.host;
    privData["Port"] = servers.port;
    privData["Sender"] = servers.sender;
    privData["Recipient"] = servers.recipient;
    privData["TLSEnable"] = servers.TLSEnable;
    privData["Authentication"] = servers.AuthEnable;
    privData["username"] = servers.user_credntial.username;
    privData["password"] = servers.user_credntial.password;
    jsonData["Config"] = privData;

    const auto& writeData = jsonData.dump(4);
    configFile << writeData << std::endl;
    configFile.close();

    int index = static_cast<int>(select_server);
    clientcfg[index] = servers;
    log<level::INFO>("Configuration updated on: ", entry("%d server", index));
    return smtpStatus::SMTP_SUCCESS;
}

smtpStatus smtp::getSmtpConfig(struct mail_server& ms,
                             currentServer server_select)
{
    std::string configFilePath;

    if (server_select == currentServer::SMTP_PRIMARY_SERVER)
    {
        configFilePath = primaryconfigFilePath;
    }
    else
    {
        configFilePath = secondaryconfigFilePath;
    }
    std::ifstream configFile(configFilePath);
    if (!configFile.is_open())
    {
        log<level::ERR>("initializeSmtpcfg: Cannot open config path:  \r\n");
        return smtpStatus::SMTP_ERROR;
    }
    try
    {
        auto data = nlohmann::json::parse(configFile, nullptr, false, true);

        Json smtpConfig = data["Config"];
        ms.enable = smtpConfig["Enabled"].get<bool>();
        ms.host = smtpConfig["Host"];
        ms.port = smtpConfig["Port"].get<int>();
        ms.sender = smtpConfig["Sender"];
        ms.recipient = smtpConfig["Recipient"];
        ms.TLSEnable = smtpConfig["TLSEnable"].get<bool>();
        ms.AuthEnable = smtpConfig["Authentication"].get<bool>();
        ms.user_credntial.username = smtpConfig["username"];
        ms.user_credntial.password = smtpConfig["password"];

        if ((ms.user_credntial.username.empty()) ||
            (ms.user_credntial.username.empty()))
        {
            return smtpStatus::SMTP_ERROR;
        }
    }
    catch (nlohmann::json::exception& e)
    {
        log<level::ERR>("Get-config: Error parsing config file \r\n");
        return smtpStatus::SMTP_ERROR;
    }
    catch (std::out_of_range& e)
    {
        log<level::ERR>("Get-config: Error invalid type \r\n");
        return smtpStatus::SMTP_ERROR;
    }
    return smtpStatus::DBUS_SUCCESS;
}

smtpStatus smtp::initializeSmtpcfg(currentServer curr_server)
{
    uint8_t cur_smtpCfg = static_cast<uint8_t>(curr_server);
    std::string configFilePath;

    if (curr_server == currentServer::SMTP_PRIMARY_SERVER)
    {
        configFilePath = primaryconfigFilePath;
        log<level::INFO>("Server is primary ",
                         entry("%s \r\n", configFilePath.c_str()));
    }
    else
    {
        configFilePath = secondaryconfigFilePath;
        log<level::INFO>("Server is Secondary",
                         entry("%s \r\n", configFilePath.c_str()));
    }

    std::ifstream configFile(configFilePath);

    if (!configFile.is_open())
    {
        log<level::ERR>("initializeSmtpcfg: Cannot open config path \r\n");
        return smtpStatus::SMTP_ERROR;
    }
    try
    {
        auto data = nlohmann::json::parse(configFile, nullptr, false, true);
        Json smtpConfig = data["Config"];

        clientcfg[cur_smtpCfg].enable = smtpConfig["Enabled"].get<bool>();
        clientcfg[cur_smtpCfg].host = smtpConfig["Host"];
        clientcfg[cur_smtpCfg].port = smtpConfig["Port"].get<int>();
        clientcfg[cur_smtpCfg].sender = smtpConfig["Sender"];
        clientcfg[cur_smtpCfg].recipient = smtpConfig["Recipient"];
        clientcfg[cur_smtpCfg].TLSEnable = smtpConfig["TLSEnable"].get<bool>();
        clientcfg[cur_smtpCfg].AuthEnable =
            smtpConfig["Authentication"].get<bool>();
        clientcfg[cur_smtpCfg].user_credntial.username = smtpConfig["username"];
        clientcfg[cur_smtpCfg].user_credntial.password = smtpConfig["password"];

        if ((!clientcfg[cur_smtpCfg].user_credntial.username.empty()) ||
            (!clientcfg[cur_smtpCfg].user_credntial.password.empty()))
        {
            credential.username =
                clientcfg[cur_smtpCfg].user_credntial.username;
            credential.password =
                clientcfg[cur_smtpCfg].user_credntial.password;
        }
        else
        {
            return smtpStatus::SMTP_ERROR;
        }
    }
    catch (nlohmann::json::exception& e)
    {
        log<level::ERR>("initializeSmtpcfg: Error parsing config file \r\n");
        return smtpStatus::SMTP_ERROR;
    }
    catch (std::out_of_range& e)
    {
        log<level::ERR>("initializeChannelsSmtpcfg: Error invalid type \r\n");
        return smtpStatus::SMTP_ERROR;
    }
    return smtpStatus::SMTP_SUCCESS;
}

} // namespace manager
} // namespace alert
} // namespace mail
