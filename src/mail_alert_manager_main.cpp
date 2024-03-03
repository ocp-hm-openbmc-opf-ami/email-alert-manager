/************************************************************************
 *          Module:  SMTP Client
 *          Author:  Dillibabug
 *          Email :  dillibabug@ami.com
 *
 * *********************************************************************/

#include "mail_alert_manager.hpp"

#include <boost/asio/io_service.hpp>
#include <iostream>
#include <sdbusplus/asio/object_server.hpp>
#include <sdbusplus/message.hpp>

static constexpr const char* smtpclient = "xyz.openbmc_project.mail";
static constexpr const char* smtpObj = "/xyz/openbmc_project/mail/alert";
static constexpr const char* smtpIntf = "xyz.openbmc_project.mail.alert";
static constexpr const char* smtp_Intf_primary_server =
    "xyz.openbmc_project.mail.alert.primary";
static constexpr const char* smtp_Intf_secondary_server =
    "xyz.openbmc_project.mail.alert.secondary";

mail::alert::manager::mail_server smtpClientcfg[2];
mail::alert::manager::smtp objsmtp;

void createDbus_Properties(
    std::shared_ptr<sdbusplus::asio::dbus_interface>& smtpIface_primary,
    currentServer select_server)
{
    uint8_t cur_smtpCfg = static_cast<int>(select_server);
    objsmtp.getSmtpConfig(smtpClientcfg[cur_smtpCfg], select_server);

    smtpIface_primary->register_property(
        "Host", smtpClientcfg[cur_smtpCfg].host,
        [&](const std::string& requested, std::string& resp) {
            int smtpServer = 0;
            if (smtpIface_primary->get_interface_name() ==
                smtp_Intf_primary_server)
            {
                smtpServer =
                    static_cast<int>(currentServer::SMTP_PRIMARY_SERVER);
            }
            else
            {
                smtpServer =
                    static_cast<int>(currentServer::SMTP_SECONDARY_SERVER);
            }
            smtpClientcfg[smtpServer].host = requested;
            objsmtp.setsmtpconfig(smtpClientcfg[smtpServer],
                                  static_cast<currentServer>(smtpServer));
            resp = requested;
            return DBUS_SUCCESS;
        });

    smtpIface_primary->register_property(
        "Port", smtpClientcfg[cur_smtpCfg].port,
        [&](const uint16_t& requested, uint16_t& resp) {
            int smtpServer = 0;
            if (smtpIface_primary->get_interface_name() ==
                smtp_Intf_primary_server)
            {
                smtpServer =
                    static_cast<int>(currentServer::SMTP_PRIMARY_SERVER);
            }
            else
            {
                smtpServer =
                    static_cast<int>(currentServer::SMTP_SECONDARY_SERVER);
            }

            smtpClientcfg[smtpServer].port = requested;
            objsmtp.setsmtpconfig(smtpClientcfg[smtpServer],
                                  static_cast<currentServer>(smtpServer));

            resp = requested;
            return DBUS_SUCCESS;
        });

    smtpIface_primary->register_property(
        "Sender", smtpClientcfg[cur_smtpCfg].sender,
        [&](const std::string& requested, std::string& resp) {
            int smtpServer = 0;
            if (smtpIface_primary->get_interface_name() ==
                smtp_Intf_primary_server)
            {
                smtpServer =
                    static_cast<int>(currentServer::SMTP_PRIMARY_SERVER);
            }
            else
            {
                smtpServer =
                    static_cast<int>(currentServer::SMTP_SECONDARY_SERVER);
            }

            smtpClientcfg[smtpServer].sender = requested;
            objsmtp.setsmtpconfig(smtpClientcfg[smtpServer],
                                  static_cast<currentServer>(smtpServer));

            resp = requested;
            return DBUS_SUCCESS;
        });

    smtpIface_primary->register_property(
        "UserName", smtpClientcfg[cur_smtpCfg].user_credntial.username,
        [&](const std::string& requested, std::string& resp) {
            uint8_t smtpServer = 0;
            if (smtpIface_primary->get_interface_name() ==
                smtp_Intf_primary_server)
            {
                smtpServer =
                    static_cast<int>(currentServer::SMTP_PRIMARY_SERVER);
            }
            else
            {
                smtpServer =
                    static_cast<int>(currentServer::SMTP_SECONDARY_SERVER);
            }

            smtpClientcfg[smtpServer].user_credntial.username = requested;
            objsmtp.setsmtpconfig(smtpClientcfg[smtpServer],
                                  static_cast<currentServer>(smtpServer));
            resp = requested;
            return DBUS_SUCCESS;
        });

    smtpIface_primary->register_property(
        "Password", smtpClientcfg[cur_smtpCfg].user_credntial.password,
        [&](const std::string& requested, std::string& resp) {
            int smtpServer = 0;
            if (smtpIface_primary->get_interface_name() ==
                smtp_Intf_primary_server)
            {
                smtpServer =
                    static_cast<int>(currentServer::SMTP_PRIMARY_SERVER);
            }
            else
            {
                smtpServer =
                    static_cast<int>(currentServer::SMTP_SECONDARY_SERVER);
            }

            smtpClientcfg[smtpServer].user_credntial.password = requested;
            objsmtp.setsmtpconfig(smtpClientcfg[smtpServer],
                                  static_cast<currentServer>(smtpServer));
            resp = requested;
            return DBUS_SUCCESS;
        });

    smtpIface_primary->register_property(
        "Enable", smtpClientcfg[cur_smtpCfg].enable,
        [&](const bool& requested, bool& resp) {
            int smtpServer = 0;
            if (smtpIface_primary->get_interface_name() ==
                smtp_Intf_primary_server)
            {
                smtpServer =
                    static_cast<int>(currentServer::SMTP_PRIMARY_SERVER);
            }
            else
            {
                smtpServer =
                    static_cast<int>(currentServer::SMTP_SECONDARY_SERVER);
            }

            smtpClientcfg[smtpServer].enable = requested;
            objsmtp.setsmtpconfig(smtpClientcfg[smtpServer],
                                  static_cast<currentServer>(smtpServer));
            resp = requested;
            return true;
        });

    smtpIface_primary->register_property(
        "Authentication", smtpClientcfg[cur_smtpCfg].AuthEnable,
        [&](const bool& requested, bool& resp) {
            uint8_t smtpServer = 0;
            if (smtpIface_primary->get_interface_name() ==
                smtp_Intf_primary_server)
            {
                smtpServer =
                    static_cast<int>(currentServer::SMTP_PRIMARY_SERVER);
            }
            else
            {
                smtpServer =
                    static_cast<int>(currentServer::SMTP_SECONDARY_SERVER);
            }

            smtpClientcfg[smtpServer].AuthEnable = requested;
            objsmtp.setsmtpconfig(smtpClientcfg[smtpServer],
                                  static_cast<currentServer>(smtpServer));

            resp = requested;
            return DBUS_SUCCESS;
        });

    smtpIface_primary->register_property(
        "TLSEnable", smtpClientcfg[cur_smtpCfg].TLSEnable,
        [&](const bool& requested, bool& resp) {
            int smtpServer = 0;
            if (smtpIface_primary->get_interface_name() ==
                smtp_Intf_primary_server)
            {
                smtpServer =
                    static_cast<int>(currentServer::SMTP_PRIMARY_SERVER);
            }
            else
            {
                smtpServer =
                    static_cast<int>(currentServer::SMTP_SECONDARY_SERVER);
            }
            smtpClientcfg[smtpServer].TLSEnable = requested;
            objsmtp.setsmtpconfig(smtpClientcfg[smtpServer],
                                  static_cast<currentServer>(smtpServer));

            resp = requested;
            return DBUS_SUCCESS;
        });

    smtpIface_primary->register_property(
        "Recipient", smtpClientcfg[cur_smtpCfg].recipient,
        [&](const std::vector<std::string>& requested,
            std::vector<std::string>& resp) {
            int smtpServer = 0;
            if (smtpIface_primary->get_interface_name() ==
                smtp_Intf_primary_server)
            {
                smtpServer =
                    static_cast<int>(currentServer::SMTP_PRIMARY_SERVER);
            }
            else
            {
                smtpServer =
                    static_cast<int>(currentServer::SMTP_SECONDARY_SERVER);
            }

            smtpClientcfg[smtpServer].recipient = requested;
            objsmtp.setsmtpconfig(smtpClientcfg[smtpServer],
                                  static_cast<currentServer>(smtpServer));

            resp = requested;
            return DBUS_SUCCESS;
        });
}

int main()
{

    boost::asio::io_service io;
    auto conn = std::make_shared<sdbusplus::asio::connection>(io);
    conn->request_name(smtpclient);

    auto server = sdbusplus::asio::object_server(conn);

    std::shared_ptr<sdbusplus::asio::dbus_interface> smtpIface =
        server.add_interface(smtpObj, smtpIntf);

    std::shared_ptr<sdbusplus::asio::dbus_interface> smtpIface_primary =
        server.add_interface(smtpObj, smtp_Intf_primary_server);

    createDbus_Properties(smtpIface_primary,
                          currentServer::SMTP_PRIMARY_SERVER);

    std::shared_ptr<sdbusplus::asio::dbus_interface> smtpIface_secondary =
        server.add_interface(smtpObj, smtp_Intf_secondary_server);

    createDbus_Properties(smtpIface_secondary,
                          currentServer::SMTP_SECONDARY_SERVER);

    objsmtp.init_smtp();
    objsmtp.initializeSmtpcfg(currentServer::SMTP_PRIMARY_SERVER);
    objsmtp.initializeSmtpcfg(currentServer::SMTP_SECONDARY_SERVER);

    smtpIface->register_method(
        "SendMail", [&](const std::string& subject, const std::string& msg) {
            return objsmtp.sendmail(subject, msg);
        });

    smtpIface_secondary->initialize();
    smtpIface_primary->initialize();
    smtpIface->initialize();

    io.run();
    return 0;
}
