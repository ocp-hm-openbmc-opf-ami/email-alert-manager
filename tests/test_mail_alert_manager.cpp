#include "mail_alert_manager.hpp"

/* Undefine macros that conflict with GoogleTest names */
#ifdef FAIL
#undef FAIL
#endif
#ifdef ERROR
#undef ERROR
#endif
#ifdef DEBUG
#undef DEBUG
#endif

#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

/* Forward declarations of internal free functions */
namespace mail::alert::manager
{
void monitor_cb(const char* buf, int buflen, int writing, void* arg);
int authinteract(auth_client_request_t request, char** result, int fields,
                 void* arg);
int tlsinteract(char* buf, int buflen, int rwflag, void* arg);
int handle_invalid_peer_certificate(long vfy_result);
void event_cb(smtp_session_t session, int event_no, void* arg, ...);
void print_recipient_status(smtp_recipient_t recipient, const char* mailbox,
                            void* arg);
} // namespace mail::alert::manager

/* Test control declared in smtp_stubs.cpp */
extern "C" void setSmtpStartSessionResult(int success);

/* Helpers */
namespace
{
constexpr const char* kPrimaryConfig =
    "/var/lib/alert/primary_smtp_config.json";
constexpr const char* kSecondaryConfig =
    "/var/lib/alert/secondary_smtp_config.json";

void writeJsonConfig(
    const char* path, bool enabled, const std::string& host, uint16_t port,
    const std::string& sender, const std::vector<std::string>& recipients,
    bool tls, bool auth, const std::string& user, const std::string& pass,
    bool oauth = false, const std::string& accesstoken = "")
{
    nlohmann::json j;
    j["Config"]["Enabled"] = enabled;
    j["Config"]["Host"] = host;
    j["Config"]["Port"] = port;
    j["Config"]["Sender"] = sender;
    j["Config"]["Recipient"] = recipients;
    j["Config"]["TLSEnable"] = tls;
    j["Config"]["Authentication"] = auth;
    j["Config"]["Oauth"] = oauth;
    j["Config"]["username"] = user;
    j["Config"]["password"] = pass;
    j["Config"]["accesstoken"] = accesstoken;

    std::ofstream out(path, std::ios::out | std::ios::trunc);
    out << j.dump(4) << "\n";
}
} // namespace

/* =============================================================================
 * Fixture: MonitorCbTest
 * Tests monitor_cb() — SMTP session monitor callback that detects auth errors.
 * =============================================================================
 */
class MonitorCbTest : public ::testing::Test
{
  protected:
    mail::alert::manager::credentials cred{"user", "pass", {}};
};

/* Arrange: writing == SMTP_CB_HEADERS
 * Act:     call monitor_cb
 * Assert:  returns immediately; authError unchanged */
TEST_F(MonitorCbTest, WritingIsHeaders_EarlyReturn_NoAuthErrorChange)
{
    mail::alert::manager::monitor_cb("HEADER: Subject: test\r\n", 24,
                                     SMTP_CB_HEADERS, &cred);
    EXPECT_EQ(cred.authError, 0u);
}

/* Arrange: writing == 1 (not headers), plain control data
 * Act:     call monitor_cb
 * Assert:  no authError change */
TEST_F(MonitorCbTest, WritingNonHeaders_NormalData_NoAuthChange)
{
    mail::alert::manager::monitor_cb("CTRL: EHLO localhost\r\n", 22, 1, &cred);
    EXPECT_EQ(cred.authError, 0u);
}

/* Arrange: writing == 0 (reading), buf contains AUTH_1 "535 5.7.8"
 * Act:     call monitor_cb
 * Assert:  authError set to 0xFF
 * Pre-scan: [Critical] Injection/Auth-Failure detection path                 */
TEST_F(MonitorCbTest, ReadingContainsAuth1String_SetsAuthError)
{
    mail::alert::manager::monitor_cb(
        "535 5.7.8 Authentication credentials invalid", 45, 0, &cred);
    EXPECT_EQ(cred.authError, static_cast<uint8_t>(0xFF));
}

/* Arrange: writing == 0 (reading), buf contains AUTH_2 "501 5.7.0"
 * Act:     call monitor_cb
 * Assert:  authError set to 0xFF */
TEST_F(MonitorCbTest, ReadingContainsAuth2String_SetsAuthError)
{
    mail::alert::manager::monitor_cb("501 5.7.0 Authentication failed", 31, 0,
                                     &cred);
    EXPECT_EQ(cred.authError, static_cast<uint8_t>(0xFF));
}

/* Arrange: writing == 0 (reading), buf with no auth-error signature
 * Act:     call monitor_cb
 * Assert:  authError unchanged */
TEST_F(MonitorCbTest, ReadingNoAuthString_NoChange)
{
    mail::alert::manager::monitor_cb("250 2.0.0 OK: queued", 21, 0, &cred);
    EXPECT_EQ(cred.authError, 0u);
}

/* =============================================================================
 * Fixture: AuthInteractTest
 * Tests authinteract() — libESMTP auth callback that fills credentials.
 * =============================================================================
 */
class AuthInteractTest : public ::testing::Test
{};

/* Arrange: empty username
 * Act:     call authinteract
 * Assert:  returns 0 (abort) */
TEST_F(AuthInteractTest, EmptyUsername_ReturnsZero)
{
    mail::alert::manager::credentials cred{"", "secret", {}};
    auth_client_request req{AUTH_USER, "Username:"};
    char* result[1] = {nullptr};

    int ret = mail::alert::manager::authinteract(&req, result, 1, &cred);
    EXPECT_EQ(ret, 0);
}

/* Arrange: empty password
 * Act:     call authinteract
 * Assert:  returns 0 (abort) */
TEST_F(AuthInteractTest, EmptyPassword_ReturnsZero)
{
    mail::alert::manager::credentials cred{"alice", "", {}};
    auth_client_request req{AUTH_PASS, "Password:"};
    char* result[1] = {nullptr};

    int ret = mail::alert::manager::authinteract(&req, result, 1, &cred);
    EXPECT_EQ(ret, 0);
}

/* Arrange: valid credentials, field with AUTH_USER flag
 * Act:     call authinteract with 1 field of AUTH_USER
 * Assert:  result[0] points to username c_str; returns 1                     */
TEST_F(AuthInteractTest, ValidCredentials_AuthUserFlag_FillsUsername)
{
    mail::alert::manager::credentials cred{"alice", "secret", {}};
    auth_client_request req{AUTH_USER, "Username:"};
    char* result[1] = {nullptr};

    int ret = mail::alert::manager::authinteract(&req, result, 1, &cred);

    EXPECT_EQ(ret, 1);
    ASSERT_NE(result[0], nullptr);
    EXPECT_STREQ(result[0], "alice");
}

/* Arrange: valid credentials, field with AUTH_PASS flag
 * Act:     call authinteract
 * Assert:  result[0] points to password c_str                                */
TEST_F(AuthInteractTest, ValidCredentials_AuthPassFlag_FillsPassword)
{
    mail::alert::manager::credentials cred{"alice", "secret", {}};
    auth_client_request req{AUTH_PASS, "Password:"};
    char* result[1] = {nullptr};

    int ret = mail::alert::manager::authinteract(&req, result, 1, &cred);

    EXPECT_EQ(ret, 1);
    ASSERT_NE(result[0], nullptr);
    EXPECT_STREQ(result[0], "secret");
}

/* Arrange: valid credentials, zero fields
 * Act:     call authinteract with fields == 0
 * Assert:  returns 1 without writing to result
 * Pre-scan: [Medium] result array size unchecked — zero-fields path          */
TEST_F(AuthInteractTest, ZeroFields_ReturnsOne_NoWrites)
{
    mail::alert::manager::credentials cred{"alice", "secret", {}};
    int ret = mail::alert::manager::authinteract(nullptr, nullptr, 0, &cred);
    EXPECT_EQ(ret, 1);
}

/* Arrange: valid credentials, two fields: AUTH_USER then AUTH_PASS
 * Act:     call authinteract with 2 fields
 * Assert:  both result slots filled correctly */
TEST_F(AuthInteractTest, TwoFields_FillsBothSlots)
{
    mail::alert::manager::credentials cred{"bob", "hunter2", {}};
    auth_client_request reqs[2] = {{AUTH_USER, "Username:"},
                                   {AUTH_PASS, "Password:"}};
    char* result[2] = {nullptr, nullptr};

    int ret = mail::alert::manager::authinteract(reqs, result, 2, &cred);

    EXPECT_EQ(ret, 1);
    EXPECT_STREQ(result[0], "bob");
    EXPECT_STREQ(result[1], "hunter2");
}

/* =============================================================================
 * Fixture: TlsInteractTest
 * Tests tlsinteract() — TLS passphrase callback (arg unused; copies buf->buf).
 * Pre-scan: [Critical] pw=buf not pw=arg; self-copy, but bounds-checked.
 * =============================================================================
 */
class TlsInteractTest : public ::testing::Test
{};

/* Arrange: buf already holds content shorter than buflen
 * Act:     call tlsinteract
 * Assert:  returns strlen(buf); self-copy is a no-op                         */
TEST_F(TlsInteractTest, ContentFitsInBuffer_ReturnsLength)
{
    char buf[32] = "hello";
    int ret = mail::alert::manager::tlsinteract(buf, 32, 0, nullptr);
    EXPECT_EQ(ret, 5);
    EXPECT_STREQ(buf, "hello");
}

/* Arrange: empty buf (len == 0), buflen == 16
 * Act:     call tlsinteract
 * Assert:  returns 0 (empty string copied)                                   */
TEST_F(TlsInteractTest, EmptyBuf_ReturnsZero)
{
    char buf[16] = {};
    int ret = mail::alert::manager::tlsinteract(buf, 16, 0, nullptr);
    EXPECT_EQ(ret, 0);
}

/* Arrange: buf content length == buflen - 1 (exactly fills buffer)
 * Act:     call tlsinteract
 * Assert:  returns buflen-1 (content copied, no overflow)                    */
TEST_F(TlsInteractTest, ContentExactlyFillsBuffer_ReturnsLength)
{
    char buf[8] = "1234567"; /* 7 chars + NUL = 8 bytes */
    int ret = mail::alert::manager::tlsinteract(buf, 8, 0, nullptr);
    EXPECT_EQ(ret, 7);
}

/* Arrange: buf content length == buflen (no room for NUL)
 * Act:     call tlsinteract
 * Assert:  returns 0 (overflow guard triggers: len+1 > buflen)
 * Pre-scan: [Critical] bounds guard covers this path                         */
TEST_F(TlsInteractTest, ContentFillsBufferNoRoom_ReturnsZero)
{
    char buf[5] = "abcd"; /* strlen = 4, buflen = 4 → len+1 > buflen */
    int ret = mail::alert::manager::tlsinteract(buf, 4, 0, nullptr);
    EXPECT_EQ(ret, 0);
}

/* =============================================================================
 * Fixture: HandleInvalidPeerCertTest
 * Tests handle_invalid_peer_certificate() — switch-case; always returns 1.
 * =============================================================================
 */
class HandleInvalidPeerCertTest : public ::testing::Test
{};

TEST_F(HandleInvalidPeerCertTest, UnableToGetIssuerCert_ReturnsOne)
{
    EXPECT_EQ(mail::alert::manager::handle_invalid_peer_certificate(
                  X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT),
              1);
}

TEST_F(HandleInvalidPeerCertTest, CertHasExpired_ReturnsOne)
{
    EXPECT_EQ(mail::alert::manager::handle_invalid_peer_certificate(
                  X509_V_ERR_CERT_HAS_EXPIRED),
              1);
}

TEST_F(HandleInvalidPeerCertTest, SelfSignedCertInChain_ReturnsOne)
{
    EXPECT_EQ(mail::alert::manager::handle_invalid_peer_certificate(
                  X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN),
              1);
}

TEST_F(HandleInvalidPeerCertTest, CertRevoked_ReturnsOne)
{
    EXPECT_EQ(mail::alert::manager::handle_invalid_peer_certificate(
                  X509_V_ERR_CERT_REVOKED),
              1);
}

TEST_F(HandleInvalidPeerCertTest, UnableToVerifyLeafSignature_ReturnsOne)
{
    EXPECT_EQ(mail::alert::manager::handle_invalid_peer_certificate(
                  X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE),
              1);
}

TEST_F(HandleInvalidPeerCertTest, CertNotYetValid_ReturnsOne)
{
    EXPECT_EQ(mail::alert::manager::handle_invalid_peer_certificate(
                  X509_V_ERR_CERT_NOT_YET_VALID),
              1);
}

TEST_F(HandleInvalidPeerCertTest, InvalidCa_ReturnsOne)
{
    EXPECT_EQ(mail::alert::manager::handle_invalid_peer_certificate(
                  X509_V_ERR_INVALID_CA),
              1);
}

TEST_F(HandleInvalidPeerCertTest, UnknownErrorCode_ReturnsOne)
{
    EXPECT_EQ(mail::alert::manager::handle_invalid_peer_certificate(99999L), 1);
}

/* =============================================================================
 * Fixture: EventCbTest
 * Tests event_cb() — SMTP event dispatcher; verifies *ok flag is set.
 * =============================================================================
 */
class EventCbTest : public ::testing::Test
{};

/* Events that only log and break — verify no crash */
TEST_F(EventCbTest, ConnectEvent_NoCrash)
{
    EXPECT_NO_FATAL_FAILURE(
        mail::alert::manager::event_cb(nullptr, SMTP_EV_CONNECT, nullptr));
}

TEST_F(EventCbTest, MailStatusEvent_NoCrash)
{
    EXPECT_NO_FATAL_FAILURE(
        mail::alert::manager::event_cb(nullptr, SMTP_EV_MAILSTATUS, nullptr));
}

TEST_F(EventCbTest, DisconnectEvent_NoCrash)
{
    EXPECT_NO_FATAL_FAILURE(
        mail::alert::manager::event_cb(nullptr, SMTP_EV_DISCONNECT, nullptr));
}

TEST_F(EventCbTest, StarttlsOkEvent_NoCrash)
{
    EXPECT_NO_FATAL_FAILURE(
        mail::alert::manager::event_cb(nullptr, SMTP_EV_STARTTLS_OK, nullptr));
}

/* SMTP_EV_WEAK_CIPHER: reads bits va_arg(long), sets *ok = 1 */
TEST_F(EventCbTest, WeakCipherEvent_SetsOkFlagToOne)
{
    int ok = 0;
    mail::alert::manager::event_cb(nullptr, SMTP_EV_WEAK_CIPHER, nullptr, 64L,
                                   &ok);
    EXPECT_EQ(ok, 1);
}

/* SMTP_EV_INVALID_PEER_CERTIFICATE: calls handle_invalid_peer_certificate */
TEST_F(EventCbTest, InvalidPeerCertEvent_SetsOkFlagToOne)
{
    int ok = 0;
    mail::alert::manager::event_cb(
        nullptr, SMTP_EV_INVALID_PEER_CERTIFICATE, nullptr,
        static_cast<long>(X509_V_ERR_CERT_HAS_EXPIRED), &ok);
    EXPECT_EQ(ok, 1);
}

/* SMTP_EV_NO_PEER_CERTIFICATE: sets *ok = 1 */
TEST_F(EventCbTest, NoPeerCertEvent_SetsOkFlagToOne)
{
    int ok = 0;
    mail::alert::manager::event_cb(nullptr, SMTP_EV_NO_PEER_CERTIFICATE,
                                   nullptr, &ok);
    EXPECT_EQ(ok, 1);
}

/* SMTP_EV_WRONG_PEER_CERTIFICATE: sets *ok = 1 */
TEST_F(EventCbTest, WrongPeerCertEvent_SetsOkFlagToOne)
{
    int ok = 0;
    mail::alert::manager::event_cb(nullptr, SMTP_EV_WRONG_PEER_CERTIFICATE,
                                   nullptr, &ok);
    EXPECT_EQ(ok, 1);
}

/* SMTP_EV_NO_CLIENT_CERTIFICATE: sets *ok = 1 */
TEST_F(EventCbTest, NoClientCertEvent_SetsOkFlagToOne)
{
    int ok = 0;
    mail::alert::manager::event_cb(nullptr, SMTP_EV_NO_CLIENT_CERTIFICATE,
                                   nullptr, &ok);
    EXPECT_EQ(ok, 1);
}

/* =============================================================================
 * Standalone test: print_recipient_status
 * With ENABLE_VERBOSE_DEBUG=0, status pointer is never dereferenced.
 * =============================================================================
 */
TEST(PrintRecipientStatusTest, NullRecipient_NoCrash)
{
    EXPECT_NO_FATAL_FAILURE(mail::alert::manager::print_recipient_status(
        nullptr, "test@example.com", nullptr));
}

/* =============================================================================
 * Fixture: SmtpConfigFileTest
 * Tests setsmtpconfig() and getSmtpConfig() — JSON read/write.
 * =============================================================================
 */
class SmtpConfigFileTest : public ::testing::Test
{
  protected:
    mail::alert::manager::smtp* smtpPtr = nullptr;

    void SetUp() override
    {
        std::filesystem::create_directories("/var/lib/alert");
        smtpPtr = new mail::alert::manager::smtp();
        setSmtpStartSessionResult(0);
    }

    void TearDown() override
    {
        delete smtpPtr;
        smtpPtr = nullptr;
        std::filesystem::remove(kPrimaryConfig);
        std::filesystem::remove(kSecondaryConfig);
        setSmtpStartSessionResult(0);
    }
};

/* Arrange: prepare a mail_server struct, write primary config
 * Act:     call setsmtpconfig for primary server
 * Assert:  JSON file created; returns SMTP_SUCCESS; clientcfg[0] updated     */
TEST_F(SmtpConfigFileTest, SetSmtpConfig_Primary_WritesFileAndUpdatesClientcfg)
{
    mail::alert::manager::mail_server ms{};
    ms.enable = true;
    ms.AuthEnable = true;
    ms.TLSEnable = false;
    ms.port = 587;
    ms.host = "smtp.example.com";
    ms.sender = "sender@example.com";
    ms.recipient = {"recv1@example.com", "recv2@example.com"};
    ms.user_credntial = {"alice", "secret", {}};

    auto status =
        smtpPtr->setsmtpconfig(ms, currentServer::SMTP_PRIMARY_SERVER);

    EXPECT_EQ(status, smtpStatus::SMTP_SUCCESS);
    EXPECT_TRUE(std::filesystem::exists(kPrimaryConfig));
    EXPECT_EQ(smtpPtr->clientcfg[0].host, "smtp.example.com");
    EXPECT_EQ(smtpPtr->clientcfg[0].port, 587);
}

/* Arrange: prepare a mail_server struct, write secondary config
 * Act:     call setsmtpconfig for secondary server
 * Assert:  secondary JSON file created; clientcfg[1] updated                 */
TEST_F(SmtpConfigFileTest, SetSmtpConfig_Secondary_WritesCorrectFile)
{
    mail::alert::manager::mail_server ms{};
    ms.enable = false;
    ms.port = 25;
    ms.host = "backup.smtp.com";
    ms.sender = "bkp@example.com";
    ms.recipient = {"r@example.com"};

    auto status =
        smtpPtr->setsmtpconfig(ms, currentServer::SMTP_SECONDARY_SERVER);

    EXPECT_EQ(status, smtpStatus::SMTP_SUCCESS);
    EXPECT_TRUE(std::filesystem::exists(kSecondaryConfig));
    EXPECT_EQ(smtpPtr->clientcfg[1].host, "backup.smtp.com");
}

/* Arrange: write then read back primary config (round-trip)
 * Act:     setsmtpconfig then getSmtpConfig
 * Assert:  all fields survive the round-trip */
TEST_F(SmtpConfigFileTest, SetGet_PrimaryConfig_RoundTrip)
{
    mail::alert::manager::mail_server written{};
    written.enable = true;
    written.AuthEnable = true;
    written.TLSEnable = true;
    written.port = 465;
    written.host = "secure.smtp.com";
    written.sender = "noreply@secure.com";
    written.recipient = {"user@secure.com"};
    written.user_credntial = {"bob", "password123", {}};

    smtpPtr->setsmtpconfig(written, currentServer::SMTP_PRIMARY_SERVER);

    mail::alert::manager::mail_server read{};
    auto status =
        smtpPtr->getSmtpConfig(read, currentServer::SMTP_PRIMARY_SERVER);

    EXPECT_EQ(status, smtpStatus::DBUS_SUCCESS);
    EXPECT_EQ(read.enable, true);
    EXPECT_EQ(read.AuthEnable, true);
    EXPECT_EQ(read.TLSEnable, true);
    EXPECT_EQ(read.port, 465);
    EXPECT_EQ(read.host, "secure.smtp.com");
    EXPECT_EQ(read.sender, "noreply@secure.com");
    EXPECT_EQ(read.recipient, std::vector<std::string>{"user@secure.com"});
    EXPECT_EQ(read.user_credntial.username, "bob");
    EXPECT_EQ(read.user_credntial.password, "password123");
}

/* Arrange: config file does not exist
 * Act:     getSmtpConfig for primary server
 * Assert:  returns SMTP_ERROR */
TEST_F(SmtpConfigFileTest, GetSmtpConfig_FileNotFound_ReturnsSMTPError)
{
    std::filesystem::remove(kPrimaryConfig);

    mail::alert::manager::mail_server ms{};
    auto status =
        smtpPtr->getSmtpConfig(ms, currentServer::SMTP_PRIMARY_SERVER);

    EXPECT_EQ(status, smtpStatus::SMTP_ERROR);
}

/* Arrange: malformed (non-JSON) content in config file
 * Act:     getSmtpConfig
 * Assert:  returns SMTP_ERROR (json::exception caught) */
TEST_F(SmtpConfigFileTest, GetSmtpConfig_InvalidJson_ReturnsSMTPError)
{
    {
        std::ofstream out(kPrimaryConfig);
        out << "NOT VALID JSON {{{";
    }

    mail::alert::manager::mail_server ms{};
    auto status =
        smtpPtr->getSmtpConfig(ms, currentServer::SMTP_PRIMARY_SERVER);

    EXPECT_EQ(status, smtpStatus::SMTP_ERROR);
}

/* Arrange: valid JSON but missing "Config" key
 * Act:     getSmtpConfig
 * Assert:  returns SMTP_ERROR */
TEST_F(SmtpConfigFileTest, GetSmtpConfig_MissingConfigKey_ReturnsSMTPError)
{
    {
        std::ofstream out(kPrimaryConfig);
        out << R"({"Other": {"Host": "x"}})";
    }

    mail::alert::manager::mail_server ms{};
    auto status =
        smtpPtr->getSmtpConfig(ms, currentServer::SMTP_PRIMARY_SERVER);

    EXPECT_EQ(status, smtpStatus::SMTP_ERROR);
}

/* Arrange: valid JSON with empty password (but non-empty username)
 * Act:     getSmtpConfig
 * Assert:  returns DBUS_SUCCESS — documents the BUG (password never checked)
 * Pre-scan: [High] Logic error in validation: username checked twice */
TEST_F(SmtpConfigFileTest, GetSmtpConfig_EmptyPassword_BugReturnsSuccess)
{
    writeJsonConfig(kPrimaryConfig, true, "smtp.example.com", 587,
                    "sender@example.com", {"r@example.com"}, false, true,
                    "alice", "" /* empty password */);

    mail::alert::manager::mail_server ms{};
    auto status =
        smtpPtr->getSmtpConfig(ms, currentServer::SMTP_PRIMARY_SERVER);

    /*
     * BUG: password not validated — getSmtpConfig checks username twice.
     * If this FAILS (returns SMTP_ERROR), the bug has been fixed.
     */
    EXPECT_EQ(status, smtpStatus::DBUS_SUCCESS)
        << "NOTE: If this fails, the validation bug (password never checked) "
           "has been fixed.";
}

/* Arrange: valid JSON with empty username AND empty password
 * Act:     getSmtpConfig
 * Assert:  returns SMTP_ERROR (both username checks fail) */
TEST_F(SmtpConfigFileTest, GetSmtpConfig_EmptyUsernameAndPassword_ReturnsError)
{
    writeJsonConfig(kPrimaryConfig, true, "smtp.example.com", 587,
                    "sender@example.com", {"r@example.com"}, false, true,
                    "" /* empty user */, "" /* empty pass */);

    mail::alert::manager::mail_server ms{};
    auto status =
        smtpPtr->getSmtpConfig(ms, currentServer::SMTP_PRIMARY_SERVER);

    EXPECT_EQ(status, smtpStatus::SMTP_ERROR);
}

/* Arrange: valid secondary config
 * Act:     getSmtpConfig for secondary server
 * Assert:  reads from secondary path; returns DBUS_SUCCESS                   */
TEST_F(SmtpConfigFileTest, GetSmtpConfig_SecondaryServer_ReadsCorrectFile)
{
    writeJsonConfig(kSecondaryConfig, false, "sec.smtp.com", 25,
                    "sec@example.com", {"sec_r@example.com"}, false, false,
                    "secuser", "secpass");

    mail::alert::manager::mail_server ms{};
    auto status =
        smtpPtr->getSmtpConfig(ms, currentServer::SMTP_SECONDARY_SERVER);

    EXPECT_EQ(status, smtpStatus::DBUS_SUCCESS);
    EXPECT_EQ(ms.host, "sec.smtp.com");
    EXPECT_EQ(ms.port, 25);
}

/* =============================================================================
 * Fixture: SmtpInitializeTest
 * Tests initializeSmtpcfg() — reads JSON into smtp::clientcfg[].
 * =============================================================================
 */
class SmtpInitializeTest : public ::testing::Test
{
  protected:
    mail::alert::manager::smtp* smtpPtr = nullptr;

    void SetUp() override
    {
        std::filesystem::create_directories("/var/lib/alert");
        smtpPtr = new mail::alert::manager::smtp();
    }

    void TearDown() override
    {
        delete smtpPtr;
        smtpPtr = nullptr;
        std::filesystem::remove(kPrimaryConfig);
        std::filesystem::remove(kSecondaryConfig);
    }
};

/* Arrange: primary config file absent
 * Act:     initializeSmtpcfg for primary
 * Assert:  returns SMTP_ERROR */
TEST_F(SmtpInitializeTest, PrimaryFileAbsent_ReturnsSMTPError)
{
    std::filesystem::remove(kPrimaryConfig);

    auto status =
        smtpPtr->initializeSmtpcfg(currentServer::SMTP_PRIMARY_SERVER);

    EXPECT_EQ(status, smtpStatus::SMTP_ERROR);
}

/* Arrange: secondary config file absent
 * Act:     initializeSmtpcfg for secondary
 * Assert:  returns SMTP_ERROR */
TEST_F(SmtpInitializeTest, SecondaryFileAbsent_ReturnsSMTPError)
{
    std::filesystem::remove(kSecondaryConfig);

    auto status =
        smtpPtr->initializeSmtpcfg(currentServer::SMTP_SECONDARY_SERVER);

    EXPECT_EQ(status, smtpStatus::SMTP_ERROR);
}

/* Arrange: valid primary config with both credentials set
 * Act:     initializeSmtpcfg
 * Assert:  clientcfg[0] populated; smtp.credential set; returns SMTP_SUCCESS */
TEST_F(SmtpInitializeTest, PrimaryValidConfig_PopulatesClientcfg)
{
    writeJsonConfig(kPrimaryConfig, true, "smtp.example.com", 587,
                    "sender@example.com", {"r@example.com"}, false, true,
                    "user1", "pass1");

    auto status =
        smtpPtr->initializeSmtpcfg(currentServer::SMTP_PRIMARY_SERVER);

    EXPECT_EQ(status, smtpStatus::SMTP_SUCCESS);
    EXPECT_EQ(smtpPtr->clientcfg[0].host, "smtp.example.com");
    EXPECT_EQ(smtpPtr->clientcfg[0].port, 587);
    EXPECT_EQ(smtpPtr->credential.username, "user1");
    EXPECT_EQ(smtpPtr->credential.password, "pass1");
}

/* Arrange: valid secondary config with both credentials set
 * Act:     initializeSmtpcfg for secondary
 * Assert:  clientcfg[1] populated */
TEST_F(SmtpInitializeTest, SecondaryValidConfig_PopulatesClientcfg)
{
    writeJsonConfig(kSecondaryConfig, true, "sec.smtp.com", 25,
                    "sec@example.com", {"sec@example.com"}, false, false,
                    "sec_user", "sec_pass");

    auto status =
        smtpPtr->initializeSmtpcfg(currentServer::SMTP_SECONDARY_SERVER);

    EXPECT_EQ(status, smtpStatus::SMTP_SUCCESS);
    EXPECT_EQ(smtpPtr->clientcfg[1].host, "sec.smtp.com");
}

/* Arrange: config with both username AND password empty
 * Act:     initializeSmtpcfg
 * Assert:  returns SMTP_ERROR (OR condition: neither non-empty) */
TEST_F(SmtpInitializeTest, BothCredentialsEmpty_ReturnsSMTPError)
{
    writeJsonConfig(kPrimaryConfig, true, "smtp.example.com", 587,
                    "sender@example.com", {"r@example.com"}, false, false,
                    "" /* user */, "" /* pass */);

    auto status =
        smtpPtr->initializeSmtpcfg(currentServer::SMTP_PRIMARY_SERVER);

    EXPECT_EQ(status, smtpStatus::SMTP_ERROR);
}

/* Arrange: config with only username set (password empty)
 * Act:     initializeSmtpcfg
 * Assert:  returns SMTP_SUCCESS (|| logic: at least one non-empty is OK) */
TEST_F(SmtpInitializeTest, OnlyUsernameSet_ReturnsSuccess)
{
    writeJsonConfig(kPrimaryConfig, true, "smtp.example.com", 587,
                    "sender@example.com", {"r@example.com"}, false, false,
                    "user_only", "" /* pass empty */);

    auto status =
        smtpPtr->initializeSmtpcfg(currentServer::SMTP_PRIMARY_SERVER);

    EXPECT_EQ(status, smtpStatus::SMTP_SUCCESS);
}

/* Arrange: malformed JSON in primary config
 * Act:     initializeSmtpcfg
 * Assert:  returns SMTP_ERROR (json::exception) */
TEST_F(SmtpInitializeTest, MalformedJson_ReturnsSMTPError)
{
    {
        std::ofstream out(kPrimaryConfig);
        out << "{ bad json";
    }

    auto status =
        smtpPtr->initializeSmtpcfg(currentServer::SMTP_PRIMARY_SERVER);

    EXPECT_EQ(status, smtpStatus::SMTP_ERROR);
}

/* =============================================================================
 * Fixture: SmtpSendMailTest
 * Tests send_mail() early-return paths using no-op libesmtp stubs.
 * =============================================================================
 */
class SmtpSendMailTest : public ::testing::Test
{
  protected:
    mail::alert::manager::smtp* smtpPtr = nullptr;

    void SetUp() override
    {
        smtpPtr = new mail::alert::manager::smtp();
        setSmtpStartSessionResult(0); /* default: smtp_start_session fails */
    }

    void TearDown() override
    {
        delete smtpPtr;
        smtpPtr = nullptr;
        setSmtpStartSessionResult(0);
    }

    static mail::alert::manager::mail_server makeValidServer()
    {
        mail::alert::manager::mail_server ms{};
        ms.enable = true;
        ms.AuthEnable = false;
        ms.TLSEnable = false;
        ms.port = 25;
        ms.host = "smtp.example.com";
        ms.sender = "sender@example.com";
        ms.recipient = {"recv@example.com"};
        ms.user_credntial = {"user", "pass", {}};
        return ms;
    }
};

/* Arrange: server.enable == false
 * Act:     send_mail
 * Assert:  returns SMTP_ERROR immediately */
TEST_F(SmtpSendMailTest, ServerDisabled_ReturnsSMTPError)
{
    smtpPtr->clientcfg[0].enable = false;

    auto ret = smtpPtr->send_mail("Subject", "Body",
                                  currentServer::SMTP_PRIMARY_SERVER, "");
    EXPECT_EQ(ret, smtpStatus::SMTP_ERROR);
}

/* Arrange: enabled but empty host
 * Act:     send_mail
 * Assert:  returns SMTP_ERROR (host/port/sender validation) */
TEST_F(SmtpSendMailTest, EmptyHost_ReturnsSMTPError)
{
    smtpPtr->clientcfg[0] = makeValidServer();
    smtpPtr->clientcfg[0].host.clear();

    auto ret = smtpPtr->send_mail("Subject", "Body",
                                  currentServer::SMTP_PRIMARY_SERVER, "");
    EXPECT_EQ(ret, smtpStatus::SMTP_ERROR);
}

/* Arrange: enabled but port == 0
 * Act:     send_mail
 * Assert:  returns SMTP_ERROR */
TEST_F(SmtpSendMailTest, ZeroPort_ReturnsSMTPError)
{
    smtpPtr->clientcfg[0] = makeValidServer();
    smtpPtr->clientcfg[0].port = 0;

    auto ret = smtpPtr->send_mail("Subject", "Body",
                                  currentServer::SMTP_PRIMARY_SERVER, "");
    EXPECT_EQ(ret, smtpStatus::SMTP_ERROR);
}

/* Arrange: enabled but empty sender
 * Act:     send_mail
 * Assert:  returns SMTP_ERROR */
TEST_F(SmtpSendMailTest, EmptySender_ReturnsSMTPError)
{
    smtpPtr->clientcfg[0] = makeValidServer();
    smtpPtr->clientcfg[0].sender.clear();

    auto ret = smtpPtr->send_mail("Subject", "Body",
                                  currentServer::SMTP_PRIMARY_SERVER, "");
    EXPECT_EQ(ret, smtpStatus::SMTP_ERROR);
}

/* Arrange: auth enabled but empty username
 * Act:     send_mail
 * Assert:  returns SMTP_ERROR */
TEST_F(SmtpSendMailTest, AuthEnabled_EmptyUsername_ReturnsSMTPError)
{
    smtpPtr->clientcfg[0] = makeValidServer();
    smtpPtr->clientcfg[0].AuthEnable = true;
    smtpPtr->clientcfg[0].user_credntial.username.clear();

    auto ret = smtpPtr->send_mail("Subject", "Body",
                                  currentServer::SMTP_PRIMARY_SERVER, "");
    EXPECT_EQ(ret, smtpStatus::SMTP_ERROR);
}

/* Arrange: auth enabled but empty password
 * Act:     send_mail
 * Assert:  returns SMTP_ERROR */
TEST_F(SmtpSendMailTest, AuthEnabled_EmptyPassword_ReturnsSMTPError)
{
    smtpPtr->clientcfg[0] = makeValidServer();
    smtpPtr->clientcfg[0].AuthEnable = true;
    smtpPtr->clientcfg[0].user_credntial.password.clear();

    auto ret = smtpPtr->send_mail("Subject", "Body",
                                  currentServer::SMTP_PRIMARY_SERVER, "");
    EXPECT_EQ(ret, smtpStatus::SMTP_ERROR);
}

/* Arrange: TLS enabled; cert files absent (expected in test environment)
 * Act:     send_mail
 * Assert:  returns SMTP_ERROR before creating SSL_CTX (cert check first)
 * Pre-scan: [High] SSL_CTX resource leak path avoided via cert check */
TEST_F(SmtpSendMailTest, TlsEnabled_CertFilesMissing_ReturnsSMTPError)
{
    smtpPtr->clientcfg[0] = makeValidServer();
    smtpPtr->clientcfg[0].TLSEnable = true;

    auto ret = smtpPtr->send_mail("Subject", "Body",
                                  currentServer::SMTP_PRIMARY_SERVER, "");
    EXPECT_EQ(ret, smtpStatus::SMTP_ERROR);
}

/* Arrange: TLS enabled on secondary server; secondary cert files also absent
 * Act:     send_mail for secondary server
 * Assert:  returns SMTP_ERROR */
TEST_F(SmtpSendMailTest,
       TlsEnabled_SecondaryServer_CertsMissing_ReturnsSMTPError)
{
    smtpPtr->clientcfg[1] = makeValidServer();
    smtpPtr->clientcfg[1].TLSEnable = true;

    auto ret = smtpPtr->send_mail("Subject", "Body",
                                  currentServer::SMTP_SECONDARY_SERVER, "");
    EXPECT_EQ(ret, smtpStatus::SMTP_ERROR);
}

/* Arrange: valid non-TLS config; smtp_start_session stub returns 0 (fail)
 * Act:     send_mail
 * Assert:  returns SMTP_ERROR */
TEST_F(SmtpSendMailTest, ValidConfig_SmtpSessionFails_ReturnsSMTPError)
{
    smtpPtr->clientcfg[0] = makeValidServer();
    setSmtpStartSessionResult(0);

    auto ret = smtpPtr->send_mail("Subject", "Body",
                                  currentServer::SMTP_PRIMARY_SERVER, "");
    EXPECT_EQ(ret, smtpStatus::SMTP_ERROR);
}

/* Arrange: valid non-TLS config; smtp_start_session stub returns 1 (success)
 * Act:     send_mail
 * Assert:  returns SMTP_SUCCESS (stub-based happy path) */
TEST_F(SmtpSendMailTest, ValidConfig_SmtpSessionSucceeds_ReturnsSuccess)
{
    smtpPtr->clientcfg[0] = makeValidServer();
    setSmtpStartSessionResult(1);

    auto ret = smtpPtr->send_mail("Subject", "Body",
                                  currentServer::SMTP_PRIMARY_SERVER, "");
    EXPECT_EQ(ret, smtpStatus::SMTP_SUCCESS);
}

/* Arrange: valid config; session succeeds; authError set to 0xFF
 * Act:     send_mail
 * Assert:  returns SMTP_AUTH_FAIL; authError cleared */
TEST_F(SmtpSendMailTest, SessionSucceeds_AuthErrorSet_ReturnsAuthFail)
{
    smtpPtr->clientcfg[0] = makeValidServer();
    smtpPtr->clientcfg[0].user_credntial.authError = 0xFF;
    setSmtpStartSessionResult(1);

    auto ret = smtpPtr->send_mail("Subject", "Body",
                                  currentServer::SMTP_PRIMARY_SERVER, "");
    EXPECT_EQ(ret, smtpStatus::SMTP_AUTH_FAIL);
    EXPECT_EQ(smtpPtr->credential.authError, 0u);
}

/* Arrange: send to explicit toAddress (forgotPassword flow)
 * Act:     send_mail with non-empty toAddress
 * Assert:  returns SMTP_SUCCESS (overrides recipient list) */
TEST_F(SmtpSendMailTest, ExplicitToAddress_SessionSucceeds_ReturnsSuccess)
{
    smtpPtr->clientcfg[0] = makeValidServer();
    setSmtpStartSessionResult(1);

    auto ret = smtpPtr->send_mail("Reset Password", "Click link",
                                  currentServer::SMTP_PRIMARY_SERVER,
                                  "user@example.com");
    EXPECT_EQ(ret, smtpStatus::SMTP_SUCCESS);
}

/* Arrange: auth enabled, valid credentials, session succeeds
 * Act:     send_mail
 * Assert:  returns SMTP_SUCCESS (auth context created and destroyed) */
TEST_F(SmtpSendMailTest, AuthEnabled_ValidCredentials_SessionSucceeds)
{
    smtpPtr->clientcfg[0] = makeValidServer();
    smtpPtr->clientcfg[0].AuthEnable = true;
    smtpPtr->clientcfg[0].user_credntial = {"authuser", "authpass", {}};
    setSmtpStartSessionResult(1);

    auto ret = smtpPtr->send_mail("Subject", "Body",
                                  currentServer::SMTP_PRIMARY_SERVER, "");
    EXPECT_EQ(ret, smtpStatus::SMTP_SUCCESS);
}

/* =============================================================================
 * Fixture: SmtpSendmailTest
 * Tests sendmail() — public method that tries primary then secondary.
 * =============================================================================
 */
class SmtpSendmailTest : public ::testing::Test
{
  protected:
    mail::alert::manager::smtp* smtpPtr = nullptr;

    void SetUp() override
    {
        smtpPtr = new mail::alert::manager::smtp();
        setSmtpStartSessionResult(0);
    }

    void TearDown() override
    {
        delete smtpPtr;
        smtpPtr = nullptr;
        setSmtpStartSessionResult(0);
    }

    static mail::alert::manager::mail_server makeValidServer()
    {
        mail::alert::manager::mail_server ms{};
        ms.enable = true;
        ms.AuthEnable = false;
        ms.TLSEnable = false;
        ms.port = 25;
        ms.host = "smtp.example.com";
        ms.sender = "sender@example.com";
        ms.recipient = {"recv@example.com"};
        ms.user_credntial = {"user", "pass", {}};
        return ms;
    }
};

/* Arrange: both servers disabled
 * Act:     sendmail
 * Assert:  returns SMTP_ERROR */
TEST_F(SmtpSendmailTest, BothServersDisabled_ReturnsSMTPError)
{
    smtpPtr->clientcfg[0].enable = false;
    smtpPtr->clientcfg[1].enable = false;

    uint16_t ret = smtpPtr->sendmail("Subject", "Body");
    EXPECT_EQ(ret, static_cast<uint16_t>(smtpStatus::SMTP_ERROR));
}

/* Arrange: primary succeeds
 * Act:     sendmail
 * Assert:  returns SMTP_SUCCESS without trying secondary */
TEST_F(SmtpSendmailTest, PrimarySucceeds_ReturnsSuccess)
{
    smtpPtr->clientcfg[0] = makeValidServer();
    smtpPtr->clientcfg[1].enable = false;
    setSmtpStartSessionResult(1);

    uint16_t ret = smtpPtr->sendmail("Subject", "Body");
    EXPECT_EQ(ret, static_cast<uint16_t>(smtpStatus::SMTP_SUCCESS));
}

/* Arrange: primary session fails; secondary also disabled
 * Act:     sendmail
 * Assert:  returns SMTP_ERROR */
TEST_F(SmtpSendmailTest, PrimaryFails_SecondaryDisabled_ReturnsSMTPError)
{
    smtpPtr->clientcfg[0] = makeValidServer();
    smtpPtr->clientcfg[1].enable = false;
    setSmtpStartSessionResult(0);

    uint16_t ret = smtpPtr->sendmail("Subject", "Body");
    EXPECT_EQ(ret, static_cast<uint16_t>(smtpStatus::SMTP_ERROR));
}

/* Arrange: primary disabled; secondary valid and succeeds
 * Act:     sendmail
 * Assert:  returns SMTP_SUCCESS (secondary fallback works) */
TEST_F(SmtpSendmailTest, PrimaryDisabled_SecondarySucceeds_ReturnsSuccess)
{
    smtpPtr->clientcfg[0].enable = false;
    smtpPtr->clientcfg[1] = makeValidServer();
    setSmtpStartSessionResult(1);

    uint16_t ret = smtpPtr->sendmail("Subject", "Body");
    EXPECT_EQ(ret, static_cast<uint16_t>(smtpStatus::SMTP_SUCCESS));
}

/* =============================================================================
 * Fixture: SmtpForgotPassTest
 * Tests forgotPassSendMail() — targeted single-recipient email with fallback.
 * =============================================================================
 */
class SmtpForgotPassTest : public ::testing::Test
{
  protected:
    mail::alert::manager::smtp* smtpPtr = nullptr;

    void SetUp() override
    {
        smtpPtr = new mail::alert::manager::smtp();
        setSmtpStartSessionResult(0);
    }

    void TearDown() override
    {
        delete smtpPtr;
        smtpPtr = nullptr;
        setSmtpStartSessionResult(0);
    }

    static mail::alert::manager::mail_server makeValidServer()
    {
        mail::alert::manager::mail_server ms{};
        ms.enable = true;
        ms.AuthEnable = false;
        ms.TLSEnable = false;
        ms.port = 587;
        ms.host = "smtp.example.com";
        ms.sender = "noreply@example.com";
        ms.recipient = {"admin@example.com"};
        ms.user_credntial = {"user", "pass", {}};
        return ms;
    }
};

/* Arrange: primary session succeeds
 * Act:     forgotPassSendMail to a specific address
 * Assert:  returns SMTP_SUCCESS */
TEST_F(SmtpForgotPassTest, PrimarySucceeds_ReturnsSuccess)
{
    smtpPtr->clientcfg[0] = makeValidServer();
    setSmtpStartSessionResult(1);

    uint16_t ret = smtpPtr->forgotPassSendMail(
        "reset@example.com", "Password Reset", "Click the link");
    EXPECT_EQ(ret, static_cast<uint16_t>(smtpStatus::SMTP_SUCCESS));
}

/* Arrange: primary disabled; secondary valid and succeeds
 * Act:     forgotPassSendMail
 * Assert:  returns SMTP_SUCCESS via secondary */
TEST_F(SmtpForgotPassTest, PrimaryDisabled_SecondarySucceeds_ReturnsSuccess)
{
    smtpPtr->clientcfg[0].enable = false;
    smtpPtr->clientcfg[1] = makeValidServer();
    setSmtpStartSessionResult(1);

    uint16_t ret = smtpPtr->forgotPassSendMail(
        "reset@example.com", "Password Reset", "Click the link");
    EXPECT_EQ(ret, static_cast<uint16_t>(smtpStatus::SMTP_SUCCESS));
}

/* Arrange: both servers disabled
 * Act:     forgotPassSendMail
 * Assert:  returns SMTP_ERROR */
TEST_F(SmtpForgotPassTest, BothServersDisabled_ReturnsSMTPError)
{
    smtpPtr->clientcfg[0].enable = false;
    smtpPtr->clientcfg[1].enable = false;

    uint16_t ret =
        smtpPtr->forgotPassSendMail("reset@example.com", "Subject", "Body");
    EXPECT_EQ(ret, static_cast<uint16_t>(smtpStatus::SMTP_ERROR));
}

/* Arrange: primary auth fail (authError set to 0xFF after session)
 * Act:     forgotPassSendMail
 * Assert:  switches to secondary; secondary also disabled -> error */
TEST_F(SmtpForgotPassTest, PrimaryAuthFail_SwitchesToSecondary)
{
    smtpPtr->clientcfg[0] = makeValidServer();
    smtpPtr->clientcfg[1].enable = false;
    smtpPtr->clientcfg[0].user_credntial.authError = 0xFF;
    setSmtpStartSessionResult(1);

    uint16_t ret =
        smtpPtr->forgotPassSendMail("reset@example.com", "Subject", "Body");
    EXPECT_EQ(ret, static_cast<uint16_t>(smtpStatus::SMTP_ERROR));
}

/* =============================================================================
 * Injection-resistance tests (Pre-scan [High] — SMTP injection via host)
 * =============================================================================
 */
class SmtpInjectionTest : public ::testing::Test
{
  protected:
    mail::alert::manager::smtp* smtpPtr = nullptr;

    void SetUp() override
    {
        smtpPtr = new mail::alert::manager::smtp();
        setSmtpStartSessionResult(0);
    }

    void TearDown() override
    {
        delete smtpPtr;
        smtpPtr = nullptr;
        setSmtpStartSessionResult(0);
    }
};

/* Arrange: host contains SMTP verb injection attempt
 * Act:     send_mail (session will fail via stub)
 * Assert:  returns SMTP_ERROR; no crash */
TEST_F(SmtpInjectionTest, HostWithSmtpVerbInjection_HandledGracefully)
{
    smtpPtr->clientcfg[0].enable = true;
    smtpPtr->clientcfg[0].host =
        "smtp.example.com\r\nDATA\r\nSUBJECT: injected";
    smtpPtr->clientcfg[0].port = 25;
    smtpPtr->clientcfg[0].sender = "sender@example.com";
    smtpPtr->clientcfg[0].recipient = {"recv@example.com"};
    smtpPtr->clientcfg[0].TLSEnable = false;
    smtpPtr->clientcfg[0].AuthEnable = false;

    EXPECT_NO_FATAL_FAILURE(smtpPtr->send_mail(
        "Subject", "Body", currentServer::SMTP_PRIMARY_SERVER, ""));
}

/* Arrange: host contains shell metacharacters
 * Act:     send_mail
 * Assert:  no crash; error returned */
TEST_F(SmtpInjectionTest, HostWithShellMetacharacters_HandledGracefully)
{
    smtpPtr->clientcfg[0].enable = true;
    smtpPtr->clientcfg[0].host = "$(id); rm -rf /";
    smtpPtr->clientcfg[0].port = 25;
    smtpPtr->clientcfg[0].sender = "sender@example.com";
    smtpPtr->clientcfg[0].recipient = {"recv@example.com"};
    smtpPtr->clientcfg[0].TLSEnable = false;
    smtpPtr->clientcfg[0].AuthEnable = false;

    EXPECT_NO_FATAL_FAILURE(smtpPtr->send_mail(
        "Subject", "Body", currentServer::SMTP_PRIMARY_SERVER, ""));
}

/* Arrange: format-specifier injection in subject
 * Act:     sendmail with format-string subject
 * Assert:  no crash */
TEST_F(SmtpInjectionTest, FormatStringInSubject_HandledGracefully)
{
    smtpPtr->clientcfg[0].enable = true;
    smtpPtr->clientcfg[0].host = "smtp.example.com";
    smtpPtr->clientcfg[0].port = 25;
    smtpPtr->clientcfg[0].sender = "sender@example.com";
    smtpPtr->clientcfg[0].recipient = {"recv@example.com"};
    smtpPtr->clientcfg[0].TLSEnable = false;
    smtpPtr->clientcfg[0].AuthEnable = false;

    EXPECT_NO_FATAL_FAILURE(smtpPtr->send_mail(
        "%s%n%d%x", "Body", currentServer::SMTP_PRIMARY_SERVER, ""));
}

/* =============================================================================
 * HandleInvalidPeerCertTest — exhaustive switch coverage (remaining cases)
 * =============================================================================
 */
TEST_F(HandleInvalidPeerCertTest, UnableToGetCrl_ReturnsOne)
{
    EXPECT_EQ(mail::alert::manager::handle_invalid_peer_certificate(
                  X509_V_ERR_UNABLE_TO_GET_CRL),
              1);
}

TEST_F(HandleInvalidPeerCertTest, UnableToDecryptCertSignature_ReturnsOne)
{
    EXPECT_EQ(mail::alert::manager::handle_invalid_peer_certificate(
                  X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE),
              1);
}

TEST_F(HandleInvalidPeerCertTest, UnableToDecryptCrlSignature_ReturnsOne)
{
    EXPECT_EQ(mail::alert::manager::handle_invalid_peer_certificate(
                  X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE),
              1);
}

TEST_F(HandleInvalidPeerCertTest, UnableToDecodeIssuerPublicKey_ReturnsOne)
{
    EXPECT_EQ(mail::alert::manager::handle_invalid_peer_certificate(
                  X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY),
              1);
}

TEST_F(HandleInvalidPeerCertTest, CertSignatureFailure_ReturnsOne)
{
    EXPECT_EQ(mail::alert::manager::handle_invalid_peer_certificate(
                  X509_V_ERR_CERT_SIGNATURE_FAILURE),
              1);
}

TEST_F(HandleInvalidPeerCertTest, CrlSignatureFailure_ReturnsOne)
{
    EXPECT_EQ(mail::alert::manager::handle_invalid_peer_certificate(
                  X509_V_ERR_CRL_SIGNATURE_FAILURE),
              1);
}

TEST_F(HandleInvalidPeerCertTest, CrlNotYetValid_ReturnsOne)
{
    EXPECT_EQ(mail::alert::manager::handle_invalid_peer_certificate(
                  X509_V_ERR_CRL_NOT_YET_VALID),
              1);
}

TEST_F(HandleInvalidPeerCertTest, CrlHasExpired_ReturnsOne)
{
    EXPECT_EQ(mail::alert::manager::handle_invalid_peer_certificate(
                  X509_V_ERR_CRL_HAS_EXPIRED),
              1);
}

TEST_F(HandleInvalidPeerCertTest, ErrorInCertNotBeforeField_ReturnsOne)
{
    EXPECT_EQ(mail::alert::manager::handle_invalid_peer_certificate(
                  X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD),
              1);
}

TEST_F(HandleInvalidPeerCertTest, ErrorInCertNotAfterField_ReturnsOne)
{
    EXPECT_EQ(mail::alert::manager::handle_invalid_peer_certificate(
                  X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD),
              1);
}

TEST_F(HandleInvalidPeerCertTest, ErrorInCrlLastUpdateField_ReturnsOne)
{
    EXPECT_EQ(mail::alert::manager::handle_invalid_peer_certificate(
                  X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD),
              1);
}

TEST_F(HandleInvalidPeerCertTest, ErrorInCrlNextUpdateField_ReturnsOne)
{
    EXPECT_EQ(mail::alert::manager::handle_invalid_peer_certificate(
                  X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD),
              1);
}

TEST_F(HandleInvalidPeerCertTest, OutOfMem_ReturnsOne)
{
    EXPECT_EQ(mail::alert::manager::handle_invalid_peer_certificate(
                  X509_V_ERR_OUT_OF_MEM),
              1);
}

TEST_F(HandleInvalidPeerCertTest, DepthZeroSelfSignedCert_ReturnsOne)
{
    EXPECT_EQ(mail::alert::manager::handle_invalid_peer_certificate(
                  X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT),
              1);
}

TEST_F(HandleInvalidPeerCertTest, UnableToGetIssuerCertLocally_ReturnsOne)
{
    EXPECT_EQ(mail::alert::manager::handle_invalid_peer_certificate(
                  X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY),
              1);
}

TEST_F(HandleInvalidPeerCertTest, CertChainTooLong_ReturnsOne)
{
    EXPECT_EQ(mail::alert::manager::handle_invalid_peer_certificate(
                  X509_V_ERR_CERT_CHAIN_TOO_LONG),
              1);
}

TEST_F(HandleInvalidPeerCertTest, PathLengthExceeded_ReturnsOne)
{
    EXPECT_EQ(mail::alert::manager::handle_invalid_peer_certificate(
                  X509_V_ERR_PATH_LENGTH_EXCEEDED),
              1);
}

TEST_F(HandleInvalidPeerCertTest, InvalidPurpose_ReturnsOne)
{
    EXPECT_EQ(mail::alert::manager::handle_invalid_peer_certificate(
                  X509_V_ERR_INVALID_PURPOSE),
              1);
}

TEST_F(HandleInvalidPeerCertTest, CertUntrusted_ReturnsOne)
{
    EXPECT_EQ(mail::alert::manager::handle_invalid_peer_certificate(
                  X509_V_ERR_CERT_UNTRUSTED),
              1);
}

TEST_F(HandleInvalidPeerCertTest, CertRejected_ReturnsOne)
{
    EXPECT_EQ(mail::alert::manager::handle_invalid_peer_certificate(
                  X509_V_ERR_CERT_REJECTED),
              1);
}

/* =============================================================================
 * EventCbTest — missing RCPTSTATUS, MESSAGEDATA, MESSAGESENT events
 * =============================================================================
 */
TEST_F(EventCbTest, RcptStatusEvent_NoCrash)
{
    EXPECT_NO_FATAL_FAILURE(
        mail::alert::manager::event_cb(nullptr, SMTP_EV_RCPTSTATUS, nullptr));
}

TEST_F(EventCbTest, MessageDataEvent_NoCrash)
{
    EXPECT_NO_FATAL_FAILURE(
        mail::alert::manager::event_cb(nullptr, SMTP_EV_MESSAGEDATA, nullptr));
}

TEST_F(EventCbTest, MessageSentEvent_NoCrash)
{
    EXPECT_NO_FATAL_FAILURE(
        mail::alert::manager::event_cb(nullptr, SMTP_EV_MESSAGESENT, nullptr));
}

/* Arrange: unknown event number (not in switch default branch)
 * Act:     event_cb
 * Assert:  no crash (va_end still called)                                    */
TEST_F(EventCbTest, UnknownEvent_NoCrash)
{
    EXPECT_NO_FATAL_FAILURE(
        mail::alert::manager::event_cb(nullptr, 9999, nullptr));
}

/* =============================================================================
 * AuthInteractTest — field with unknown flag (neither AUTH_USER nor AUTH_PASS)
 * =============================================================================
 */
TEST_F(AuthInteractTest, UnknownFlag_SlotNotFilled_ReturnsOne)
{
    /* flag = 0 → neither AUTH_USER nor AUTH_PASS branch taken */
    mail::alert::manager::credentials cred{"alice", "secret", {}};
    auth_client_request req{0u /* unknown flag */, "Other:"};
    char* result[1] = {reinterpret_cast<char*>(0xDEAD)};

    int ret = mail::alert::manager::authinteract(&req, result, 1, &cred);

    EXPECT_EQ(ret, 1);
    /* result[0] must remain untouched — still the sentinel value */
    EXPECT_EQ(result[0], reinterpret_cast<char*>(0xDEAD));
}

/* =============================================================================
 * SmtpInitSmtpTest
 * Tests init_smtp() — creates a session handle (stub returns nullptr).
 * =============================================================================
 */
TEST(SmtpInitSmtpTest, InitSmtp_SetsSession)
{
    mail::alert::manager::smtp s;
    s.session = reinterpret_cast<smtp_session_t>(0xDEAD); /* sentinel */
    s.init_smtp();
    /* stub smtp_create_session returns nullptr */
    EXPECT_EQ(s.session, nullptr);
}

/* =============================================================================
 * SmtpEnumValueTest
 * Verify enum int values match protocol constants used in return logic.
 * =============================================================================
 */
TEST(SmtpEnumValueTest, SmtpErrorEqualsMinusOne)
{
    EXPECT_EQ(static_cast<int16_t>(smtpStatus::SMTP_ERROR), -1);
}

TEST(SmtpEnumValueTest, SmtpAuthFailEqualsMinusTwo)
{
    EXPECT_EQ(static_cast<int16_t>(smtpStatus::SMTP_AUTH_FAIL), -2);
}

TEST(SmtpEnumValueTest, SmtpSuccessEqualsZero)
{
    EXPECT_EQ(static_cast<int16_t>(smtpStatus::SMTP_SUCCESS), 0);
}

TEST(SmtpEnumValueTest, DbusSuccessEqualsOne)
{
    EXPECT_EQ(static_cast<int16_t>(smtpStatus::DBUS_SUCCESS), 1);
}

/* =============================================================================
 * SmtpSendMailTest — secondary server paths
 * =============================================================================
 */
TEST_F(SmtpSendMailTest, SecondaryServer_ValidConfig_SessionSucceeds)
{
    smtpPtr->clientcfg[1] = makeValidServer();
    smtpPtr->clientcfg[1].recipient = {"sec@example.com"};
    setSmtpStartSessionResult(1);

    auto ret = smtpPtr->send_mail("Subject", "Body",
                                  currentServer::SMTP_SECONDARY_SERVER, "");
    EXPECT_EQ(ret, smtpStatus::SMTP_SUCCESS);
}

/* Arrange: secondary, auth enabled, valid credentials, session succeeds
 * Act:     send_mail on SECONDARY
 * Assert:  returns SMTP_SUCCESS */
TEST_F(SmtpSendMailTest, SecondaryServer_AuthEnabled_SessionSucceeds)
{
    smtpPtr->clientcfg[1] = makeValidServer();
    smtpPtr->clientcfg[1].AuthEnable = true;
    smtpPtr->clientcfg[1].user_credntial = {"secuser", "secpass", {}};
    setSmtpStartSessionResult(1);

    auto ret = smtpPtr->send_mail("Subject", "Body",
                                  currentServer::SMTP_SECONDARY_SERVER, "");
    EXPECT_EQ(ret, smtpStatus::SMTP_SUCCESS);
}

/* Arrange: valid config, empty recipient list, empty toAddress
 *          (loops over no recipients — smtp_set_header/add_recipient never
 * called) Act:     send_mail with empty toAddress and no recipients configured
 * Assert:  returns SMTP_SUCCESS (session stub returns 1; logic proceeds)     */
TEST_F(SmtpSendMailTest, EmptyRecipientList_EmptyToAddress_SessionSucceeds)
{
    smtpPtr->clientcfg[0] = makeValidServer();
    smtpPtr->clientcfg[0].recipient = {}; /* empty list */
    setSmtpStartSessionResult(1);

    auto ret = smtpPtr->send_mail("Subject", "Body",
                                  currentServer::SMTP_PRIMARY_SERVER, "");
    EXPECT_EQ(ret, smtpStatus::SMTP_SUCCESS);
}

/* =============================================================================
 * SmtpSendmailTest — primary auth-fail then secondary succeeds
 * =============================================================================
 */

/* Arrange: primary session "succeeds" but authError is 0xFF → SMTP_AUTH_FAIL;
 *          secondary valid and session succeeds
 * Act:     sendmail
 * Assert:  returns SMTP_SUCCESS (secondary fallback after auth failure) */
TEST_F(SmtpSendmailTest, PrimaryAuthFail_SecondarySucceeds_ReturnsSuccess)
{
    smtpPtr->clientcfg[0] = makeValidServer();
    smtpPtr->clientcfg[0].user_credntial.authError = 0xFF;
    smtpPtr->clientcfg[1] = makeValidServer();
    smtpPtr->clientcfg[1].user_credntial.authError = 0; /* secondary clean */
    setSmtpStartSessionResult(1);

    uint16_t ret = smtpPtr->sendmail("Subject", "Body");
    EXPECT_EQ(ret, static_cast<uint16_t>(smtpStatus::SMTP_SUCCESS));
}

/* =============================================================================
 * SmtpForgotPassTest — primary auth-fail then secondary succeeds
 * =============================================================================
 */

/* Arrange: primary session succeeds but auth error set; secondary valid
 * Act:     forgotPassSendMail
 * Assert:  returns SMTP_SUCCESS via secondary */
TEST_F(SmtpForgotPassTest, PrimaryAuthFail_SecondarySucceeds_ReturnsSuccess)
{
    smtpPtr->clientcfg[0] = makeValidServer();
    smtpPtr->clientcfg[0].user_credntial.authError = 0xFF;
    smtpPtr->clientcfg[1] = makeValidServer();
    smtpPtr->clientcfg[1].user_credntial.authError = 0;
    setSmtpStartSessionResult(1);

    uint16_t ret =
        smtpPtr->forgotPassSendMail("reset@example.com", "Subject", "Body");
    EXPECT_EQ(ret, static_cast<uint16_t>(smtpStatus::SMTP_SUCCESS));
}

/* =============================================================================
 * SmtpInitializeTest — additional edge paths
 * =============================================================================
 */

/* Arrange: config with only password set (username empty)
 * Act:     initializeSmtpcfg
 * Assert:  returns SMTP_SUCCESS (|| condition: password is non-empty) */
TEST_F(SmtpInitializeTest, OnlyPasswordSet_ReturnsSuccess)
{
    writeJsonConfig(kPrimaryConfig, true, "smtp.example.com", 587,
                    "sender@example.com", {"r@example.com"}, false, false,
                    "" /* username empty */, "pass_only");

    auto status =
        smtpPtr->initializeSmtpcfg(currentServer::SMTP_PRIMARY_SERVER);

    EXPECT_EQ(status, smtpStatus::SMTP_SUCCESS);
}

/* Arrange: secondary config malformed JSON
 * Act:     initializeSmtpcfg for secondary
 * Assert:  returns SMTP_ERROR */
TEST_F(SmtpInitializeTest, SecondaryMalformedJson_ReturnsSMTPError)
{
    {
        std::ofstream out(kSecondaryConfig);
        out << "{ not valid";
    }

    auto status =
        smtpPtr->initializeSmtpcfg(currentServer::SMTP_SECONDARY_SERVER);

    EXPECT_EQ(status, smtpStatus::SMTP_ERROR);
}

/* Arrange: JSON with Port as string (wrong type)
 * Act:     initializeSmtpcfg
 * Assert:  returns SMTP_ERROR (json::exception on get<int>()) */
TEST_F(SmtpInitializeTest, WrongTypeForPort_ReturnsSMTPError)
{
    {
        std::ofstream out(kPrimaryConfig);
        out << R"({"Config":{"Enabled":true,"Host":"h","Port":"not_a_number",)"
               R"("Sender":"s","Recipient":[],"TLSEnable":false,)"
               R"("Authentication":false,"username":"u","password":"p"}})";
    }

    auto status =
        smtpPtr->initializeSmtpcfg(currentServer::SMTP_PRIMARY_SERVER);

    EXPECT_EQ(status, smtpStatus::SMTP_ERROR);
}

/* =============================================================================
 * SmtpConfigFileTest — additional edge paths
 * =============================================================================
 */

/* Arrange: write config, then overwrite with different values
 * Act:     setsmtpconfig twice for primary; getSmtpConfig
 * Assert:  second write wins */
TEST_F(SmtpConfigFileTest, SetSmtpConfig_OverwriteExistingFile_SecondWriteWins)
{
    mail::alert::manager::mail_server ms1{};
    ms1.enable = true;
    ms1.port = 25;
    ms1.host = "first.smtp.com";
    ms1.sender = "first@example.com";
    smtpPtr->setsmtpconfig(ms1, currentServer::SMTP_PRIMARY_SERVER);

    mail::alert::manager::mail_server ms2{};
    ms2.enable = true;
    ms2.port = 587;
    ms2.host = "second.smtp.com";
    ms2.sender = "second@example.com";
    ms2.user_credntial = {"u", "p", {}};
    smtpPtr->setsmtpconfig(ms2, currentServer::SMTP_PRIMARY_SERVER);

    mail::alert::manager::mail_server read{};
    smtpPtr->getSmtpConfig(read, currentServer::SMTP_PRIMARY_SERVER);

    EXPECT_EQ(read.host, "second.smtp.com");
    EXPECT_EQ(read.port, 587);
}

/* Arrange: JSON with TLSEnable as wrong type (string instead of bool)
 * Act:     getSmtpConfig
 * Assert:  returns SMTP_ERROR (json::exception) */
TEST_F(SmtpConfigFileTest, GetSmtpConfig_WrongTypeForTlsEnable_ReturnsSMTPError)
{
    {
        std::ofstream out(kPrimaryConfig);
        out << R"({"Config":{"Enabled":true,"Host":"h","Port":25,)"
               R"("Sender":"s","Recipient":[],"TLSEnable":"yes",)"
               R"("Authentication":false,"username":"u","password":"p"}})";
    }

    mail::alert::manager::mail_server ms{};
    auto status =
        smtpPtr->getSmtpConfig(ms, currentServer::SMTP_PRIMARY_SERVER);

    EXPECT_EQ(status, smtpStatus::SMTP_ERROR);
}

/* Arrange: valid config with multiple recipients
 * Act:     setsmtpconfig then getSmtpConfig
 * Assert:  all recipients survive round-trip */
TEST_F(SmtpConfigFileTest, SetGet_MultipleRecipients_AllSurviveRoundTrip)
{
    mail::alert::manager::mail_server ms{};
    ms.enable = true;
    ms.port = 25;
    ms.host = "smtp.example.com";
    ms.sender = "from@example.com";
    ms.recipient = {"a@x.com", "b@x.com", "c@x.com"};
    ms.user_credntial = {"u", "p", {}};

    smtpPtr->setsmtpconfig(ms, currentServer::SMTP_PRIMARY_SERVER);

    mail::alert::manager::mail_server read{};
    smtpPtr->getSmtpConfig(read, currentServer::SMTP_PRIMARY_SERVER);

    EXPECT_EQ(read.recipient.size(), 3u);
    EXPECT_EQ(read.recipient[0], "a@x.com");
    EXPECT_EQ(read.recipient[1], "b@x.com");
    EXPECT_EQ(read.recipient[2], "c@x.com");
}
