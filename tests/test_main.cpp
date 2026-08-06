/*
 * Custom test main for email-alert-manager unit tests.
 *
 * Registers a GlobalTestEnvironment that makes /etc/ssl/private
 * accessible before the first test runs, then restores it after all
 * tests complete.  This is required because GCC 15 libstdc++ calls
 * directory_entry::refresh() (which calls symlink_status/lstat) eagerly
 * in the smtp class constructor — that call fails with EACCES unless
 * the /etc/ssl/private directory (mode 0700, root-owned) has o+x.
 */

#ifdef FAIL
#undef FAIL
#endif
#ifdef ERROR
#undef ERROR
#endif

#include <cstdlib>

#include <gtest/gtest.h>

class PrivateSslEnvironment : public ::testing::Environment
{
  public:
    void SetUp() override
    {
        /* Allow traversal of /etc/ssl/private/ so smtp class constructor
         * can call directory_entry::refresh() on key/cert paths.         */
        ::system("sudo -n chmod o+x /etc/ssl/private 2>/dev/null");
        /* Create /var/lib/alert with write permission for config file tests */
        ::system("sudo -n mkdir -p /var/lib/alert 2>/dev/null");
        ::system("sudo -n chmod 777 /var/lib/alert 2>/dev/null");
    }

    void TearDown() override
    {
        ::system("sudo -n chmod o-x /etc/ssl/private 2>/dev/null");
    }
};

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    ::testing::AddGlobalTestEnvironment(new PrivateSslEnvironment());
    return RUN_ALL_TESTS();
}
