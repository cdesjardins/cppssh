#include "cppsshtestutil.h"
#include "cppssh.h"
#include "CDLogger/Logger.h"
#include <iostream>
#include <vector>
#include <thread>
#include <mutex>
#include <fstream>
#include <sstream>

void runConnectionTest(const std::string& hostname, const std::string& username, const std::string& password,
                       const char* keyfile)
{
    int channel;
    if (Cppssh::connect(&channel, hostname.c_str(), 22, username.c_str(), keyfile, password.c_str(),
                        10000) == CPPSSH_CONNECT_OK)
    {
        std::vector<std::string> cmdList {"env\n", "mkdir cppsshTestDir\n", "ls -l cppsshTestDir\n",
                                          "rmdir cppsshTestDir\n"};
        std::ofstream remoteOutput;
        remoteOutput.open("testoutput.txt");
        if (!remoteOutput)
        {
            cdLog(LogLevel::Error) << "Unable to open testoutput.txt";
        }
        else
        {
            sendCmdList(channel, cmdList, 700, remoteOutput);
            remoteOutput.close();
        }
        Cppssh::close(channel);
    }
    else
    {
        cdLog(LogLevel::Error) << "Did not connect " << channel;
    }
}

int main(int argc, char** argv)
{
    if ((argc != 6) && (argc != 7))
    {
        std::cerr << "Error: Five or Six arguments required: " << argv[0] <<
            " <hostname> <username> <password> <cipher> <hmac> <key>" << std::endl;
    }
    else
    {
        Cppssh::create();
        Logger::getLogger().addStream("testlog.txt");
        //Logger::getLogger().addStream(std::shared_ptr<std::ostream>(&std::cout, [](void*) {}));
        try
        {
            Logger::getLogger().setMinLogLevel(LogLevel::Debug);
            std::string hostname(argv[1]);
            std::string username(argv[2]);
            std::string password(argv[3]);
            std::string cipher(argv[4]);
            std::string hmac(argv[5]);

            Cppssh::setPreferredCipher(cipher.c_str());
            Cppssh::setPreferredHmac(hmac.c_str());

            char* keyfile = nullptr;
            if (argc == 7)
            {
                keyfile = argv[6];
            }
            runConnectionTest(hostname, username, password, keyfile);
        }
        catch (const std::exception& ex)
        {
            cdLog(LogLevel::Error) << "Exception: " << ex.what() << std::endl;
        }
        Cppssh::destroy();
    }
    return 0;
}

