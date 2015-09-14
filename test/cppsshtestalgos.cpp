#include "cppssh.h"
#include "CDLogger/Logger.h"
#include <iostream>
#include <vector>
#include <thread>
#include <mutex>
#include <fstream>
#include <sstream>

void runConnectionTest(char* hostname, char* username, char* password, char* keyfile)
{
    int channel;
    if (Cppssh::connect(&channel, hostname, 22, username, keyfile, password, 10000) == true)
    {
        std::vector<std::string> cmdList {"env\n", "mkdir cppsshTestDir\n", "ls -l cppsshTestDir\n", "rmdir cppsshTestDir\n"};
        std::ofstream remoteOutput;
        remoteOutput.open("testoutput.txt");
        if (!remoteOutput)
        {
            cdLog(LogLevel::Error) << "Unable to open testoutput.txt";
        }
        else
        {
            std::chrono::steady_clock::time_point txTime = std::chrono::steady_clock::now();
            size_t txIndex = 0;

            while ((Cppssh::isConnected(channel) == true) && (std::chrono::steady_clock::now() < (txTime + std::chrono::seconds(1))))
            {
                CppsshMessage message;
                if (Cppssh::read(channel, &message) == true)
                {
                    remoteOutput << message.message();
                    //std::cout << message.message();
                }

                if (std::chrono::steady_clock::now() > (txTime + std::chrono::milliseconds(500)) && (txIndex < cmdList.size()))
                {
                    Cppssh::writeString(channel, cmdList[txIndex].c_str());
                    txTime = std::chrono::steady_clock::now();
                    txIndex++;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
            remoteOutput.close();
        }
    }
    else
    {
        cdLog(LogLevel::Error) << "Did not connect " << channel;
    }
    Cppssh::close(channel);
}

int main(int argc, char** argv)
{
    if ((argc != 6) && (argc != 7))
    {
        std::cerr << "Error: Five or Six arguments required: " << argv[0] << " <hostname> <username> <password> <cipher> <hmac> <key>" << std::endl;
    }
    else
    {
        Logger::getLogger().addStream("testlog.txt");
        try
        {
            Logger::getLogger().setMinLogLevel(LogLevel::Debug);
            Cppssh::setOptions(argv[4], argv[5]);

            char* keyfile = NULL;
            if (argc == 7)
            {
                keyfile = argv[6];
            }
            runConnectionTest(argv[1], argv[2], argv[3], keyfile);
        }
        catch (const std::exception& ex)
        {
            cdLog(LogLevel::Error) << "Exception: " << ex.what() << std::endl;
        }
    }
    return 0;
}

