#include "cppssh.h"
#include "CDLogger/Logger.h"
#include <iostream>
#include <vector>
#include <thread>
#include <mutex>
#include <fstream>
#include <sstream>

#define NUM_THREADS 10

void getOutFile(int channel, std::ofstream& outfile)
{
    std::stringstream filename;
    filename << "channel" << channel << ".log";
    outfile.open(filename.str());
}

void runConnectionTest(char* hostname, char* username, char* password)
{
    int channel;
    if (Cppssh::connect(&channel, hostname, 22, username, password, password, NUM_THREADS * 10000) == true)
    {
        std::ofstream output;
        getOutFile(channel, output);
        cdLog(LogLevel::Info) << "Connected " << channel;
        std::chrono::steady_clock::time_point txTime = std::chrono::steady_clock::now();
        int txCount = 0;
        bool sentGvim = false;

        Cppssh::writeString(channel, "env\n");
        //Cppssh::windowSize(channel, 80, 40);

        while ((Cppssh::isConnected(channel) == true) && (std::chrono::steady_clock::now() < (txTime + std::chrono::seconds(1))))
        {
            CppsshMessage message;
            if (Cppssh::read(channel, &message) == true)
            {
                output << message.message();
            }

            if ((txCount < 20) && (std::chrono::steady_clock::now() > (txTime + std::chrono::milliseconds(100))))
            {
                // send ls -l every 100 milliseconds
                Cppssh::writeString(channel, "ls -l\n");
                txTime = std::chrono::steady_clock::now();

                if ((sentGvim == false) && (txCount > 5))
                {
                    Cppssh::writeString(channel, "xterm&\n");
                    sentGvim = true;
                }

                txCount++;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
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
    std::cout << "Test program for cppssh API level: " << Cppssh::getCppsshVersion(true) << std::endl;
    if (argc != 4)
    {
        std::cerr << "Error: Three arguments required: " << argv[0] << " <hostname> <username> <password>" << std::endl;
        return -1;
    }

    try
    {
        Logger::getLogger().addStream(&std::cout);
        Logger::getLogger().setMinLogLevel(LogLevel::Debug);
        Cppssh::create();
        Cppssh::setOptions("aes256-cbc", "hmac-md5");

        //Cppssh::generateRsaKeyPair("test", "privRsa", "pubRsa", 1024);
        //Cppssh::generateDsaKeyPair("test", "privDsa", "pubDsa", 1024);

        std::vector<std::thread> threads;
        for (int i = 0; i < NUM_THREADS; i++)
        {
            threads.push_back(std::thread(&runConnectionTest, argv[1], argv[2], argv[3]));
        }
        for (std::thread& t : threads)
        {
            t.join();
        }
        Cppssh::destroy();
    }
    catch (const std::exception& ex)
    {
        cdLog(LogLevel::Error) << "Exception: " << ex.what() << std::endl;
    }
    return 0;
}

