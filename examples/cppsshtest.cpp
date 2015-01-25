#include "cppssh.h"
#include <iostream>
#include <vector>
#include <thread>
#include <mutex>

#define NUM_THREADS 5

void reportErrors(const std::string& tag, const int channel)
{
    CppsshMessage logMessage;
    while (Cppssh::getLogMessage(channel, &logMessage))
    {
        std::cout << tag << " " << channel << " " << logMessage.message() << std::endl;
    }
}

void runConnectionTest(char* hostname, char* username, char* password)
{
    int channel;
    bool connected = Cppssh::connectWithPassword(&channel, hostname, 22, username, password, NUM_THREADS * 10);
    {
        if (connected == true)
        {
            std::cout << "Connected " << channel << std::endl;
            std::chrono::steady_clock::time_point txTime = std::chrono::steady_clock::now();
            int txCount = 0;
            int rxCount = 0;
            while ((Cppssh::isConnected(channel) == true) && (std::chrono::steady_clock::now() < (txTime + std::chrono::seconds(1))))
            {
                CppsshMessage message;
                if (Cppssh::read(channel, &message) == true)
                {
                    std::cout << message.message();
                    rxCount++;
                }
                if ((txCount < 100) && (std::chrono::steady_clock::now() > (txTime + std::chrono::milliseconds(100))))
                {
                    // send ls -l every 100 milliseconds
                    Cppssh::sendString(channel, "ls -l\n");
                    txTime = std::chrono::steady_clock::now();
                    txCount++;
                }
            }
        }
        else
        {
            std::cout << "Did not connect " << channel << std::endl;
        }
        reportErrors("Connect", channel);
    }
    Cppssh::close(channel);
}

int main(int argc, char** argv)
{
    if (argc != 4)
    {
        std::cerr << "Error: Three arguments required: " << argv[0] << " <hostname> <username> <password>" << std::endl;
        return -1;
    }

    Cppssh::create();

    Cppssh::setOptions("aes192-cbc", "hmac-sha1");
    std::vector<std::thread> threads;
    for (int i = 0; i < NUM_THREADS; i++)
    {
        threads.push_back(std::thread(&runConnectionTest, argv[1], argv[2], argv[3]));
    }
    for (std::vector<std::thread>::iterator it = threads.begin(); it != threads.end(); it++)
    {
        (*it).join();
    }
    Cppssh::destroy();
    return 0;
}

