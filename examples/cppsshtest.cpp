#include "cppssh.h"
#include <iostream>
#include <vector>
#include <thread>
#include <mutex>

#define NUM_THREADS 5
std::mutex _outputMutex;

void reportErrors(const std::string& tag, const int channel)
{
    CppsshLogMessage logMessage;
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
        std::unique_lock<std::mutex> lock(_outputMutex);
        if (connected == true)
        {
            std::cout << "Connected " << channel << std::endl;
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

    Cppssh::setOptions("aes192-cbc", "hmac-md5");
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

