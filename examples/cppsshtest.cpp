#include "cppssh.h"
#include <iostream>

void reportErrors(const std::string &tag, const int channel)
{
    CppsshLogMessage logMessage;
    while (Cppssh::getLogMessage(channel, &logMessage))
    {
        std::cout << tag << " " << logMessage.message() << std::endl;
    }
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
    int channel;
    bool connected = Cppssh::connectWithPassword(&channel, argv[1], 22, argv[2], argv[3]);
    if (connected == false)
    {
        reportErrors("Connect", channel);
    }
    Cppssh::close(channel);

    Cppssh::destroy();
    return 0;
}
