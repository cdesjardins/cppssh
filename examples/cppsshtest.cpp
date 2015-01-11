#include "cppssh.h"
#include <iostream>

int main(int argc, char** argv)
{
    if (argc != 4)
    {
        std::cerr << "Error: Three arguments required: " << argv[0] << " <hostname> <username> <password>" << std::endl;
        return -1;
    }

    Cppssh::create();
    Cppssh::setOptions("aes128-cbc", "hmac-sha1");
    Cppssh::connectWithPassword(argv[1], 22, argv[2], argv[3]);
    Cppssh::destroy();
    return 0;
}
