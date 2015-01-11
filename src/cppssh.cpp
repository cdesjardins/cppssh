#include "cppssh.h"
#include "impl.h"

std::shared_ptr<CppsshImpl> Cppssh::s_cppsshInst;

void Cppssh::create()
{
    if (s_cppsshInst == NULL)
    {
        s_cppsshInst = CppsshImpl::create();
    }
}

void Cppssh::destroy()
{
    s_cppsshInst->destroy();
    s_cppsshInst.reset();
}

int Cppssh::connectWithPassword(const char* host, const short port, const char* username, const char* password, bool shell, const int timeout)
{
    return s_cppsshInst->connectWithPassword(host, port, username, password, shell, timeout);
}

int Cppssh::connectWithKey(const char* host, const short port, const char* username, const char* privKeyFileName, bool shell, const int timeout)
{
    return 0;
}

bool Cppssh::send(const char* data, size_t bytes, int channel)
{
    return false;
}

size_t Cppssh::read(char* data, int channel)
{
    return 0;
}

bool Cppssh::close(int channel)
{
    return false;
}

void Cppssh::setOptions(const char* prefCipher, const char* prefHmac)
{
}

bool Cppssh::generateKeyPair(const char* type, const char* fqdn, const char* privKeyFileName, const char* pubKeyFileName, short keySize)
{
    return false;
}

