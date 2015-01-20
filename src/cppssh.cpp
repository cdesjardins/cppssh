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

bool Cppssh::connectWithPassword(int* channelId, const char* host, const short port, const char* username, const char* password, bool shell)
{
    return s_cppsshInst->connect(channelId, host, port, username, password, NULL, shell);
}

bool Cppssh::connectWithKey(int* channelId, const char* host, const short port, const char* username, const char* privKeyFileName, bool shell)
{
    return s_cppsshInst->connect(channelId, host, port, username, NULL, privKeyFileName, shell);
}

bool Cppssh::send(const int channelId, const char* data, size_t bytes)
{
    return false;
}

size_t Cppssh::read(const int channelId, char* data)
{
    return 0;
}

bool Cppssh::close(const int channelId)
{
    return s_cppsshInst->close(channelId);
}

void Cppssh::setOptions(const char* prefCipher, const char* prefHmac)
{
    CppsshImpl::setOptions(prefCipher, prefHmac);
}

bool Cppssh::generateKeyPair(const char* type, const char* fqdn, const char* privKeyFileName, const char* pubKeyFileName, short keySize)
{
    return false;
}

bool Cppssh::getLogMessage(const int channelId, CppsshLogMessage* message)
{
    return s_cppsshInst->getLogMessage(channelId, message);
}

CppsshLogMessage::CppsshLogMessage()
{

}

CppsshLogMessage::~CppsshLogMessage()
{

}

const char* const CppsshLogMessage::message() const
{
    return _message.get();
}
