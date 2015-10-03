#include "cppsshtestutil.h"
#include "cppssh.h"
#include "CDLogger/Logger.h"
#include <iostream>
#include <vector>

#ifdef WIN32
#define DIR_SEP "\\"
#else
#define DIR_SEP "/"
#endif

inline bool endsWith(std::string const& value, std::string const& ending)
{
    if (ending.size() > value.size())
    {
        return false;
    }
    return std::equal(ending.rbegin(), ending.rend(), value.rbegin());
}

void getPublicKeys(const char* keydir, std::vector<std::string>* publicKeys)
{
    std::vector<std::string> keyFiles =
    {
        "testkey_dsa.pub",
        "testkey_rsa.pub",
        "testkey_dsa_pw.pub",
        "testkey_rsa_pw.pub"
    };
    for (std::vector<std::string>::iterator it = keyFiles.begin(); it < keyFiles.end(); it++)
    {
        std::string name(keydir);
        name.append(DIR_SEP);
        name.append(*it);
        std::ifstream t(name);
        if (t)
        {
            std::string str((std::istreambuf_iterator<char>(t)), std::istreambuf_iterator<char>());
            publicKeys->push_back(str);
        }
        else
        {
            cdLog(LogLevel::Error) << "Unable to open file " << name;
        }
    }
}

void installPublicKeys(const char* hostname, const char* username, const char* password, const char* keydir)
{
    std::vector<std::string> publicKeys;
    getPublicKeys(keydir, &publicKeys);
    if (publicKeys.size() > 0)
    {
        int channel;
        if (Cppssh::connect(&channel, hostname, 22, username, nullptr, password, 10000) == CPPSSH_CONNECT_OK)
        {
            std::vector<std::string> cmdList { "mkdir -p ~/.ssh\n", "rm ~/.ssh/authorized_keys\n", "touch ~/.ssh/authorized_keys\n", "chmod 600 ~/.ssh/authorized_keys\n"};
            for (std::vector<std::string>::iterator it = publicKeys.begin(); it < publicKeys.end(); it++)
            {
                std::string cmd("echo \"");
                cmd.append(*it);
                cmd.append("\" >> ~/.ssh/authorized_keys\n");
                cmdList.push_back(cmd);
            }
            std::ofstream remoteOutput;
            remoteOutput.open("testoutput.txt");
            if (!remoteOutput)
            {
                cdLog(LogLevel::Error) << "Unable to open testoutput.txt";
            }
            else
            {
                sendCmdList(channel, cmdList, 500, remoteOutput);
                remoteOutput.close();
            }
            Cppssh::close(channel);
        }
        else
        {
            cdLog(LogLevel::Error) << "Did not connect " << channel;
        }
    }
}

int main(int argc, char** argv)
{
    if (argc != 5)
    {
        std::cerr << "Error: Four arguments required: " << argv[0] << " <hostname> <username> <password> <keydir>" << std::endl;
    }
    else
    {
        Cppssh::create();
        Logger::getLogger().addStream("testlog.txt");
        try
        {
            Logger::getLogger().setMinLogLevel(LogLevel::Debug);

            installPublicKeys(argv[1], argv[2], argv[3], argv[4]);
        }
        catch (const std::exception& ex)
        {
            cdLog(LogLevel::Error) << "Exception: " << ex.what() << std::endl;
        }
    }
    Cppssh::destroy();
    return 0;
}

