#include "cppsshtestutil.h"
#include "cppssh.h"
#include "CDLogger/Logger.h"
#include <iostream>
#include <vector>
#include <dirent.h>

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
    DIR* dir;
    struct dirent* ent;
    dir = opendir(keydir);
    if (dir != nullptr)
    {
        do
        {
            ent = readdir(dir);
            if (ent != nullptr)
            {
                std::string name(ent->d_name);
                if (endsWith(name, ".pub") == true)
                {
                    std::ifstream t(name);
                    std::string str((std::istreambuf_iterator<char>(t)), std::istreambuf_iterator<char>());
                    publicKeys->push_back(str);
                }
            }
        } while (ent != nullptr);
        closedir(dir);
    }
}

void installPublicKeys(const char* hostname, const char* username, const char* password, const char* keydir)
{
    std::vector<std::string> publicKeys;
    getPublicKeys(keydir, &publicKeys);
    if (publicKeys.size() > 0)
    {
        int channel;
        if (Cppssh::connect(&channel, hostname, 22, username, nullptr, password, 10000) == true)
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
                //sendCmdList(channel, cmdList, 500, remoteOutput);
                remoteOutput.close();
            }
            Cppssh::close(channel);
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
    return 0;
}

