#include "cppsshtestutil.h"
#include "cppssh.h"
#include <thread>

void sendCmdList(int channel, const std::vector<std::string>& cmdList, const int periodMs, std::ofstream& remoteOutput)
{
    std::chrono::steady_clock::time_point txTime = std::chrono::steady_clock::now();
    size_t txIndex = 0;

    while ((Cppssh::isConnected(channel) == true) && (std::chrono::steady_clock::now() < (txTime + std::chrono::seconds(1))))
    {
        CppsshMessage message;
        if (Cppssh::read(channel, &message) == true)
        {
            remoteOutput << message.message();
        }

        if (std::chrono::steady_clock::now() > (txTime + std::chrono::milliseconds(periodMs)) && (txIndex < cmdList.size()))
        {
            Cppssh::writeString(channel, cmdList[txIndex].c_str());
            txTime = std::chrono::steady_clock::now();
            txIndex++;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

