#ifndef CPPSSH_TEST_UTIL_Hxx
#define CPPSSH_TEST_UTIL_Hxx
#include <vector>
#include <fstream>
#include <sstream>
#include <chrono>

void sendCmdList(int channel, const std::vector<std::string>& cmdList, const int periodMs, std::ofstream& remoteOutput);

#endif
