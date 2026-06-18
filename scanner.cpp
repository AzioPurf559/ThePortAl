#include <ctime>
#include <iostream>
#include <string>
#include <set>
#include <map>
#include <winsock2.h>
#include <iphlpapi.h>
#include <windows.h>
#include <psapi.h>
#include <fstream>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "psapi.lib")

// -----------------------------
// PROCESS NAME
// -----------------------------
std::string GetProcessName(DWORD pid)
{
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) return "UNKNOWN";

    char path[MAX_PATH];
    DWORD size = MAX_PATH;

    if (QueryFullProcessImageNameA(hProcess, 0, path, &size))
    {
        CloseHandle(hProcess);

        std::string fullPath(path);
        size_t pos = fullPath.find_last_of("\\/");
        return (pos == std::string::npos) ? fullPath : fullPath.substr(pos + 1);
    }

    CloseHandle(hProcess);
    return "UNKNOWN";
}

// -----------------------------
// MEMORY USAGE
// -----------------------------
DWORD GetProcessMemoryKB(DWORD pid)
{
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return 0;

    PROCESS_MEMORY_COUNTERS pmc;

    if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc)))
    {
        CloseHandle(hProcess);
        return pmc.WorkingSetSize / 1024;
    }

    CloseHandle(hProcess);
    return 0;
}

// -----------------------------
// TIMESTAMP
// -----------------------------
std::string GetTimestamp()
{
    time_t now = time(0);
    tm* ltm = localtime(&now);

    char buffer[32];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", ltm);

    return std::string(buffer);
}

// -----------------------------
// RISK SCORING ENGINE
// -----------------------------
int CalculateRiskScore(const std::string& process, DWORD memoryKB)
{
    int score = 0;

    // Unknown process
    if (process == "UNKNOWN")
        score += 5;

    // High memory usage
    if (memoryKB > 300000) // ~300MB+
        score += 3;

    // Suspicious system tools (basic heuristic)
    if (process.find("powershell") != std::string::npos ||
        process.find("cmd") != std::string::npos)
        score += 2;

    return score;
}

// -----------------------------
// MAIN CONNECTION SCAN
// -----------------------------
void GetConnections(const std::set<std::string>& ignoreProcesses)
{
    std::ofstream logFile("connections.log", std::ios::app);

    PMIB_TCPTABLE_OWNER_PID pTcpTable;
    DWORD size = 0;

    GetExtendedTcpTable(NULL, &size, FALSE, AF_INET,
                        TCP_TABLE_OWNER_PID_ALL, 0);

    if (size == 0)
    {
        std::cout << "No TCP data available\n";
        return;
    }

    pTcpTable = (MIB_TCPTABLE_OWNER_PID*)malloc(size);

    if (!pTcpTable)
    {
        std::cout << "Memory allocation failed\n";
        return;
    }

    if (GetExtendedTcpTable(pTcpTable, &size, FALSE, AF_INET,
                            TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR)
    {
        std::cout << "Failed to get connections\n";
        free(pTcpTable);
        return;
    }

    // PID caches (performance improvement)
    std::map<DWORD, std::string> processCache;
    std::map<DWORD, DWORD> memoryCache;

    for (DWORD i = 0; i < pTcpTable->dwNumEntries; i++)
    {
        MIB_TCPROW_OWNER_PID row = pTcpTable->table[i];

        // Include more states
        if (row.dwState != MIB_TCP_STATE_ESTAB &&
            row.dwState != MIB_TCP_STATE_LISTEN &&
            row.dwState != MIB_TCP_STATE_TIME_WAIT)
            continue;

        in_addr local, remote;
        local.S_un.S_addr = row.dwLocalAddr;
        remote.S_un.S_addr = row.dwRemoteAddr;

        std::string localIP = inet_ntoa(local);
        std::string remoteIP = inet_ntoa(remote);

        DWORD pid = row.dwOwningPid;

        // caching
        if (processCache.find(pid) == processCache.end())
            processCache[pid] = GetProcessName(pid);

        std::string process = processCache[pid];

        if (ignoreProcesses.find(process) != ignoreProcesses.end())
            continue;

        if (memoryCache.find(pid) == memoryCache.end())
            memoryCache[pid] = GetProcessMemoryKB(pid);

        DWORD memoryKB = memoryCache[pid];

        std::string timestamp = GetTimestamp();
        int risk = CalculateRiskScore(process, memoryKB);

        std::string riskLevel =
            (risk >= 6) ? "HIGH" :
            (risk >= 3) ? "MEDIUM" : "LOW";

        std::string line =
            "Time: " + timestamp +
            " | PID: " + std::to_string(pid) +
            " | " + process +
            " | Memory: " + std::to_string(memoryKB) + " KB" +
            " | Risk: " + riskLevel +
            " (" + std::to_string(risk) + ")" +
            " | Source: " + localIP +
            ":" + std::to_string(ntohs((u_short)row.dwLocalPort)) +
            " | Destination: " + remoteIP +
            ":" + std::to_string(ntohs((u_short)row.dwRemotePort));

        std::cout << line << std::endl;
        logFile << line << std::endl;
    }

    free(pTcpTable);
}

// -----------------------------
// MAIN
// -----------------------------
int main(int argc, char* argv[])
{
    std::set<std::string> ignoreProcesses;

    for (int i = 1; i < argc; i++)
        ignoreProcesses.insert(argv[i]);

    GetConnections(ignoreProcesses);

    return 0;
}