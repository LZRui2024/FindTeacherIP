// 在文件最顶部添加这三行
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#pragma comment(lib, "ws2_32.lib")

#include <iostream>
#include <cstring>
#include <string>
#include <thread>
#include <chrono>
#include <winsock2.h>
#include <ws2tcpip.h>

#define TEACHER_MULTICAST_GROUP "224.50.50.42"
#define TEACHER_PORT            4988
#define BUFFER_SIZE             4096

class JiYuStudentClient {
private:
    SOCKET multicastSock;
    std::string teacherIP;

    void listLocalIPs() {
        char hostname[256];
        gethostname(hostname, sizeof(hostname));
        hostent* host = gethostbyname(hostname);

        std::cout << "[*] 本机网卡IP地址列表：" << std::endl;
        for (int i = 0; host->h_addr_list[i] != nullptr; i++) {
            in_addr addr;
            memcpy(&addr, host->h_addr_list[i], sizeof(in_addr));
            std::cout << "  - " << inet_ntoa(addr) << std::endl;
        }
    }

public:
    JiYuStudentClient() {
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);
        multicastSock = INVALID_SOCKET;
    }

    ~JiYuStudentClient() {
        if (multicastSock != INVALID_SOCKET) closesocket(multicastSock);
        WSACleanup();
    }

    std::string discoverTeacherIP(int timeoutSeconds = 5) {
        std::cout << "=== 极域电子教室教师机发现工具 ===\nBy: Lxrui & KimiAI\n" << std::endl;
        listLocalIPs();

        std::cout << "\n[*] 正在监听组播地址 " << TEACHER_MULTICAST_GROUP
            << " 端口 " << TEACHER_PORT << " ..." << std::endl;

        multicastSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (multicastSock == INVALID_SOCKET) {
            std::cerr << "[-] 创建套接字失败，错误码：" << WSAGetLastError() << std::endl;
            return "";
        }

        int reuse = 1;
        setsockopt(multicastSock, SOL_SOCKET, SO_REUSEADDR, (char*)&reuse, sizeof(reuse));

        sockaddr_in localAddr;
        memset(&localAddr, 0, sizeof(localAddr));
        localAddr.sin_family = AF_INET;
        localAddr.sin_addr.s_addr = INADDR_ANY;
        localAddr.sin_port = htons(TEACHER_PORT);

        if (bind(multicastSock, (sockaddr*)&localAddr, sizeof(localAddr)) == SOCKET_ERROR) {
            std::cerr << "[-] 绑定端口失败，错误码：" << WSAGetLastError() << std::endl;
            return "";
        }

        ip_mreq mreq;
        mreq.imr_multiaddr.s_addr = inet_addr(TEACHER_MULTICAST_GROUP);
        mreq.imr_interface.s_addr = INADDR_ANY;

        if (setsockopt(multicastSock, IPPROTO_IP, IP_ADD_MEMBERSHIP,
            (char*)&mreq, sizeof(mreq)) == SOCKET_ERROR) {
            std::cerr << "[!] 加入组播组失败（可能需要管理员权限），错误码："
                << WSAGetLastError() << std::endl;
        }

        DWORD timeout = timeoutSeconds * 1000;
        setsockopt(multicastSock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));

        char buffer[BUFFER_SIZE];

        std::cout << "[*] 等待教师机广播消息..." << std::endl;

        sockaddr_in fromAddr;
        int fromLen = sizeof(fromAddr);
        int recvLen = recvfrom(multicastSock, buffer, BUFFER_SIZE - 1, 0,
            (sockaddr*)&fromAddr, &fromLen);

        if (recvLen > 0 && recvLen >= 44 && memcmp(buffer, "OONC", 4) == 0) {
            teacherIP = inet_ntoa(fromAddr.sin_addr);

            std::cout << "\n[+] 发现教师机！" << std::endl;
            std::cout << "====================================" << std::endl;
            std::cout << "教师机IP地址: " << teacherIP << std::endl;
            std::cout << "通信端口: " << ntohs(fromAddr.sin_port) << std::endl;
            std::cout << "数据包大小: " << recvLen << " 字节" << std::endl;
            std::cout << "====================================" << std::endl;

            return teacherIP;
        }

        std::cerr << "\n[-] 搜索超时，未在 " << timeoutSeconds << " 秒内发现教师机" << std::endl;
        return "";
    }
};

int main() {
    //std::cout << "=== 极域电子教室学生端模拟程序 ===" << std::endl;

    JiYuStudentClient client;
    std::string teacherIP = client.discoverTeacherIP(5);

    if (!teacherIP.empty()) {
        std::cout << "\n[+] 成功发现教师机IP地址: " << teacherIP << std::endl;
    }
    else {
        std::cout << "\n[-] 未发现教师机" << std::endl;
    }

    std::cout << "\n[*] 按回车键退出程序..." << std::endl;
    std::cin.get();

    return 0;
}