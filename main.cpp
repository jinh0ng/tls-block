// main.cpp for tls-block

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <pcap.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string>
#include <iostream>

#include "ethhdr.h"
#include "iphdr.h"
#include "tcphdr.h"

using std::string;

// error 출력 및 사용법
void usage()
{
    printf("syntax : tls-block <interface> <server name>\n");
    printf("sample : tls-block wlan0 example.com\n");
}

// 인터페이스 MAC/IP 조회용 구조체
typedef struct
{
    Mac mac;
    Ip ip;
} t_info;
t_info MyInfo;

// pcap_capture → raw socket 전송 시 사용할 IP 레벨 유사헤더
typedef struct
{
    uint32_t srcAddr;
    uint32_t dstAddr;
    uint8_t reserved;
    uint8_t proto;
    uint16_t tcpLen;
} ChecksumHdr;

// IPv4/TCP 헤더 + Ethernet 헤더 간편 구조
#pragma pack(push, 1)
struct PacketInfo
{
    EthHdr ethHdr_;
    IpHdr ipHdr_;
    TcpHdr tcpHdr_;
};
#pragma pack(pop)

// IP/TCP checksum 계산 (tcp-block 코드 재사용)
uint16_t CheckSum(uint16_t *buffer, int size)
{
    uint32_t csum = 0;
    while (size > 1)
    {
        csum += *buffer++;
        size -= 2;
    }
    if (size)
    {
        csum += *(uint8_t *)buffer;
    }
    while (csum >> 16)
    {
        csum = (csum & 0xFFFF) + (csum >> 16);
    }
    return (uint16_t)(~csum);
}

// 내 MAC/IP 가져오기 (tcp-block 코드 재사용)
int getMyInfo(t_info *info, const char *dev)
{
    struct ifreq ifr;
    int fd = socket(PF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    // MAC
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0)
    {
        info->mac = Mac((uint8_t *)ifr.ifr_hwaddr.sa_data);
    }
    else
    {
        close(fd);
        return -1;
    }
    // IP
    if (ioctl(fd, SIOCGIFADDR, &ifr) == 0)
    {
        uint32_t raw = ntohl(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr);
        info->ip = Ip(raw);
    }
    else
    {
        close(fd);
        return -1;
    }
    close(fd);
    std::cout << "My MAC: " << std::string(info->mac) << "\n";
    std::cout << "My IP : " << std::string(info->ip) << "\n";
    return 0;
}

// TCP payload에서 TLS ClientHello SNI를 파싱해 반환 (매칭 실패 시 빈 문자열)
string parse_sni(const uint8_t *data, int len)
{
    int pos = 0;
    if (len < 5)
        return "";
    uint8_t content_type = data[pos++];
    if (content_type != 0x16)
        return ""; // Handshake
    pos += 2;      // 버전
    uint16_t rec_len = ntohs(*(uint16_t *)(data + pos));
    pos += 2;
    if (rec_len + 5 > (uint16_t)len)
        return "";
    // Handshake 메시지
    if (pos + 4 > len)
        return "";
    uint8_t hs_type = data[pos++];
    if (hs_type != 0x01)
        return ""; // ClientHello
    uint32_t hs_len = ((data[pos] << 16) | (data[pos + 1] << 8) | data[pos + 2]);
    pos += 3;
    if (pos + hs_len > len)
        return "";
    // 버전(2) + 랜덤(32)
    pos += 2 + 32;
    if (pos + 1 > len)
        return "";
    // SessionID
    uint8_t sid_len = data[pos++];
    pos += sid_len;
    if (pos + 2 > len)
        return "";
    // CipherSuites
    uint16_t cs_len = (data[pos] << 8) | (data[pos + 1]);
    pos += 2 + cs_len;
    if (pos + 1 > len)
        return "";
    // CompressionMethods
    uint8_t cm_len = data[pos++];
    pos += cm_len;
    if (pos + 2 > len)
        return "";
    // Extensions 전체 길이
    uint16_t ext_tot = (data[pos] << 8) | (data[pos + 1]);
    pos += 2;
    int ext_end = pos + ext_tot;
    // Extensions 순회
    while (pos + 4 <= ext_end && pos + 4 <= len)
    {
        uint16_t ext_type = (data[pos] << 8) | (data[pos + 1]);
        pos += 2;
        uint16_t ext_len = (data[pos] << 8) | (data[pos + 1]);
        pos += 2;
        if (ext_type == 0x0000)
        { // server_name
            if (pos + 2 > len)
                return "";
            uint16_t list_len = (data[pos] << 8) | (data[pos + 1]);
            pos += 2;
            int list_end = pos + list_len;
            while (pos + 3 <= list_end && pos + 3 <= len)
            {
                uint8_t name_type = data[pos++];
                uint16_t name_len = (data[pos] << 8) | (data[pos + 1]);
                pos += 2;
                if (pos + name_len > len)
                    return "";
                return string((char *)(data + pos), name_len);
            }
        }
        pos += ext_len;
    }
    return "";
}

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        usage();
        return -1;
    }
    const char *dev = argv[1];
    const string target_sni = argv[2];
    char errbuf[PCAP_ERRBUF_SIZE];

    // 1) pcap 열기
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (!handle)
    {
        fprintf(stderr, "pcap_open_live(%s) failed: %s\n", dev, errbuf);
        return -1;
    }
    if (getMyInfo(&MyInfo, dev) < 0)
    {
        fprintf(stderr, "getMyInfo(%s) failed\n", dev);
        pcap_close(handle);
        return -1;
    }
    // 2) raw socket (IP_HDRINCL)
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd < 0)
    {
        perror("socket");
        pcap_close(handle);
        return -1;
    }
    int on = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
    {
        perror("setsockopt");
        close(sockfd);
        pcap_close(handle);
        return -1;
    }

    // 패킷 캡처 루프
    while (true)
    {
        struct pcap_pkthdr *hdr;
        const u_char *pkt;
        int res = pcap_next_ex(handle, &hdr, &pkt);
        if (res == 0)
            continue;
        if (res < 0)
        {
            fprintf(stderr, "pcap_next_ex -> %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        auto *pi = (PacketInfo *)pkt;
        // Ethernet ⇒ IPv4?
        if (pi->ethHdr_.type() != EthHdr::Ip4)
            continue;
        // IP ⇒ TCP?
        if (pi->ipHdr_.p() != IpHdr::Tcp)
            continue;

        int ip_hdr_len = pi->ipHdr_.hl() * 4;
        int tcp_hdr_len = pi->tcpHdr_.off() * 4;
        int ip_pkt_len = pi->ipHdr_.len();
        int tcp_data_len = ip_pkt_len - ip_hdr_len - tcp_hdr_len;
        if (tcp_data_len <= 0)
            continue;
        // ClientHello는 클라이언트→서버(443) 방향
        if (pi->tcpHdr_.dport() != 443)
            continue;

        const uint8_t *tcp_payload = pkt + sizeof(EthHdr) + ip_hdr_len + tcp_hdr_len;
        string sni = parse_sni(tcp_payload, tcp_data_len);
        if (sni.empty() || sni != target_sni)
            continue;
        printf("[Matched SNI] %s\n", sni.c_str());

        // === Forward: RST-only 패킷 전송 (pcap_sendpacket) ===
        {
            PacketInfo *fwd = (PacketInfo *)malloc(sizeof(PacketInfo));
            memcpy(fwd, pkt, sizeof(PacketInfo));
            // Ethernet
            fwd->ethHdr_.smac_ = MyInfo.mac;
            // IP
            uint16_t new_ip_len = ip_hdr_len + tcp_hdr_len;
            fwd->ipHdr_.len_ = htons(new_ip_len);
            fwd->ipHdr_.sum_ = 0;
            fwd->ipHdr_.sum_ = CheckSum((uint16_t *)&fwd->ipHdr_, sizeof(IpHdr));
            // TCP
            uint32_t orig_seq = pi->tcpHdr_.seq();
            uint32_t new_seq = orig_seq + tcp_data_len;
            fwd->tcpHdr_.seq_ = htonl(new_seq);
            fwd->tcpHdr_.flags_ = TcpHdr::Rst; // RST only
            fwd->tcpHdr_.off_rsvd_ = (sizeof(TcpHdr) / 4) << 4;
            // TCP checksum
            fwd->tcpHdr_.sum_ = 0;
            ChecksumHdr ph;
            memset(&ph, 0, sizeof(ph));
            ph.srcAddr = (uint32_t)pi->ipHdr_.sip();
            ph.dstAddr = (uint32_t)pi->ipHdr_.dip();
            ph.reserved = 0;
            ph.proto = pi->ipHdr_.p();
            ph.tcpLen = htons(sizeof(TcpHdr));
            uint32_t tcp_csum = 0;
            tcp_csum += CheckSum((uint16_t *)&fwd->tcpHdr_, sizeof(TcpHdr));
            tcp_csum += CheckSum((uint16_t *)&ph, sizeof(ph));
            tcp_csum = (tcp_csum & 0xFFFF) + (tcp_csum >> 16);
            fwd->tcpHdr_.sum_ = tcp_csum;
            // 전송
            if (pcap_sendpacket(handle, (const u_char *)fwd, sizeof(PacketInfo)) != 0)
            {
                fprintf(stderr, "pcap_sendpacket error: %s\n", pcap_geterr(handle));
            }
            free(fwd);
        }

        // === Backward: RST-only 패킷 전송 (raw socket) ===
        {
            // IP 헤더 및 TCP 헤더만 전송
            struct
            {
                IpHdr ipHdr_;
                TcpHdr tcpHdr_;
            } bwd;
            // 복사
            memcpy(&bwd.ipHdr_, &pi->ipHdr_, sizeof(IpHdr));
            memcpy(&bwd.tcpHdr_, &pi->tcpHdr_, sizeof(TcpHdr));

            // IP swap & 설정
            int new_ip_len = ip_hdr_len + tcp_hdr_len;
            bwd.ipHdr_.len_ = htons(new_ip_len);
            bwd.ipHdr_.ttl_ = 128;
            std::swap(bwd.ipHdr_.sip_, bwd.ipHdr_.dip_);
            bwd.ipHdr_.sum_ = 0;
            bwd.ipHdr_.sum_ = CheckSum((uint16_t *)&bwd.ipHdr_, sizeof(IpHdr));

            // TCP swap & 설정
            bwd.tcpHdr_.sport_ = pi->tcpHdr_.dport_;
            bwd.tcpHdr_.dport_ = pi->tcpHdr_.sport_;
            // seq=클라이언트 ack, ack=orig_seq+data_len
            bwd.tcpHdr_.seq_ = pi->tcpHdr_.ack_;
            uint32_t orig_seq = pi->tcpHdr_.seq();
            uint32_t new_ack = orig_seq + tcp_data_len;
            bwd.tcpHdr_.ack_ = htonl(new_ack);

            bwd.tcpHdr_.flags_ = TcpHdr::Rst;
            bwd.tcpHdr_.off_rsvd_ = (sizeof(TcpHdr) / 4) << 4;
            bwd.tcpHdr_.sum_ = 0;
            // TCP checksum
            ChecksumHdr ph2;
            memset(&ph2, 0, sizeof(ph2));
            ph2.srcAddr = (uint32_t)pi->ipHdr_.dip();
            ph2.dstAddr = (uint32_t)pi->ipHdr_.sip();
            ph2.reserved = 0;
            ph2.proto = pi->ipHdr_.p();
            ph2.tcpLen = htons(sizeof(TcpHdr));
            uint32_t csum2 = 0;
            csum2 += CheckSum((uint16_t *)&bwd.tcpHdr_, sizeof(TcpHdr));
            csum2 += CheckSum((uint16_t *)&ph2, sizeof(ph2));
            csum2 = (csum2 & 0xFFFF) + (csum2 >> 16);
            bwd.tcpHdr_.sum_ = csum2;

            // 전송 대상 설정
            struct sockaddr_in sin{};
            sin.sin_family = AF_INET;
            sin.sin_addr.s_addr = inet_addr(std::string(pi->ipHdr_.sip()).c_str());
            int pkt_len = sizeof(IpHdr) + sizeof(TcpHdr);
            if (sendto(sockfd, &bwd.ipHdr_, pkt_len, 0,
                       (struct sockaddr *)&sin, sizeof(sin)) < 0)
            {
                perror("sendto");
            }
        }
    }

    close(sockfd);
    pcap_close(handle);
    return 0;
}
