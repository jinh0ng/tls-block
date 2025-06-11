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

#include "ethhdr.h"
#include "iphdr.h"
#include "tcphdr.h"
#include "ip.h"

#pragma pack(push, 1)
struct PacketInfo
{
    EthHdr ethHdr_;
    IpHdr ipHdr_;
    TcpHdr tcpHdr_;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct ChecksumHdr
{
    uint32_t srcAddr;
    uint32_t dstAddr;
    uint8_t reserved;
    uint8_t proto;
    uint16_t tcpLen;
};
#pragma pack(pop)

typedef struct
{
    Mac mac;
    Ip ip;
} t_info;

t_info MyInfo;

void usage()
{
    printf("syntax : tls-block <interface> <server name>\n");
    printf("sample : tls-block wlan0 naver.com\n");
}

int getMyInfo(t_info *info, const char *dev)
{
    struct ifreq ifr;
    int fd = socket(PF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;

    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    // MAC address
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0)
    {
        info->mac = Mac(reinterpret_cast<uint8_t *>(ifr.ifr_hwaddr.sa_data));
    }
    else
    {
        close(fd);
        return -1;
    }

    // IP address
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

    printf("My MAC: %s\n", std::string(info->mac).c_str());
    printf("My IP: %s\n", std::string(info->ip).c_str());
    close(fd);
    return 0;
}

uint16_t CheckSum(uint16_t *buf, int size)
{
    uint32_t sum = 0;
    while (size > 1)
    {
        sum += *buf++;
        size -= 2;
    }
    if (size > 0)
        sum += *(uint8_t *)buf;
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)(~sum);
}

bool parseTlsSni(const uint8_t *data, uint32_t len, std::string &sni)
{
    if (len < 5)
        return false;
    uint32_t pos = 0;

    // TLS Record Header
    uint8_t type = data[pos++];
    if (type != 22)
        return false; // Handshake
    pos += 2;         // version
    uint16_t recLen = (data[pos] << 8) | data[pos + 1];
    pos += 2;
    if (recLen + 5 > len)
        return false;

    // Handshake Message
    if (data[pos++] != 1)
        return false; // ClientHello
    uint32_t hsLen = (data[pos] << 16) | (data[pos + 1] << 8) | data[pos + 2];
    pos += 3;
    if (hsLen + 4 > recLen)
        return false;

    // skip version(2) + random(32)
    pos += 2 + 32;
    if (pos + 1 > len)
        return false;

    // session ID
    uint8_t sidLen = data[pos++];
    pos += sidLen;
    if (pos + 2 > len)
        return false;

    // cipher suites
    uint16_t csLen = (data[pos] << 8) | data[pos + 1];
    pos += 2 + csLen;
    if (pos + 1 > len)
        return false;

    // compression methods
    uint8_t compLen = data[pos++];
    pos += compLen;
    if (pos + 2 > len)
        return false;

    // extensions
    uint16_t extLen = (data[pos] << 8) | data[pos + 1];
    pos += 2;
    uint32_t extEnd = pos + extLen;

    while (pos + 4 <= extEnd)
    {
        uint16_t extType = (data[pos] << 8) | data[pos + 1];
        uint16_t extSize = (data[pos + 2] << 8) | data[pos + 3];
        pos += 4;
        if (extType == 0x0000)
        { // SNI
            if (pos + 2 > len)
                return false;
            uint16_t listLen = (data[pos] << 8) | data[pos + 1];
            pos += 2;
            uint32_t listEnd = pos + listLen;
            while (pos + 3 <= listEnd)
            {
                uint8_t nameType = data[pos++];
                uint16_t nameLen = (data[pos] << 8) | data[pos + 1];
                pos += 2;
                if (nameType == 0)
                {
                    if (pos + nameLen > len)
                        return false;
                    sni.assign((const char *)(data + pos), nameLen);
                    return true;
                }
                pos += nameLen;
            }
            return false;
        }
        pos += extSize;
    }
    return false;
}

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        usage();
        return -1;
    }
    const char *dev = argv[1];
    const std::string target = argv[2];
    char errbuf[PCAP_ERRBUF_SIZE];

    // open pcap handle
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (!handle)
    {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    // install BPF filter for TCP dst port 443
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "tcp dst port 443", 1, PCAP_NETMASK_UNKNOWN) < 0)
    {
        fprintf(stderr, "pcap_compile failed: %s\n", pcap_geterr(handle));
        return -1;
    }
    if (pcap_setfilter(handle, &fp) < 0)
    {
        fprintf(stderr, "pcap_setfilter failed: %s\n", pcap_geterr(handle));
        return -1;
    }
    pcap_freecode(&fp);

    if (getMyInfo(&MyInfo, dev) < 0)
    {
        fprintf(stderr, "failed to get interface info for %s\n", dev);
        pcap_close(handle);
        return -1;
    }

    // raw socket for backward RST
    int rsock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (rsock < 0)
    {
        perror("socket");
        pcap_close(handle);
        return -1;
    }
    int on = 1;
    if (setsockopt(rsock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
    {
        perror("setsockopt");
        close(rsock);
        pcap_close(handle);
        return -1;
    }

    while (true)
    {
        struct pcap_pkthdr *header;
        const u_char *packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0)
            continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
            break;

        PacketInfo *pi = (PacketInfo *)packet;
        if (pi->ethHdr_.type() != EthHdr::Ip4)
            continue;

        uint32_t ihl = pi->ipHdr_.hl() * 4;
        if (pi->ipHdr_.p() != IpHdr::Tcp)
            continue;
        uint32_t ipTotal = pi->ipHdr_.len();
        uint32_t thl = pi->tcpHdr_.off() * 4;
        uint32_t dataLen = ipTotal - ihl - thl;
        if (dataLen == 0)
            continue;

        const uint8_t *payload = packet + sizeof(EthHdr) + ihl + thl;
        // debug: check first bytes
        // printf("[DEBUG] payload %u bytes -> first 5 bytes = %02X %02X %02X %02X %02X\n",
        //        dataLen,
        //        payload[0], payload[1], payload[2], payload[3], payload[4]);

        std::string sni;
        if (!parseTlsSni(payload, dataLen, sni))
            continue;
        if (sni != target)
            continue;

        printf("Blocking SNI: %s\n", sni.c_str());

        // --- Forward RST/ACK ---
        PacketInfo *fpkt = (PacketInfo *)malloc(sizeof(PacketInfo));
        memcpy(fpkt, packet, sizeof(PacketInfo));
        fpkt->ethHdr_.smac_ = MyInfo.mac;
        fpkt->ipHdr_.len_ = htons(ihl + thl);
        fpkt->ipHdr_.sum_ = 0;
        fpkt->ipHdr_.sum_ = CheckSum((uint16_t *)&fpkt->ipHdr_, sizeof(IpHdr));

        uint32_t origSeq = pi->tcpHdr_.seq();
        uint32_t newSeq = origSeq + dataLen;
        fpkt->tcpHdr_.seq_ = htonl(newSeq);
        fpkt->tcpHdr_.flags_ = TcpHdr::Rst | TcpHdr::Ack;
        fpkt->tcpHdr_.off_rsvd_ = (sizeof(TcpHdr) / 4) << 4;
        fpkt->tcpHdr_.sum_ = 0;

        ChecksumHdr phdr;
        memset(&phdr, 0, sizeof(phdr));
        phdr.srcAddr = (uint32_t)pi->ipHdr_.sip();
        phdr.dstAddr = (uint32_t)pi->ipHdr_.dip();
        phdr.proto = pi->ipHdr_.p();
        phdr.tcpLen = htons(sizeof(TcpHdr));

        uint32_t csum = 0;
        csum += CheckSum((uint16_t *)&fpkt->tcpHdr_, sizeof(TcpHdr));
        csum += CheckSum((uint16_t *)&phdr, sizeof(phdr));
        csum = (csum & 0xFFFF) + (csum >> 16);
        fpkt->tcpHdr_.sum_ = (uint16_t)csum;

        pcap_sendpacket(handle, (const u_char *)fpkt, sizeof(PacketInfo));
        free(fpkt);

        // --- Backward RST/ACK ---
        struct
        {
            IpHdr ip;
            TcpHdr tcp;
        } bpkt;

        memcpy(&bpkt.ip, &pi->ipHdr_, sizeof(IpHdr));
        bpkt.ip.sip_ = pi->ipHdr_.dip_;
        bpkt.ip.dip_ = pi->ipHdr_.sip_;
        bpkt.ip.len_ = htons(ihl + thl);
        bpkt.ip.ttl_ = 64;
        bpkt.ip.sum_ = 0;
        bpkt.ip.sum_ = CheckSum((uint16_t *)&bpkt.ip, sizeof(IpHdr));

        memcpy(&bpkt.tcp, &pi->tcpHdr_, sizeof(TcpHdr));
        bpkt.tcp.sport_ = pi->tcpHdr_.dport_;
        bpkt.tcp.dport_ = pi->tcpHdr_.sport_;
        bpkt.tcp.seq_ = pi->tcpHdr_.ack_;
        uint32_t newAck = origSeq + dataLen;
        bpkt.tcp.ack_ = htonl(newAck);
        bpkt.tcp.flags_ = TcpHdr::Rst | TcpHdr::Ack;
        bpkt.tcp.off_rsvd_ = (sizeof(TcpHdr) / 4) << 4;
        bpkt.tcp.sum_ = 0;

        ChecksumHdr ph2;
        memset(&ph2, 0, sizeof(ph2));
        ph2.srcAddr = (uint32_t)bpkt.ip.sip_;
        ph2.dstAddr = (uint32_t)bpkt.ip.dip_;
        ph2.proto = bpkt.ip.p();
        ph2.tcpLen = htons(sizeof(TcpHdr));

        uint32_t c2 = 0;
        c2 += CheckSum((uint16_t *)&bpkt.tcp, sizeof(TcpHdr));
        c2 += CheckSum((uint16_t *)&ph2, sizeof(ph2));
        c2 = (c2 & 0xFFFF) + (c2 >> 16);
        bpkt.tcp.sum_ = (uint16_t)c2;

        struct sockaddr_in sin;
        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = inet_addr(std::string(pi->ipHdr_.sip()).c_str());

        sendto(rsock,
               &bpkt.ip,
               sizeof(IpHdr) + sizeof(TcpHdr),
               0,
               (struct sockaddr *)&sin,
               sizeof(sin));
    }

    close(rsock);
    pcap_close(handle);
    return 0;
}
