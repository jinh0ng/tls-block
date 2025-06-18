// tls-block main.cpp
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
#include <map>

#include "ip.h"
#include "iphdr.h"
#include "ethhdr.h"
#include "tcphdr.h"
#include "mac.h"

void usage()
{
    printf("syntax : tls-block <interface> <server name>\n");
    printf("sample : tls-block wlan0 naver.com\n");
}

#pragma pack(push, 1)
struct TlsSegmentHeader
{
    uint8_t seg_type;
    uint16_t seg_ver;
    uint16_t seg_len;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct TlsHandshakeHeader
{
    uint8_t handshake_type;
    uint8_t length[3];
};
#pragma pack(pop)

struct ConnectionKey
{
    uint32_t srcIP;   // 발신지 IP
    uint16_t srcPort; // 발신지 포트
    uint32_t dstIP;   // 수신지 IP
    uint16_t dstPort; // 수신지 포트

    // std::map에 사용할 순서 비교자: srcIP→srcPort→dstIP→dstPort
    bool operator<(const ConnectionKey &o) const
    {
        if (srcIP != o.srcIP)
            return srcIP < o.srcIP;
        if (srcPort != o.srcPort)
            return srcPort < o.srcPort;
        if (dstIP != o.dstIP)
            return dstIP < o.dstIP;
        return dstPort < o.dstPort;
    }
};

#pragma pack(push, 1)
struct PseudoHeader
{
    uint32_t src;
    uint32_t dst;
    uint8_t reserved;
    uint8_t protocol;
    uint16_t tcp_len;
};
#pragma pack(pop)

typedef struct
{
    Mac mac;
    Ip ip;
} t_info;
t_info MyInfo;

int sd = 0;
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

// IP 헤더 체크섬 갱신
void ip_Checksum(IpHdr *hdr)
{
    hdr->check = 0;
    hdr->check = CheckSum(
        reinterpret_cast<uint16_t *>(hdr),
        (hdr->version_ihl & 0x0F) * 4);
}

// TCP 체크섬 계산 및 설정
void tcp_Checksum(IpHdr *iph, TcpHdr *tcph, const uint8_t *payload, size_t payload_len)
{
    // Pseudo TCP header 구성
    struct TcpPseudoHdr
    {
        uint32_t src;
        uint32_t dst;
        uint8_t zero;
        uint8_t proto;
        uint16_t tcp_len;
    } pseudo{
        iph->sip_,
        iph->dip_,
        0,
        IPPROTO_TCP,
        htons(static_cast<uint16_t>(sizeof(TcpHdr) + payload_len))};

    // 임시 버퍼에 PseudoHdr + TCPHdr + 데이터 복사
    size_t totalBytes = sizeof(pseudo) + sizeof(TcpHdr) + payload_len;
    uint8_t *tmpBuf = static_cast<uint8_t *>(alloca(totalBytes));
    memcpy(tmpBuf, &pseudo, sizeof(pseudo));

    uint8_t *cur = tmpBuf + sizeof(pseudo);
    tcph->crc = 0; // 체크섬 필드 초기화
    memcpy(cur, tcph, sizeof(TcpHdr));
    cur += sizeof(TcpHdr);

    if (payload_len)
        memcpy(cur, payload, payload_len);

    // 최종 체크섬 계산 후 기록
    tcph->crc = CheckSum(
        reinterpret_cast<uint16_t *>(tmpBuf),
        static_cast<int>(totalBytes));
}

// TLS ClientHello에서 SNI를 추출 (실패 시 NULL 반환)
const char *parse_sni(const uint8_t *tls_buf, size_t tls_len)
{
    // 레코드+핸드쉐이크 헤더 건너뛰기
    size_t idx = sizeof(TlsSegmentHeader) + sizeof(TlsHandshakeHeader);
    if (tls_len <= idx + 34)
        return nullptr;
    idx += 34; // 버전(2) + 랜덤(32)

    // SessionID
    if (idx + 1 > tls_len)
        return nullptr;
    uint8_t sid_sz = tls_buf[idx];
    if (idx + 1 + sid_sz > tls_len)
        return nullptr;
    idx += 1 + sid_sz;

    // CipherSuites
    if (idx + 2 > tls_len)
        return nullptr;
    uint16_t cs_sz = (tls_buf[idx] << 8) | tls_buf[idx + 1];
    fprintf(stderr, "[DEBUG] cipher_suites=%u @%zu/%zu\n", cs_sz, idx, tls_len);
    if (idx + 2 + cs_sz > tls_len)
        return nullptr;
    idx += 2 + cs_sz;

    // CompressionMethods
    if (idx + 1 > tls_len)
        return nullptr;
    uint8_t comp_sz = tls_buf[idx];
    if (idx + 1 + comp_sz > tls_len)
        return nullptr;
    idx += 1 + comp_sz;

    // Extensions 길이
    if (idx + 2 > tls_len)
        return nullptr;
    uint16_t ext_total = (tls_buf[idx] << 8) | tls_buf[idx + 1];
    idx += 2;
    fprintf(stderr, "[TRACE] total_extensions=%u, start=%zu\n", ext_total, idx);

    size_t ext_end = idx + ext_total;
    // Extension 항목 탐색
    while (idx + 4 <= tls_len && idx + 4 <= ext_end)
    {
        uint16_t ext_type = (tls_buf[idx] << 8) | tls_buf[idx + 1];
        uint16_t ext_len = (tls_buf[idx + 2] << 8) | tls_buf[idx + 3];
        idx += 4;

        if (ext_type == 0x0000) // Server Name extension
        {
            if (idx + 5 > tls_len)
                return nullptr;
            uint8_t nm_type = tls_buf[idx + 2];
            uint16_t nm_len = (tls_buf[idx + 3] << 8) | tls_buf[idx + 4];
            fprintf(stderr, "[INFO] SNI type=%u, length=%u\n", nm_type, nm_len);

            if (nm_type != 0 || idx + 5 + nm_len > tls_len)
                return nullptr;

            fprintf(stderr, "[INFO] SNI extracted successfully\n");
            return reinterpret_cast<const char *>(tls_buf + idx + 5);
        }

        idx += ext_len;
    }

    // SNI 미발견
    return nullptr;
}

// Forward RST 패킷 전송
int forward_rst(pcap_t *session,
                const EthHdr *ref_eth,
                const IpHdr *ref_ip,
                const TcpHdr *ref_tcp,
                int payload_size,
                Mac src_mac)
{
    // 프레임용 버퍼 확보
    uint8_t frameBuf[sizeof(EthHdr) + sizeof(IpHdr) + sizeof(TcpHdr)] = {0};

    // 이더넷/IP/TCP 헤더 포인터 설정
    EthHdr *ethFrame = reinterpret_cast<EthHdr *>(frameBuf);
    IpHdr *ipFrame = reinterpret_cast<IpHdr *>(frameBuf + sizeof(EthHdr));
    TcpHdr *tcpFrame = reinterpret_cast<TcpHdr *>(frameBuf + sizeof(EthHdr) + sizeof(IpHdr));

    // 이더넷 헤더 구성
    ethFrame->smac_ = src_mac;
    ethFrame->dmac_ = ref_eth->dmac_;
    ethFrame->type_ = htons(EthHdr::Ip4);

    // IP 헤더 설정
    ipFrame->version_ihl = 0x45;
    ipFrame->tos = 0;
    ipFrame->total_len = htons(sizeof(IpHdr) + sizeof(TcpHdr));
    ipFrame->id = htons(rand());
    ipFrame->frag_offset = htons(0x4000);
    ipFrame->ttl = ref_ip->ttl;
    ipFrame->proto = IPPROTO_TCP;
    ipFrame->sip_ = ref_ip->sip_;
    ipFrame->dip_ = ref_ip->dip_;
    ip_Checksum(ipFrame);

    // TCP 헤더 설정
    tcpFrame->sport = ref_tcp->sport;
    tcpFrame->dport = ref_tcp->dport;
    tcpFrame->seqnum = htonl(ntohl(ref_tcp->seqnum) + payload_size);
    tcpFrame->acknum = ref_tcp->acknum;
    tcpFrame->data_offset_reserved = 0x50;
    tcpFrame->flags = 0x14; // RST+ACK
    tcpFrame->win = 0;
    tcpFrame->urgptr = 0;
    tcp_Checksum(ipFrame, tcpFrame, nullptr, 0);

    // 패킷 전송
    if (pcap_sendpacket(session, frameBuf, sizeof(frameBuf)) != 0)
    {
        fprintf(stderr, "[WARN] Upstream RST fail\n");
    }
    else
    {
        fprintf(stderr, "[INFO] Upstream RST success\n");
    }

    return 0;
}

// 역방향 RST 패킷 전송
int backward_rst(PIpHdr orig_ip,
                 PTcpHdr orig_tcp,
                 int payload_len,
                 int sock_fd)
{
    // 패킷 버퍼 할당
    uint8_t pkt_buf[sizeof(IpHdr) + sizeof(TcpHdr)] = {0};

    // IP/TCP 헤더 포인터 설정
    PIpHdr ip_out = reinterpret_cast<PIpHdr>(pkt_buf);
    PTcpHdr tcp_out = reinterpret_cast<PTcpHdr>(pkt_buf + sizeof(IpHdr));

    // IP 헤더 복사 및 값 뒤집기
    *ip_out = *orig_ip;
    ip_out->version_ihl = 0x45; // IPv4, 헤더 길이 20바이트
    ip_out->tos = 0;
    ip_out->total_len = htons(sizeof(IpHdr) + sizeof(TcpHdr));
    ip_out->id = htons(rand());
    std::swap(ip_out->sip_, ip_out->dip_); // 출/도착 IP 교환
    ip_out->check = 0;
    ip_Checksum(ip_out); // IP 체크섬 갱신

    // TCP 헤더 필드 설정
    tcp_out->sport = orig_tcp->dport; // 포트 교환
    tcp_out->dport = orig_tcp->sport;
    tcp_out->seqnum = orig_tcp->acknum; // seq/ack 맞춤
    tcp_out->acknum = htonl(ntohl(orig_tcp->seqnum) + payload_len);
    tcp_out->data_offset_reserved = 0x50; // 헤더 길이 20바이트
    tcp_out->flags = 0x14;                // RST + ACK
    tcp_out->win = 0;
    tcp_out->urgptr = 0;
    tcp_out->crc = 0;
    tcp_Checksum(ip_out, tcp_out, nullptr, 0); // TCP 체크섬 계산

    // 대상 주소 구조체
    struct sockaddr_in dest{};
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = orig_ip->sip_; // 원본 출발지로 전송

    // 패킷 전송
    int sent = sendto(sock_fd,
                      pkt_buf,
                      sizeof(pkt_buf),
                      0,
                      reinterpret_cast<struct sockaddr *>(&dest),
                      sizeof(dest));
    close(sock_fd);

    if (sent < 0)
    {
        perror("[Error] fail");
        return -1;
    }
    else
    {
        puts("[Success]: RST packet sent");
        return 0;
    }
}

int main(int argc, char *argv[])
{
    std::map<ConnectionKey, std::string> segmap;

    if (argc != 3)
    {
        usage();
        return -1;
    }
    char *dev = argv[1];
    const char *target = argv[2];
    printf("Target: %s\n", target);

    if (getMyInfo(&MyInfo, dev) < 0)
    {
        fprintf(stderr, "failed to get local MAC/IP on %s\n", dev);
        return -1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, -1, errbuf);
    if (!handle)
    {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    int sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    int on = 1;
    setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));

    while (true)
    {
        struct pcap_pkthdr *pktMeta;
        const u_char *pktData;

        if (pcap_next_ex(handle, &pktMeta, &pktData) <= 0)
            continue;

        // 이더넷 헤더 파싱
        const EthHdr *ethFrame = reinterpret_cast<const EthHdr *>(pktData);
        if (ethFrame->type() != EthHdr::Ip4)
            continue;

        // IP 헤더 파싱
        const IpHdr *ipHdr4 = reinterpret_cast<const IpHdr *>(
            pktData + sizeof(EthHdr));
        if (ipHdr4->proto != IPPROTO_TCP)
            continue;

        // 헤더 길이 계산
        int ipHdrLen = (ipHdr4->version_ihl & 0x0F) * 4;
        const TcpHdr *tcpHdr = reinterpret_cast<const TcpHdr *>(
            pktData + sizeof(EthHdr) + ipHdrLen);
        if (ntohs(tcpHdr->dport) != 443)
            continue;
        int tcpHdrLen = ((tcpHdr->data_offset_reserved >> 4) & 0x0F) * 4;

        // TLS 페이로드 위치/길이
        const uint8_t *tlsPtr = pktData + sizeof(EthHdr) + ipHdrLen + tcpHdrLen;
        int tlsLen = ntohs(ipHdr4->total_len) - ipHdrLen - tcpHdrLen;
        if (tlsLen <= (int)(sizeof(TlsSegmentHeader) + sizeof(TlsHandshakeHeader)))
            continue;

        // 스트림 키 생성 (네트워크 바이트오더 → 호스트 바이트오더)
        ConnectionKey flowKey{
            ntohl(ipHdr4->sip_),
            ntohs(tcpHdr->sport),
            ntohl(ipHdr4->dip_),
            ntohs(tcpHdr->dport)};

        auto &streamBuf = segmap[flowKey];
        streamBuf.append(reinterpret_cast<const char *>(tlsPtr), tlsLen);
        fprintf(stderr, "[CAPTURE] +%d bytes\n", tlsLen);

        // 페이로드 덤프
        fprintf(stdout, "[PRE] %02x %02x %02x %02x %02x %02x\n",
                tlsPtr[0], tlsPtr[1], tlsPtr[2],
                tlsPtr[3], tlsPtr[4], tlsPtr[5]);

        // TLS 레코드/핸드쉐이크 확인
        auto recHdr = reinterpret_cast<const TlsSegmentHeader *>(streamBuf.data());
        if (recHdr->seg_type != 0x16)
            continue;
        auto hsHdr = reinterpret_cast<const TlsHandshakeHeader *>(
            streamBuf.data() + sizeof(TlsSegmentHeader));
        if (hsHdr->handshake_type != 0x01)
            continue;

        fprintf(stderr, "[INFO] buffer size=%zu\n", streamBuf.size());
        int totalBytes = streamBuf.size();

        // SNI 추출
        const char *hostName = parse_sni(
            reinterpret_cast<const uint8_t *>(streamBuf.data()), streamBuf.size());
        if (hostName)
            fprintf(stderr, "[INFO] SNI=%s\n", hostName);

        // 도메인 매칭 시 RST 전송
        if (hostName &&
            memmem(hostName, strlen(hostName), target, strlen(target)))
        {
            fprintf(stdout, "[DBG] tot=%d, seqO=%u, seqN=%u\n",
                    totalBytes,
                    ntohl(tcpHdr->seqnum),
                    ntohl(ntohl(tcpHdr->seqnum) + totalBytes));

            backward_rst(
                const_cast<IpHdr *>(ipHdr4),
                const_cast<TcpHdr *>(tcpHdr),
                totalBytes,
                sd);

            forward_rst(
                handle,
                ethFrame,
                ipHdr4,
                tcpHdr,
                totalBytes,
                MyInfo.mac);

            segmap.erase(flowKey);
        }
    }

    pcap_close(handle);
    return 0;
}