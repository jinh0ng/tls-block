#pragma once

#include <cstdint>
#include <arpa/inet.h>

#pragma pack(push, 1)
struct TcpHdr final
{
    uint16_t sport;
    uint16_t dport;
    uint32_t seqnum;
    uint32_t acknum;
    uint8_t data_offset_reserved;
    uint8_t flags;
    uint16_t win;
    uint16_t crc;
    uint16_t urgptr;
};
typedef TcpHdr *PTcpHdr;
#pragma pack(pop)