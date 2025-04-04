#ifndef __MFW_H__
#define __MFW_H__

#include <cstdint>
#include <netinet/in.h>

#define DEVICE_INTF_NAME "/dev/mfw_dev"

enum {
    MFW_NONE = 0,
    MFW_ADD,
    MFW_REMOVE,
    MFW_VIEW,
};

// Dual-stack IP Support (IPv4 or IPv6)
struct mfw_rule {
    int in;  // Direction: 1 = In, 0 = Out

    // IPv4/IPv6 agnostic addresses
    uint8_t s_ip[16];    // Source IP
    uint8_t s_mask[16];  // Source Mask
    uint16_t s_port;

    uint8_t d_ip[16];    // Destination IP
    uint8_t d_mask[16];  // Destination Mask
    uint16_t d_port;

    uint8_t proto; // Protocol (TCP/UDP)
    uint8_t ip_version; // 4 or 6
};

struct mfw_ctl {
    int mode;            // MFW_ADD, MFW_REMOVE, MFW_VIEW
    struct mfw_rule rule;
};

#endif
