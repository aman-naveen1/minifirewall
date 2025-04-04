struct mfw_rule {
    int in;
    int ip_version;

    uint32_t s_ip;
    struct in6_addr s_ip6;

    uint32_t s_mask;
    struct in6_addr s_mask6;

    uint16_t s_port;
    uint16_t s_port6;

    uint32_t d_ip;
    struct in6_addr d_ip6;

    uint32_t d_mask;
    struct in6_addr d_mask6;

    uint16_t d_port;
    uint16_t d_port6;

    uint8_t proto;
};

#define IP_VERSION_4 4
#define IP_VERSION_6 6

struct mfw_ctl {
    int mode;
    struct mfw_rule rule;
};

#define MFW_NONE 0
#define MFW_ADD 1
#define MFW_REMOVE 2
#define MFW_VIEW 3

#define DEVICE_INTF_NAME "/dev/mfw"  // Or whatever your char device is
