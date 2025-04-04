#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <limits.h>

#include "mfw.h"  // Ensure this header includes IPv6 field support

#define PORT_NUM_MAX USHRT_MAX

static void print_usage(void)
{
    printf("Usage: mf RULE_OPTIONS..\n"
           "MiniFirewall implements an exact match algorithm, where "
           "unspecified options are ignored.\n"
           "-i --in             input\n"
           "-o --out            output\n"
           "-s --s_ip IPADDR    source ip address\n"
           "-m --s_mask MASK    source mask\n"
           "-p --s_port PORT    source port\n"
           "-d --d_ip IPADDR    destination ip address\n"
           "-n --d_mask MASK    destination mask\n"
           "-q --d_port PORT    destination port\n"
           "-c --proto PROTO    protocol\n"
           "-a --add            add a rule\n"
           "-r --remove         remove a rule\n"
           "-v --view           view rules\n"
           "-h --help           this usage\n");
}

static void send_instruction(struct mfw_ctl *ctl)
{
    FILE *fp = fopen(DEVICE_INTF_NAME, "w");
    if (fp == NULL) {
        printf("Device file (%s) cannot be opened.\n", DEVICE_INTF_NAME);
        return;
    }
    int byte_count = fwrite(ctl, 1, sizeof(*ctl), fp);
    if (byte_count != sizeof(*ctl))
        printf("Write process is incomplete. Please try again.\n");
    fclose(fp);
}

static void view_rules(void)
{
    FILE *fp = fopen(DEVICE_INTF_NAME, "r");
    if (fp == NULL) {
        printf("Device file (%s) cannot be opened.\n", DEVICE_INTF_NAME);
        return;
    }

    struct mfw_rule rule;
    char ipbuf[INET6_ADDRSTRLEN];
    printf("I/O  Version  "
           "S_Addr                            S_Port "
           "D_Addr                            D_Port Proto\n");

    while (fread(&rule, 1, sizeof(rule), fp) == sizeof(rule)) {
        printf("%-3s  ", rule.in ? "In" : "Out");
        printf("IPv%d    ", rule.ip_version == IP_VERSION_6 ? 6 : 4);

        if (rule.ip_version == IP_VERSION_4) {
            struct in_addr addr4;

            addr4.s_addr = rule.s_ip;
            printf("%-32s ", inet_ntoa(addr4));

            printf("%-5d ", ntohs(rule.s_port));

            addr4.s_addr = rule.d_ip;
            printf("%-32s ", inet_ntoa(addr4));

            printf("%-5d ", ntohs(rule.d_port));
        } else {
            inet_ntop(AF_INET6, &rule.s_ip6, ipbuf, sizeof(ipbuf));
            printf("%-32s ", ipbuf);
            printf("%-5d ", ntohs(rule.s_port6));

            inet_ntop(AF_INET6, &rule.d_ip6, ipbuf, sizeof(ipbuf));
            printf("%-32s ", ipbuf);
            printf("%-5d ", ntohs(rule.d_port6));
        }

        printf("%-3d\n", rule.proto);
    }

    fclose(fp);
}

static int64_t parse_number(const char *str, uint32_t min_val, uint32_t max_val)
{
    char *end;
    long num = strtol(str, &end, 10);
    if (end == str || num < min_val || num > max_val)
        return -1;
    return num;
}

static int parse_arguments(int argc, char **argv, struct mfw_ctl *ret_ctl)
{
    int opt, opt_index;
    int64_t lnum;
    struct mfw_ctl ctl = {};
    struct in_addr addr4;
    struct in6_addr addr6;

    static struct option long_options[] = {
        {"in", no_argument, 0, 'i'},
        {"out", no_argument, 0, 'o'},
        {"s_ip", required_argument, 0, 's'},
        {"s_mask", required_argument, 0, 'm'},
        {"s_port", required_argument, 0, 'p'},
        {"d_ip", required_argument, 0, 'd'},
        {"d_mask", required_argument, 0, 'n'},
        {"d_port", required_argument, 0, 'q'},
        {"proto", required_argument, 0, 'c'},
        {"add", no_argument, 0, 'a'},
        {"remove", no_argument, 0, 'r'},
        {"view", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    if (argc == 1) {
        print_usage();
        return 0;
    }

    ctl.mode = MFW_NONE;
    ctl.rule.in = -1;

    while ((opt = getopt_long(argc, argv, "ios:m:p:d:n:q:c:arvh", long_options, &opt_index)) != -1) {
        switch (opt) {
        case 'i':
            if (ctl.rule.in == 0) {
                printf("Please select either In or Out\n");
                return -1;
            }
            ctl.rule.in = 1;
            break;

        case 'o':
            if (ctl.rule.in == 1) {
                printf("Please select either In or Out\n");
                return -1;
            }
            ctl.rule.in = 0;
            break;

        case 's':
            if (inet_pton(AF_INET, optarg, &addr4)) {
                ctl.rule.ip_version = IP_VERSION_4;
                ctl.rule.s_ip = addr4.s_addr;
            } else if (inet_pton(AF_INET6, optarg, &addr6)) {
                ctl.rule.ip_version = IP_VERSION_6;
                ctl.rule.s_ip6 = addr6;
            } else {
                printf("Invalid source IP address\n");
                return -1;
            }
            break;

        case 'm':
            if (ctl.rule.ip_version == IP_VERSION_4) {
                if (!inet_pton(AF_INET, optarg, &addr4)) {
                    printf("Invalid source subnet mask\n");
                    return -1;
                }
                ctl.rule.s_mask = addr4.s_addr;
            } else {
                if (!inet_pton(AF_INET6, optarg, &addr6)) {
                    printf("Invalid source subnet mask (IPv6)\n");
                    return -1;
                }
                ctl.rule.s_mask6 = addr6;
            }
            break;

        case 'p':
            lnum = parse_number(optarg, 0, USHRT_MAX);
            if (lnum < 0) {
                printf("Invalid source port number\n");
                return -1;
            }
            ctl.rule.s_port = htons((uint16_t)lnum);
            ctl.rule.s_port6 = htons((uint16_t)lnum);
            break;

        case 'd':
            if (inet_pton(AF_INET, optarg, &addr4)) {
                ctl.rule.ip_version = IP_VERSION_4;
                ctl.rule.d_ip = addr4.s_addr;
            } else if (inet_pton(AF_INET6, optarg, &addr6)) {
                ctl.rule.ip_version = IP_VERSION_6;
                ctl.rule.d_ip6 = addr6;
            } else {
                printf("Invalid destination IP address\n");
                return -1;
            }
            break;

        case 'n':
            if (ctl.rule.ip_version == IP_VERSION_4) {
                if (!inet_pton(AF_INET, optarg, &addr4)) {
                    printf("Invalid destination subnet mask\n");
                    return -1;
                }
                ctl.rule.d_mask = addr4.s_addr;
            } else {
                if (!inet_pton(AF_INET6, optarg, &addr6)) {
                    printf("Invalid destination subnet mask (IPv6)\n");
                    return -1;
                }
                ctl.rule.d_mask6 = addr6;
            }
            break;

        case 'q':
            lnum = parse_number(optarg, 0, USHRT_MAX);
            if (lnum < 0) {
                printf("Invalid destination port number\n");
                return -1;
            }
            ctl.rule.d_port = htons((uint16_t)lnum);
            ctl.rule.d_port6 = htons((uint16_t)lnum);
            break;

        case 'c':
            lnum = parse_number(optarg, 0, UCHAR_MAX);
            if (lnum < 0 || !(lnum == 0 || lnum == IPPROTO_TCP || lnum == IPPROTO_UDP)) {
                printf("Invalid protocol number\n");
                return -1;
            }
            ctl.rule.proto = (uint8_t)lnum;
            break;

        case 'a':
            if (ctl.mode != MFW_NONE) {
                printf("Only one mode can be selected.\n");
                return -1;
            }
            ctl.mode = MFW_ADD;
            break;

        case 'r':
            if (ctl.mode != MFW_NONE) {
                printf("Only one mode can be selected.\n");
                return -1;
            }
            ctl.mode = MFW_REMOVE;
            break;

        case 'v':
            if (ctl.mode != MFW_NONE) {
                printf("Only one mode can be selected.\n");
                return -1;
            }
            ctl.mode = MFW_VIEW;
            break;

        case 'h':
        default:
            print_usage();
            return -1;
        }
    }

    if (ctl.mode == MFW_NONE) {
        printf("Please specify mode --(add|remove|view)\n");
        return -1;
    }
    if (ctl.mode != MFW_VIEW && ctl.rule.in == -1) {
        printf("Please specify either In or Out\n");
        return -1;
    }

    *ret_ctl = ctl;
    return 0;
}

int main(int argc, char *argv[])
{
    struct mfw_ctl ctl = {};
    int ret = parse_arguments(argc, argv, &ctl);
    if (ret < 0)
        return ret;

    switch (ctl.mode) {
    case MFW_ADD:
    case MFW_REMOVE:
        send_instruction(&ctl);
        break;
    case MFW_VIEW:
        view_rules();
        break;
    default:
        return 0;
    }
}
