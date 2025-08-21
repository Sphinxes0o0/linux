/*
 * Linux Conntrack 用户空间示例程序
 * 演示如何通过netlink接口与内核conntrack模块交互
 * 
 * 编译: gcc -o conntrack_example conntrack_example.c -lnetfilter_conntrack -lnfnetlink
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack_tcp.h>

/* 连接事件回调函数 */
static int event_callback(enum nf_conntrack_msg_type type,
                         struct nf_conntrack *ct,
                         void *data)
{
    char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];
    uint16_t src_port, dst_port;
    uint8_t proto;
    const char *proto_name;
    const char *event_name;

    /* 获取事件类型 */
    switch(type) {
        case NFCT_T_NEW:
            event_name = "NEW";
            break;
        case NFCT_T_UPDATE:
            event_name = "UPDATE";
            break;
        case NFCT_T_DESTROY:
            event_name = "DESTROY";
            break;
        default:
            event_name = "UNKNOWN";
            break;
    }

    /* 获取协议 */
    proto = nfct_get_attr_u8(ct, ATTR_L4PROTO);
    switch(proto) {
        case IPPROTO_TCP:
            proto_name = "TCP";
            break;
        case IPPROTO_UDP:
            proto_name = "UDP";
            break;
        case IPPROTO_ICMP:
            proto_name = "ICMP";
            break;
        default:
            proto_name = "OTHER";
            break;
    }

    /* 获取源地址和端口 */
    if (nfct_attr_is_set(ct, ATTR_IPV4_SRC)) {
        struct in_addr addr;
        addr.s_addr = nfct_get_attr_u32(ct, ATTR_IPV4_SRC);
        inet_ntop(AF_INET, &addr, src_ip, sizeof(src_ip));
    } else if (nfct_attr_is_set(ct, ATTR_IPV6_SRC)) {
        const void *addr = nfct_get_attr(ct, ATTR_IPV6_SRC);
        inet_ntop(AF_INET6, addr, src_ip, sizeof(src_ip));
    } else {
        strcpy(src_ip, "unknown");
    }

    /* 获取目的地址和端口 */
    if (nfct_attr_is_set(ct, ATTR_IPV4_DST)) {
        struct in_addr addr;
        addr.s_addr = nfct_get_attr_u32(ct, ATTR_IPV4_DST);
        inet_ntop(AF_INET, &addr, dst_ip, sizeof(dst_ip));
    } else if (nfct_attr_is_set(ct, ATTR_IPV6_DST)) {
        const void *addr = nfct_get_attr(ct, ATTR_IPV6_DST);
        inet_ntop(AF_INET6, addr, dst_ip, sizeof(dst_ip));
    } else {
        strcpy(dst_ip, "unknown");
    }

    /* 获取端口 */
    if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
        src_port = ntohs(nfct_get_attr_u16(ct, ATTR_PORT_SRC));
        dst_port = ntohs(nfct_get_attr_u16(ct, ATTR_PORT_DST));
        
        printf("[%s] %s: %s:%u -> %s:%u", 
               event_name, proto_name,
               src_ip, src_port, dst_ip, dst_port);
    } else {
        printf("[%s] %s: %s -> %s", 
               event_name, proto_name,
               src_ip, dst_ip);
    }

    /* 显示TCP状态 */
    if (proto == IPPROTO_TCP && nfct_attr_is_set(ct, ATTR_TCP_STATE)) {
        uint8_t state = nfct_get_attr_u8(ct, ATTR_TCP_STATE);
        const char *state_name;
        
        switch(state) {
            case TCP_CONNTRACK_SYN_SENT:
                state_name = "SYN_SENT";
                break;
            case TCP_CONNTRACK_SYN_RECV:
                state_name = "SYN_RECV";
                break;
            case TCP_CONNTRACK_ESTABLISHED:
                state_name = "ESTABLISHED";
                break;
            case TCP_CONNTRACK_FIN_WAIT:
                state_name = "FIN_WAIT";
                break;
            case TCP_CONNTRACK_CLOSE_WAIT:
                state_name = "CLOSE_WAIT";
                break;
            case TCP_CONNTRACK_LAST_ACK:
                state_name = "LAST_ACK";
                break;
            case TCP_CONNTRACK_TIME_WAIT:
                state_name = "TIME_WAIT";
                break;
            case TCP_CONNTRACK_CLOSE:
                state_name = "CLOSE";
                break;
            default:
                state_name = "UNKNOWN";
                break;
        }
        printf(" [State: %s]", state_name);
    }

    /* 显示超时时间 */
    if (nfct_attr_is_set(ct, ATTR_TIMEOUT)) {
        uint32_t timeout = nfct_get_attr_u32(ct, ATTR_TIMEOUT);
        printf(" [Timeout: %us]", timeout);
    }

    /* 显示包/字节计数 */
    if (nfct_attr_is_set(ct, ATTR_ORIG_COUNTER_PACKETS)) {
        uint64_t packets = nfct_get_attr_u64(ct, ATTR_ORIG_COUNTER_PACKETS);
        uint64_t bytes = nfct_get_attr_u64(ct, ATTR_ORIG_COUNTER_BYTES);
        printf(" [Packets: %lu, Bytes: %lu]", packets, bytes);
    }

    printf("\n");
    
    return NFCT_CB_CONTINUE;
}

/* 显示连接表中的所有连接 */
static void dump_conntrack_table(void)
{
    struct nfct_handle *h;
    int ret;

    printf("\n=== Current Conntrack Table ===\n");

    /* 创建netlink句柄 */
    h = nfct_open(CONNTRACK, 0);
    if (!h) {
        perror("nfct_open");
        return;
    }

    /* 注册回调 */
    nfct_callback_register(h, NFCT_T_ALL, event_callback, NULL);

    /* 查询连接表 */
    ret = nfct_query(h, NFCT_Q_DUMP, &family);
    if (ret == -1) {
        perror("nfct_query");
    }

    nfct_close(h);
}

/* 监听连接事件 */
static void monitor_conntrack_events(void)
{
    struct nfct_handle *h;
    int ret;

    printf("\n=== Monitoring Conntrack Events (Press Ctrl+C to stop) ===\n");

    /* 创建事件监听句柄 */
    h = nfct_open(CONNTRACK, NF_NETLINK_CONNTRACK_NEW | 
                             NF_NETLINK_CONNTRACK_UPDATE |
                             NF_NETLINK_CONNTRACK_DESTROY);
    if (!h) {
        perror("nfct_open");
        return;
    }

    /* 注册回调 */
    nfct_callback_register(h, NFCT_T_ALL, event_callback, NULL);

    /* 开始监听 */
    printf("Listening for events...\n");
    ret = nfct_catch(h);
    if (ret == -1) {
        perror("nfct_catch");
    }

    nfct_close(h);
}

/* 创建一个测试连接 */
static void create_test_connection(void)
{
    struct nfct_handle *h;
    struct nf_conntrack *ct;
    int ret;

    printf("\n=== Creating Test Connection ===\n");

    /* 创建句柄 */
    h = nfct_open(CONNTRACK, 0);
    if (!h) {
        perror("nfct_open");
        return;
    }

    /* 创建连接对象 */
    ct = nfct_new();
    if (!ct) {
        perror("nfct_new");
        nfct_close(h);
        return;
    }

    /* 设置连接属性 */
    nfct_set_attr_u8(ct, ATTR_L3PROTO, AF_INET);
    nfct_set_attr_u8(ct, ATTR_L4PROTO, IPPROTO_TCP);
    
    /* 设置源地址和端口 */
    struct in_addr src, dst;
    inet_pton(AF_INET, "192.168.1.100", &src);
    inet_pton(AF_INET, "8.8.8.8", &dst);
    
    nfct_set_attr_u32(ct, ATTR_IPV4_SRC, src.s_addr);
    nfct_set_attr_u32(ct, ATTR_IPV4_DST, dst.s_addr);
    nfct_set_attr_u16(ct, ATTR_PORT_SRC, htons(12345));
    nfct_set_attr_u16(ct, ATTR_PORT_DST, htons(80));
    
    /* 设置TCP状态 */
    nfct_set_attr_u8(ct, ATTR_TCP_STATE, TCP_CONNTRACK_ESTABLISHED);
    
    /* 设置超时 */
    nfct_set_attr_u32(ct, ATTR_TIMEOUT, 3600);
    
    /* 创建连接 */
    ret = nfct_query(h, NFCT_Q_CREATE, ct);
    if (ret == -1) {
        perror("nfct_query");
    } else {
        printf("Test connection created successfully\n");
    }

    nfct_destroy(ct);
    nfct_close(h);
}

/* 删除指定连接 */
static void delete_connection(const char *src_ip, uint16_t src_port,
                            const char *dst_ip, uint16_t dst_port)
{
    struct nfct_handle *h;
    struct nf_conntrack *ct;
    struct in_addr src, dst;
    int ret;

    printf("\n=== Deleting Connection ===\n");

    /* 创建句柄 */
    h = nfct_open(CONNTRACK, 0);
    if (!h) {
        perror("nfct_open");
        return;
    }

    /* 创建连接对象 */
    ct = nfct_new();
    if (!ct) {
        perror("nfct_new");
        nfct_close(h);
        return;
    }

    /* 设置要删除的连接属性 */
    nfct_set_attr_u8(ct, ATTR_L3PROTO, AF_INET);
    nfct_set_attr_u8(ct, ATTR_L4PROTO, IPPROTO_TCP);
    
    inet_pton(AF_INET, src_ip, &src);
    inet_pton(AF_INET, dst_ip, &dst);
    
    nfct_set_attr_u32(ct, ATTR_IPV4_SRC, src.s_addr);
    nfct_set_attr_u32(ct, ATTR_IPV4_DST, dst.s_addr);
    nfct_set_attr_u16(ct, ATTR_PORT_SRC, htons(src_port));
    nfct_set_attr_u16(ct, ATTR_PORT_DST, htons(dst_port));
    
    /* 删除连接 */
    ret = nfct_query(h, NFCT_Q_DESTROY, ct);
    if (ret == -1) {
        perror("nfct_query");
    } else {
        printf("Connection deleted successfully\n");
    }

    nfct_destroy(ct);
    nfct_close(h);
}

/* 显示统计信息 */
static void show_statistics(void)
{
    FILE *fp;
    char line[256];
    
    printf("\n=== Conntrack Statistics ===\n");
    
    /* 读取统计信息 */
    fp = fopen("/proc/sys/net/netfilter/nf_conntrack_count", "r");
    if (fp) {
        if (fgets(line, sizeof(line), fp)) {
            printf("Current connections: %s", line);
        }
        fclose(fp);
    }
    
    fp = fopen("/proc/sys/net/netfilter/nf_conntrack_max", "r");
    if (fp) {
        if (fgets(line, sizeof(line), fp)) {
            printf("Maximum connections: %s", line);
        }
        fclose(fp);
    }
    
    /* 显示详细统计 */
    fp = fopen("/proc/net/stat/nf_conntrack", "r");
    if (fp) {
        printf("\nDetailed statistics:\n");
        while (fgets(line, sizeof(line), fp)) {
            printf("%s", line);
        }
        fclose(fp);
    }
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        printf("Usage: %s <command>\n", argv[0]);
        printf("Commands:\n");
        printf("  dump     - Dump current conntrack table\n");
        printf("  monitor  - Monitor conntrack events\n");
        printf("  create   - Create a test connection\n");
        printf("  delete <src_ip> <src_port> <dst_ip> <dst_port> - Delete a connection\n");
        printf("  stats    - Show statistics\n");
        return 1;
    }

    if (strcmp(argv[1], "dump") == 0) {
        dump_conntrack_table();
    } else if (strcmp(argv[1], "monitor") == 0) {
        monitor_conntrack_events();
    } else if (strcmp(argv[1], "create") == 0) {
        create_test_connection();
    } else if (strcmp(argv[1], "delete") == 0 && argc == 6) {
        delete_connection(argv[2], atoi(argv[3]), argv[4], atoi(argv[5]));
    } else if (strcmp(argv[1], "stats") == 0) {
        show_statistics();
    } else {
        printf("Invalid command\n");
        return 1;
    }

    return 0;
}