# Linux Conntrack（连接跟踪）模块深度分析

## 目录
1. [概述](#概述)
2. [核心数据结构](#核心数据结构)
3. [初始化流程](#初始化流程)
4. [数据包处理流程](#数据包处理流程)
5. [连接跟踪表实现](#连接跟踪表实现)
6. [协议状态机](#协议状态机)
7. [超时和垃圾回收](#超时和垃圾回收)
8. [NAT集成](#nat集成)
9. [性能优化](#性能优化)

## 概述

Conntrack（Connection Tracking）是Linux内核中Netfilter框架的核心组件之一，负责跟踪网络连接的状态。它为状态防火墙、NAT（网络地址转换）等功能提供基础支持。

### 主要功能
- **连接状态跟踪**：记录每个连接的状态（NEW、ESTABLISHED、RELATED等）
- **协议识别**：支持TCP、UDP、ICMP等多种协议
- **NAT支持**：为NAT功能提供连接映射信息
- **会话管理**：管理连接的生命周期和超时

### 源码位置
主要源码位于Linux内核的以下目录：
- `net/netfilter/nf_conntrack_*`：核心实现
- `include/net/netfilter/nf_conntrack.h`：主要头文件
- `include/uapi/linux/netfilter/nf_conntrack_*.h`：用户空间API

## 核心数据结构

### 1. struct nf_conn - 连接跟踪实体

```c
/* include/net/netfilter/nf_conntrack.h */
struct nf_conn {
    /* 引用计数，用于内存管理 */
    struct nf_conntrack ct_general;

    /* 自旋锁，保护并发访问 */
    spinlock_t lock;

    /* 连接超时时间 */
    u32 timeout;

    /* 连接所属的网络命名空间 */
    struct net *ct_net;

    /* 双向连接的tuple信息 */
    struct nf_conntrack_tuple_hash tuplehash[IP_CT_DIR_MAX];

    /* 连接状态 */
    unsigned long status;

    /* 协议相关的私有数据 */
    union nf_conntrack_proto proto;

    /* 期望连接链表 */
    struct list_head master_list;

    /* 扩展数据区域 */
    struct nf_ct_ext *ext;

    /* 每CPU计数器 */
    struct nf_conn_counter *counters;

    /* 标记和安全标记 */
    u32 mark;
    u32 secmark;

    /* 时间戳 */
    u32 timestamp;
};
```

#### 关键字段解析：

1. **ct_general**: 包含引用计数，用于管理连接对象的生命周期
2. **tuplehash**: 存储连接的五元组信息（源IP、源端口、目的IP、目的端口、协议）
3. **status**: 连接状态标志位，包括：
   - IPS_EXPECTED：期望连接
   - IPS_SEEN_REPLY：已看到回复包
   - IPS_ASSURED：确认的连接
   - IPS_CONFIRMED：已确认连接
   - IPS_SRC_NAT/IPS_DST_NAT：NAT标志

### 2. struct nf_conntrack_tuple - 连接五元组

```c
/* include/net/netfilter/nf_conntrack_tuple.h */
struct nf_conntrack_tuple {
    struct nf_conntrack_man src;  /* 源地址信息 */
    
    /* 目的地址信息 */
    struct {
        union nf_inet_addr u3;
        union {
            __be16 all;
            
            struct {
                __be16 port;
            } tcp;
            struct {
                __be16 port;
            } udp;
            struct {
                u8 type, code;
            } icmp;
            struct {
                __be16 port;
            } dccp;
            struct {
                __be16 port;
            } sctp;
            struct {
                __be16 key;
            } gre;
        } u;
        
        /* 协议号 */
        u8 protonum;
        
        /* 方向：原始或回复 */
        u8 dir;
    } dst;
};
```

### 3. struct nf_conntrack_l4proto - 四层协议处理器

```c
/* include/net/netfilter/nf_conntrack_l4proto.h */
struct nf_conntrack_l4proto {
    /* 协议号（IPPROTO_TCP, IPPROTO_UDP等） */
    u8 l4proto;

    /* 协议名称 */
    const char *name;

    /* 数据包处理函数 */
    int (*packet)(struct nf_conn *ct,
                  const struct sk_buff *skb,
                  unsigned int dataoff,
                  enum ip_conntrack_info ctinfo,
                  const struct nf_hook_state *state);

    /* 创建新连接 */
    bool (*new)(struct nf_conn *ct, const struct sk_buff *skb,
                unsigned int dataoff);

    /* 销毁连接 */
    void (*destroy)(struct nf_conn *ct);

    /* 错误处理 */
    int (*error)(struct nf_conn *tmpl, struct sk_buff *skb,
                 unsigned int dataoff,
                 const struct nf_hook_state *state);

    /* 超时值数组 */
    unsigned int *timeout;
};
```

## 初始化流程

### 1. 模块初始化

```c
/* net/netfilter/nf_conntrack_core.c */
static int __init nf_conntrack_standalone_init(void)
{
    int ret;

    /* 初始化连接跟踪核心 */
    ret = nf_conntrack_init_start();
    if (ret < 0)
        goto out;

    /* 注册各种协议处理器 */
    ret = nf_conntrack_proto_init();
    if (ret < 0)
        goto out_proto;

    /* 初始化proc文件系统接口 */
    ret = nf_conntrack_standalone_init_proc();
    if (ret < 0)
        goto out_proc;

    /* 初始化sysctl接口 */
    ret = nf_conntrack_standalone_init_sysctl();
    if (ret < 0)
        goto out_sysctl;

    /* 完成初始化 */
    nf_conntrack_init_end();

    return 0;

out_sysctl:
    nf_conntrack_standalone_fini_proc();
out_proc:
    nf_conntrack_proto_fini();
out_proto:
    nf_conntrack_cleanup_end();
out:
    return ret;
}
```

### 2. 哈希表初始化

```c
/* net/netfilter/nf_conntrack_core.c */
int nf_conntrack_init_start(void)
{
    unsigned int hashsize, i;
    int ret = -ENOMEM;

    /* 计算哈希表大小 */
    if (!nf_conntrack_htable_size) {
        nf_conntrack_htable_size = nf_conntrack_default_hashsize();
    }

    /* 分配哈希表内存 */
    nf_conntrack_hash = nf_ct_alloc_hashtable(&nf_conntrack_htable_size, 1);
    if (!nf_conntrack_hash)
        return -ENOMEM;

    /* 初始化每个哈希桶 */
    for (i = 0; i < nf_conntrack_htable_size; i++)
        INIT_HLIST_NULLS_HEAD(&nf_conntrack_hash[i], i);

    /* 创建slab缓存 */
    nf_conntrack_cachep = kmem_cache_create("nf_conntrack",
                                           sizeof(struct nf_conn),
                                           NFCT_INFOMASK + 1,
                                           SLAB_TYPESAFE_BY_RCU | 
                                           SLAB_HWCACHE_ALIGN,
                                           NULL);
    if (!nf_conntrack_cachep)
        goto err_cachep;

    /* 初始化期望连接处理 */
    ret = nf_conntrack_expect_init();
    if (ret < 0)
        goto err_expect;

    /* 初始化辅助模块 */
    ret = nf_conntrack_helper_init();
    if (ret < 0)
        goto err_helper;

    /* 初始化超时处理 */
    ret = nf_conntrack_timeout_init();
    if (ret < 0)
        goto err_timeout;

    return 0;

err_timeout:
    nf_conntrack_helper_fini();
err_helper:
    nf_conntrack_expect_fini();
err_expect:
    kmem_cache_destroy(nf_conntrack_cachep);
err_cachep:
    nf_ct_free_hashtable(nf_conntrack_hash, nf_conntrack_htable_size);
    return ret;
}
```

### 3. Netfilter钩子注册

```c
/* net/netfilter/nf_conntrack_proto.c */
static struct nf_hook_ops ipv4_conntrack_ops[] __read_mostly = {
    {
        .hook = ipv4_conntrack_in,
        .pf = NFPROTO_IPV4,
        .hooknum = NF_INET_PRE_ROUTING,
        .priority = NF_IP_PRI_CONNTRACK,
    },
    {
        .hook = ipv4_conntrack_local,
        .pf = NFPROTO_IPV4,
        .hooknum = NF_INET_LOCAL_OUT,
        .priority = NF_IP_PRI_CONNTRACK,
    },
    {
        .hook = ipv4_confirm,
        .pf = NFPROTO_IPV4,
        .hooknum = NF_INET_POST_ROUTING,
        .priority = NF_IP_PRI_CONNTRACK_CONFIRM,
    },
    {
        .hook = ipv4_confirm,
        .pf = NFPROTO_IPV4,
        .hooknum = NF_INET_LOCAL_IN,
        .priority = NF_IP_PRI_CONNTRACK_CONFIRM,
    },
};

/* 注册钩子 */
int nf_conntrack_proto_init(void)
{
    int ret;

    ret = nf_register_net_hooks(&init_net, ipv4_conntrack_ops,
                                ARRAY_SIZE(ipv4_conntrack_ops));
    if (ret < 0)
        return ret;

    /* IPv6钩子注册（如果启用） */
#if IS_ENABLED(CONFIG_IPV6)
    ret = nf_register_net_hooks(&init_net, ipv6_conntrack_ops,
                                ARRAY_SIZE(ipv6_conntrack_ops));
    if (ret < 0)
        nf_unregister_net_hooks(&init_net, ipv4_conntrack_ops,
                               ARRAY_SIZE(ipv4_conntrack_ops));
#endif

    return ret;
}
```

## 数据包处理流程

### 1. 主处理函数 nf_conntrack_in

```c
/* net/netfilter/nf_conntrack_core.c */
unsigned int
nf_conntrack_in(struct sk_buff *skb, const struct nf_hook_state *state)
{
    enum ip_conntrack_info ctinfo;
    struct nf_conn *ct, *tmpl;
    u_int8_t protonum;
    int dataoff, ret;

    /* 已经处理过的包，直接返回 */
    if (skb->_nfct & NFCT_STATE_BIT)
        return NF_ACCEPT;

    /* 获取模板连接（如果有） */
    tmpl = nf_ct_get(skb, &ctinfo);
    if (tmpl && nf_ct_is_template(tmpl)) {
        /* 模板连接用于期望连接 */
        skb->_nfct = 0;
        nf_ct_put(tmpl);
        tmpl = NULL;
    }

    /* 提取协议号和数据偏移 */
    dataoff = get_l4proto(skb, &protonum);
    if (dataoff < 0) {
        pr_debug("not prepared to track yet or error occurred\n");
        NF_CT_STAT_INC_ATOMIC(state->net, error);
        NF_CT_STAT_INC_ATOMIC(state->net, invalid);
        return NF_ACCEPT;
    }

    /* 查找或创建连接 */
    ct = resolve_normal_ct(skb, dataoff, protonum, state);
    if (!ct) {
        /* 无法创建连接，可能是内存不足 */
        NF_CT_STAT_INC_ATOMIC(state->net, drop);
        return NF_DROP;
    }

    if (IS_ERR(ct)) {
        /* 连接无效 */
        NF_CT_STAT_INC_ATOMIC(state->net, invalid);
        return NF_ACCEPT;
    }

    /* 设置连接信息 */
    NF_CT_ASSERT(skb_nfct(skb));

    /* 调用协议特定的处理函数 */
    ret = nf_conntrack_handle_packet(ct, skb, dataoff, ctinfo, state);
    if (ret <= 0) {
        /* 协议处理失败 */
        NF_CT_STAT_INC_ATOMIC(state->net, invalid);
        if (ret == -NF_DROP)
            NF_CT_STAT_INC_ATOMIC(state->net, drop);
        
        /* 释放连接引用 */
        skb->_nfct = 0;
        nf_conntrack_put(&ct->ct_general);
        return ret == -NF_DROP ? NF_DROP : NF_ACCEPT;
    }

    /* 处理期望连接 */
    if (ctinfo == IP_CT_RELATED_REPLY) {
        ret = nf_conntrack_handle_icmp(ct, skb, dataoff, ctinfo, state);
        if (ret <= 0) {
            skb->_nfct = 0;
            nf_conntrack_put(&ct->ct_general);
            return ret == -NF_DROP ? NF_DROP : NF_ACCEPT;
        }
    }

    return NF_ACCEPT;
}
```

### 2. 连接查找/创建 - resolve_normal_ct

```c
/* net/netfilter/nf_conntrack_core.c */
static struct nf_conn *
resolve_normal_ct(struct sk_buff *skb,
                  unsigned int dataoff,
                  u_int8_t protonum,
                  const struct nf_hook_state *state)
{
    struct nf_conntrack_tuple tuple;
    struct nf_conntrack_tuple_hash *h;
    enum ip_conntrack_info ctinfo;
    struct nf_conn *ct;
    u32 hash;

    /* 从数据包提取五元组 */
    if (!nf_ct_get_tuple(skb, dataoff, state->pf, protonum, &tuple)) {
        pr_debug("Can't get tuple\n");
        return NULL;
    }

    /* 计算哈希值 */
    hash = hash_conntrack_raw(&tuple, state->net);

    /* 在哈希表中查找连接 */
    h = __nf_conntrack_find_get(state->net, &tuple, hash);

    if (!h) {
        /* 没有找到，创建新连接 */
        ct = init_conntrack(state->net, tmpl, &tuple,
                           skb, dataoff, hash);
        if (!ct)
            return NULL;
        
        if (IS_ERR(ct))
            return ct;

        ctinfo = IP_CT_NEW;
    } else {
        /* 找到现有连接 */
        ct = nf_ct_tuplehash_to_ctrack(h);
        
        /* 判断数据包方向 */
        if (NF_CT_DIRECTION(h) == IP_CT_DIR_REPLY) {
            ctinfo = IP_CT_ESTABLISHED_REPLY;
        } else {
            /* 原始方向 */
            if (test_bit(IPS_SEEN_REPLY_BIT, &ct->status)) {
                ctinfo = IP_CT_ESTABLISHED;
            } else {
                ctinfo = IP_CT_NEW;
            }
        }
    }

    /* 将连接关联到skb */
    nf_ct_set(skb, ct, ctinfo);
    return ct;
}
```

### 3. 创建新连接 - init_conntrack

```c
/* net/netfilter/nf_conntrack_core.c */
static struct nf_conn *
init_conntrack(struct net *net,
               struct nf_conn *tmpl,
               const struct nf_conntrack_tuple *tuple,
               struct sk_buff *skb,
               unsigned int dataoff,
               u32 hash)
{
    struct nf_conn *ct;
    struct nf_conntrack_tuple repl_tuple;
    struct nf_conntrack_zone tmp;
    struct nf_conntrack_l4proto *l4proto;

    /* 获取协议处理器 */
    l4proto = nf_ct_l4proto_find(tuple->dst.protonum);

    /* 计算回复方向的五元组 */
    if (!nf_ct_invert_tuple(&repl_tuple, tuple, l4proto)) {
        pr_debug("Can't invert tuple.\n");
        return NULL;
    }

    /* 分配连接对象 */
    ct = __nf_conntrack_alloc(net, zone, tuple, &repl_tuple, GFP_ATOMIC, hash);
    if (IS_ERR(ct))
        return ct;

    /* 初始化连接状态 */
    ct->status = 0;
    ct->timeout = 0;
    
    /* 调用协议特定的new函数 */
    if (l4proto->new && !l4proto->new(ct, skb, dataoff)) {
        nf_conntrack_free(ct);
        pr_debug("can't track with proto module\n");
        return NULL;
    }

    /* 设置超时时间 */
    nf_ct_timeout_ext_add(ct, &timeout, GFP_ATOMIC);

    /* 初始化计数器 */
    nf_ct_acct_ext_add(ct, GFP_ATOMIC);

    /* 初始化时间戳 */
    nf_ct_tstamp_ext_add(ct, GFP_ATOMIC);

    /* 初始化标签 */
    nf_ct_labels_ext_add(ct, GFP_ATOMIC);

    /* 设置初始超时 */
    if (!nf_ct_is_confirmed(ct))
        __nf_ct_refresh_acct(ct, 0, skb, l4proto->timeouts[0], 1);

    /* 将连接加入未确认列表 */
    spin_lock_bh(&nf_conntrack_expect_lock);
    ct->master = exp->master;
    if (exp) {
        /* 处理期望连接 */
        __set_bit(IPS_EXPECTED_BIT, &ct->status);
        ct->mark = exp->master->mark;
        ct->secmark = exp->master->secmark;
        nf_conntrack_get(&exp->master->ct_general);
        NF_CT_STAT_INC(net, expect_new);
    }
    spin_unlock_bh(&nf_conntrack_expect_lock);

    /* 加入未确认连接列表 */
    local_bh_disable();
    if (net->ct.expect_count) {
        spin_lock(&nf_conntrack_expect_lock);
        exp = nf_ct_find_expectation(net, zone, tuple);
        if (exp) {
            /* 匹配到期望连接 */
            __set_bit(IPS_EXPECTED_BIT, &ct->status);
            nf_conntrack_get(&exp->master->ct_general);
            ct->master = exp->master;
            ct->mark = exp->master->mark;
            ct->secmark = exp->master->secmark;
            NF_CT_STAT_INC(net, expect_new);
        }
        spin_unlock(&nf_conntrack_expect_lock);
    }

    /* 将连接加入未确认列表 */
    __nf_conntrack_hash_insert(ct, hash, repl_hash);
    local_bh_enable();

    return ct;
}
```

## 连接跟踪表实现

### 1. 哈希表结构

```c
/* net/netfilter/nf_conntrack_core.c */

/* 全局哈希表 */
static struct hlist_nulls_head *nf_conntrack_hash __read_mostly;
static unsigned int nf_conntrack_htable_size __read_mostly;

/* 哈希函数 */
static u32 hash_conntrack_raw(const struct nf_conntrack_tuple *tuple,
                              const struct net *net)
{
    unsigned int n;
    u32 seed;

    get_random_once(&nf_conntrack_hash_rnd, sizeof(nf_conntrack_hash_rnd));

    /* 原始方向的哈希 */
    seed = nf_conntrack_hash_rnd ^ net_hash_mix(net);
    n = (sizeof(tuple->src) + sizeof(tuple->dst.u3)) / sizeof(u32);
    
    return jhash2((u32 *)tuple, n, seed ^
                  (((__force __u16)tuple->dst.u.all << 16) |
                   tuple->dst.protonum));
}

static u32 scale_hash(u32 hash)
{
    return reciprocal_scale(hash, nf_conntrack_htable_size);
}

static u32 __hash_conntrack(const struct net *net,
                            const struct nf_conntrack_tuple *tuple,
                            unsigned int size)
{
    return reciprocal_scale(hash_conntrack_raw(tuple, net), size);
}

static u32 hash_conntrack(const struct net *net,
                         const struct nf_conntrack_tuple *tuple)
{
    return scale_hash(hash_conntrack_raw(tuple, net));
}
```

### 2. 连接插入

```c
/* net/netfilter/nf_conntrack_core.c */
int __nf_conntrack_hash_insert(struct nf_conn *ct, unsigned int hash,
                               unsigned int reply_hash)
{
    struct net *net = nf_ct_net(ct);
    struct hlist_nulls_head *list;
    struct nf_conntrack_tuple_hash *h;
    struct hlist_nulls_node *n;
    unsigned int sequence;

    /* 检查是否已经存在相同的连接 */
    local_bh_disable();
    do {
        sequence = read_seqcount_begin(&nf_conntrack_generation);
        
        /* 原始方向查找 */
        list = &nf_conntrack_hash[hash];
        hlist_nulls_for_each_entry_rcu(h, n, list, hnnode) {
            if (nf_ct_tuple_equal(&h->tuple, &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple) &&
                nf_ct_zone_equal(nf_ct_tuplehash_to_ctrack(h), zone, IP_CT_DIR_ORIGINAL)) {
                /* 已存在相同连接 */
                NF_CT_STAT_INC(net, insert_failed);
                local_bh_enable();
                return -EEXIST;
            }
        }
        
        /* 回复方向查找 */
        list = &nf_conntrack_hash[reply_hash];
        hlist_nulls_for_each_entry_rcu(h, n, list, hnnode) {
            if (nf_ct_tuple_equal(&h->tuple, &ct->tuplehash[IP_CT_DIR_REPLY].tuple) &&
                nf_ct_zone_equal(nf_ct_tuplehash_to_ctrack(h), zone, IP_CT_DIR_REPLY)) {
                /* 已存在相同连接 */
                NF_CT_STAT_INC(net, insert_failed);
                local_bh_enable();
                return -EEXIST;
            }
        }
    } while (nf_conntrack_double_lock(net, hash, reply_hash, sequence));

    /* 插入到哈希表 */
    hlist_nulls_add_head_rcu(&ct->tuplehash[IP_CT_DIR_ORIGINAL].hnnode,
                             &nf_conntrack_hash[hash]);
    hlist_nulls_add_head_rcu(&ct->tuplehash[IP_CT_DIR_REPLY].hnnode,
                             &nf_conntrack_hash[reply_hash]);

    /* 更新统计 */
    NF_CT_STAT_INC(net, insert);
    nf_conntrack_double_unlock(hash, reply_hash);
    local_bh_enable();

    return 0;
}
```

### 3. 连接查找

```c
/* net/netfilter/nf_conntrack_core.c */
static struct nf_conntrack_tuple_hash *
____nf_conntrack_find(struct net *net, const struct nf_conntrack_zone *zone,
                     const struct nf_conntrack_tuple *tuple, u32 hash)
{
    struct nf_conntrack_tuple_hash *h;
    struct hlist_nulls_head *ct_hash;
    struct hlist_nulls_node *n;
    unsigned int bucket, hsize;

begin:
    nf_conntrack_get_ht(&ct_hash, &hsize);
    bucket = reciprocal_scale(hash, hsize);

    hlist_nulls_for_each_entry_rcu(h, n, &ct_hash[bucket], hnnode) {
        struct nf_conn *ct;

        ct = nf_ct_tuplehash_to_ctrack(h);
        
        /* 比较tuple和zone */
        if (nf_ct_tuple_equal(tuple, &h->tuple) &&
            nf_ct_zone_equal(ct, zone, NF_CT_DIRECTION(h)) &&
            nf_ct_is_confirmed(ct))
            return h;
    }
    
    /*
     * 如果遍历到null节点，需要检查是否发生了resize
     * 如果bucket值不匹配，说明发生了resize，需要重试
     */
    if (get_nulls_value(n) != bucket) {
        NF_CT_STAT_INC_ATOMIC(net, search_restart);
        goto begin;
    }

    return NULL;
}

/* 带引用计数的查找 */
struct nf_conntrack_tuple_hash *
nf_conntrack_find_get(struct net *net, const struct nf_conntrack_zone *zone,
                     const struct nf_conntrack_tuple *tuple)
{
    struct nf_conntrack_tuple_hash *h;
    struct nf_conn *ct;

    rcu_read_lock();
    
    h = ____nf_conntrack_find(net, zone, tuple, 
                             hash_conntrack_raw(tuple, net));
    if (h) {
        ct = nf_ct_tuplehash_to_ctrack(h);
        if (unlikely(nf_ct_is_dying(ct) ||
                    !atomic_inc_not_zero(&ct->ct_general.use)))
            h = NULL;
        else {
            /* 再次检查tuple，防止并发修改 */
            if (unlikely(!nf_ct_tuple_equal(tuple, &h->tuple) ||
                        nf_ct_zone(ct) != zone)) {
                nf_ct_put(ct);
                goto begin;
            }
        }
    }
    rcu_read_unlock();

    return h;
}
```

## 协议状态机

### 1. TCP状态机实现

```c
/* net/netfilter/nf_conntrack_proto_tcp.c */

/* TCP连接状态 */
enum tcp_conntrack {
    TCP_CONNTRACK_NONE,
    TCP_CONNTRACK_SYN_SENT,
    TCP_CONNTRACK_SYN_RECV,
    TCP_CONNTRACK_ESTABLISHED,
    TCP_CONNTRACK_FIN_WAIT,
    TCP_CONNTRACK_CLOSE_WAIT,
    TCP_CONNTRACK_LAST_ACK,
    TCP_CONNTRACK_TIME_WAIT,
    TCP_CONNTRACK_CLOSE,
    TCP_CONNTRACK_LISTEN,
    TCP_CONNTRACK_MAX,
    TCP_CONNTRACK_IGNORE,
    TCP_CONNTRACK_RETRANS,
    TCP_CONNTRACK_UNACK,
    TCP_CONNTRACK_TIMEOUT_MAX
};

/* TCP状态转换表 */
static const u8 tcp_conntracks[2][6][TCP_CONNTRACK_MAX] = {
    {
        /* ORIGINAL方向 */
        /* sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2 */
        /*syn*/ { sSS, sSS, sIG, sIG, sIG, sIG, sIG, sSS, sSS, sS2 },
        /*synack*/ { sIV, sIV, sIG, sIG, sIG, sIG, sIG, sIV, sIV, sSR },
        /*fin*/ { sIV, sIV, sFW, sFW, sLA, sLA, sLA, sTW, sCL, sIV },
        /*ack*/ { sES, sIV, sES, sES, sCW, sCW, sTW, sTW, sCL, sIV },
        /*rst*/ { sIV, sCL, sCL, sCL, sCL, sCL, sCL, sCL, sCL, sCL },
        /*none*/ { sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV }
    },
    {
        /* REPLY方向 */
        /* sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2 */
        /*syn*/ { sIV, sS2, sIV, sIV, sIV, sIV, sIV, sIV, sIV, sS2 },
        /*synack*/ { sIV, sSR, sSR, sIG, sIG, sIG, sIG, sIG, sIG, sSR },
        /*fin*/ { sIV, sIV, sFW, sFW, sLA, sLA, sLA, sTW, sCL, sIV },
        /*ack*/ { sIV, sES, sES, sES, sCW, sCW, sTW, sTW, sCL, sES },
        /*rst*/ { sIV, sCL, sCL, sCL, sCL, sCL, sCL, sCL, sCL, sCL },
        /*none*/ { sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV }
    }
};

/* TCP数据包处理 */
static int tcp_packet(struct nf_conn *ct,
                     const struct sk_buff *skb,
                     unsigned int dataoff,
                     enum ip_conntrack_info ctinfo,
                     const struct nf_hook_state *state)
{
    struct net *net = nf_ct_net(ct);
    struct nf_tcp_net *tn = tcp_pernet(net);
    enum tcp_conntrack new_state, old_state;
    enum ip_conntrack_dir dir;
    const struct tcphdr *th;
    struct tcphdr _tcph;
    unsigned int index;
    unsigned int *timeouts;

    /* 获取TCP头 */
    th = skb_header_pointer(skb, dataoff, sizeof(_tcph), &_tcph);
    if (th == NULL)
        return -NF_ACCEPT;

    /* 获取方向 */
    dir = CTINFO2DIR(ctinfo);
    
    /* 获取当前状态 */
    old_state = ct->proto.tcp.state;
    
    /* 计算TCP标志索引 */
    index = get_conntrack_index(th);
    
    /* 查找新状态 */
    new_state = tcp_conntracks[dir][index][old_state];

    switch (new_state) {
    case TCP_CONNTRACK_SYN_SENT:
        /* SYN包已发送，等待SYN+ACK */
        if (old_state < TCP_CONNTRACK_TIME_WAIT)
            break;
        
        /* 重传的SYN */
        if (ct->proto.tcp.seen[!dir].flags & IP_CT_TCP_FLAG_CLOSE_INIT) {
            /* 对端已经关闭 */
            spin_unlock_bh(&ct->lock);
            return -NF_ACCEPT;
        }
        /* fallthrough */
    case TCP_CONNTRACK_IGNORE:
        /* 忽略的包 */
        spin_unlock_bh(&ct->lock);
        return NF_ACCEPT;
    case TCP_CONNTRACK_MAX:
        /* 无效转换 */
        spin_unlock_bh(&ct->lock);
        nf_ct_l4proto_log_invalid(skb, ct, "invalid state transition");
        return -NF_ACCEPT;
    case TCP_CONNTRACK_CLOSE:
        /* 连接关闭 */
        if (index == TCP_RST_SET
            && (ct->proto.tcp.seen[!dir].flags & IP_CT_TCP_FLAG_MAXACK_SET)
            && before(ntohl(th->seq), ct->proto.tcp.seen[!dir].td_maxack)) {
            /* 忽略旧的RST */
            spin_unlock_bh(&ct->lock);
            return NF_ACCEPT;
        }
        /* 检查是否重新打开连接 */
        if (index == TCP_SYN_SET && dir == IP_CT_DIR_ORIGINAL) {
            /* 尝试重新打开 */
            ct->proto.tcp.seen[dir].td_end =
                ct->proto.tcp.seen[dir].td_maxend = 
                    segment_seq_plus_len(ntohl(th->seq), skb->len, dataoff, th);
            ct->proto.tcp.seen[dir].td_maxwin = ntohs(th->window);
            if (ct->proto.tcp.seen[dir].td_maxwin == 0)
                ct->proto.tcp.seen[dir].td_maxwin = 1;
            ct->proto.tcp.seen[dir].flags =
                ct->proto.tcp.seen[!dir].flags = IP_CT_TCP_FLAG_SACK_PERM |
                                                 IP_CT_TCP_FLAG_BE_LIBERAL;
            ct->proto.tcp.seen[dir].td_scale =
                ct->proto.tcp.seen[!dir].td_scale = 0;
            ct->proto.tcp.last_index = TCP_SYN_SET;
            ct->proto.tcp.last_dir = dir;
            ct->proto.tcp.last_seq = ntohl(th->seq);
            ct->proto.tcp.last_end =
                segment_seq_plus_len(ntohl(th->seq), skb->len, dataoff, th);
            ct->proto.tcp.last_win = ntohs(th->window);
            
            /* 转换到SYN_SENT状态 */
            new_state = TCP_CONNTRACK_SYN_SENT;
        }
        break;
    case TCP_CONNTRACK_SYN_SENT2:
        /* 同时打开 */
        ct->proto.tcp.last_index = TCP_SYN_SET;
        ct->proto.tcp.last_dir = dir;
        ct->proto.tcp.last_seq = ntohl(th->seq);
        ct->proto.tcp.last_end =
            segment_seq_plus_len(ntohl(th->seq), skb->len, dataoff, th);
        ct->proto.tcp.last_win = ntohs(th->window);
        
        /* 回退标志 */
        ct->proto.tcp.retrans = 0;
        break;
    case TCP_CONNTRACK_SYN_RECV:
        /* SYN+ACK已收到 */
        ct->proto.tcp.last_index = index;
        ct->proto.tcp.last_dir = dir;
        ct->proto.tcp.last_seq = ntohl(th->seq);
        ct->proto.tcp.last_end =
            segment_seq_plus_len(ntohl(th->seq), skb->len, dataoff, th);
        ct->proto.tcp.last_win = ntohs(th->window);
        
        /* 重置重传计数器 */
        ct->proto.tcp.retrans = 0;
        break;
    case TCP_CONNTRACK_ESTABLISHED:
        /* 连接已建立 */
        /* 更新窗口跟踪 */
        if (!tcp_in_window(ct, &ct->proto.tcp, dir, index,
                          skb, dataoff, th)) {
            spin_unlock_bh(&ct->lock);
            return -NF_ACCEPT;
        }
        break;
    case TCP_CONNTRACK_FIN_WAIT:
        /* FIN已发送 */
        ct->proto.tcp.seen[dir].flags |= IP_CT_TCP_FLAG_CLOSE_INIT;
        /* 检查序列号 */
        if (!tcp_in_window(ct, &ct->proto.tcp, dir, index,
                          skb, dataoff, th)) {
            spin_unlock_bh(&ct->lock);
            return -NF_ACCEPT;
        }
        break;
    case TCP_CONNTRACK_CLOSE_WAIT:
        /* 等待关闭 */
        ct->proto.tcp.seen[dir].flags |= IP_CT_TCP_FLAG_CLOSE_INIT;
        /* 检查序列号 */
        if (!tcp_in_window(ct, &ct->proto.tcp, dir, index,
                          skb, dataoff, th)) {
            spin_unlock_bh(&ct->lock);
            return -NF_ACCEPT;
        }
        break;
    case TCP_CONNTRACK_LAST_ACK:
        /* 最后的ACK */
        /* 检查序列号 */
        if (!tcp_in_window(ct, &ct->proto.tcp, dir, index,
                          skb, dataoff, th)) {
            spin_unlock_bh(&ct->lock);
            return -NF_ACCEPT;
        }
        /* 设置ASSURED标志 */
        if (dir == IP_CT_DIR_REPLY && index == TCP_ACK_SET &&
            ct->proto.tcp.last_index == TCP_SYN_SET &&
            ct->proto.tcp.last_dir != dir &&
            ntohl(th->ack_seq) == ct->proto.tcp.last_end) {
            /* 三次握手完成 */
            set_bit(IPS_ASSURED_BIT, &ct->status);
            nf_conntrack_event_cache(IPCT_ASSURED, ct);
        }
        break;
    case TCP_CONNTRACK_TIME_WAIT:
        /* TIME_WAIT状态 */
        /* 检查是否可以重用 */
        if ((ct->proto.tcp.seen[dir].flags & IP_CT_TCP_FLAG_CLOSE_INIT)
            && last_index == TCP_ACK_SET && index == TCP_SYN_SET
            && (ct->proto.tcp.last_dir == !dir)) {
            /* 尝试重用TIME_WAIT连接 */
            new_state = TCP_CONNTRACK_SYN_SENT;
        }
        break;
    default:
        break;
    }

    /* 更新状态 */
    if (new_state != old_state) {
        ct->proto.tcp.state = new_state;
        
        /* 如果从SYN_RECV转到ESTABLISHED，设置ASSURED */
        if (old_state == TCP_CONNTRACK_SYN_RECV &&
            new_state == TCP_CONNTRACK_ESTABLISHED) {
            set_bit(IPS_ASSURED_BIT, &ct->status);
            nf_conntrack_event_cache(IPCT_ASSURED, ct);
        }
    }

    /* 更新超时 */
    timeouts = nf_ct_timeout_lookup(ct);
    if (!timeouts)
        timeouts = tn->timeouts;
    nf_ct_refresh_acct(ct, ctinfo, skb, timeouts[new_state]);

    spin_unlock_bh(&ct->lock);
    return NF_ACCEPT;
}
```

### 2. UDP状态处理

```c
/* net/netfilter/nf_conntrack_proto_udp.c */

/* UDP超时值 */
enum udp_conntrack {
    UDP_CT_UNREPLIED,
    UDP_CT_REPLIED,
    UDP_CT_MAX
};

static unsigned int udp_timeouts[UDP_CT_MAX] = {
    [UDP_CT_UNREPLIED] = 30*HZ,
    [UDP_CT_REPLIED] = 180*HZ,
};

/* UDP数据包处理 */
static int udp_packet(struct nf_conn *ct,
                     const struct sk_buff *skb,
                     unsigned int dataoff,
                     enum ip_conntrack_info ctinfo,
                     const struct nf_hook_state *state)
{
    unsigned int *timeouts;

    /* 如果是回复包，设置SEEN_REPLY标志 */
    if (test_bit(IPS_SEEN_REPLY_BIT, &ct->status)) {
        /* 已经看到回复，更新超时为REPLIED状态 */
        nf_ct_refresh_acct(ct, ctinfo, skb,
                          timeouts[UDP_CT_REPLIED]);
        
        /* 如果还没设置ASSURED，检查是否需要设置 */
        if (!test_bit(IPS_ASSURED_BIT, &ct->status)) {
            /* UDP流量双向后设置ASSURED */
            set_bit(IPS_ASSURED_BIT, &ct->status);
            nf_conntrack_event_cache(IPCT_ASSURED, ct);
        }
    } else {
        /* 还没看到回复，使用UNREPLIED超时 */
        nf_ct_refresh_acct(ct, ctinfo, skb,
                          timeouts[UDP_CT_UNREPLIED]);
    }
    
    return NF_ACCEPT;
}

/* 创建新的UDP连接 */
static bool udp_new(struct nf_conn *ct, const struct sk_buff *skb,
                   unsigned int dataoff)
{
    /* UDP不需要特殊初始化 */
    return true;
}
```

## 超时和垃圾回收

### 1. 超时管理

```c
/* net/netfilter/nf_conntrack_core.c */

/* 刷新连接超时 */
void __nf_ct_refresh_acct(struct nf_conn *ct,
                          enum ip_conntrack_info ctinfo,
                          const struct sk_buff *skb,
                          unsigned long extra_jiffies,
                          int do_acct)
{
    /* 只有确认的连接才能刷新 */
    if (!nf_ct_is_confirmed(ct))
        return;

    /* 如果连接正在被销毁，不刷新 */
    if (test_bit(IPS_DYING_BIT, &ct->status))
        return;

    /* 更新超时时间 */
    if (extra_jiffies) {
        unsigned long newtime = jiffies + extra_jiffies;
        
        /* 确保不会溢出 */
        if (newtime - ct->timeout.expires >= HZ)
            mod_timer_pending(&ct->timeout, newtime);
    }

    /* 更新计数器 */
    if (do_acct) {
        struct nf_conn_acct *acct;
        
        acct = nf_conn_acct_find(ct);
        if (acct) {
            struct nf_conn_counter *counter = acct->counter;
            
            atomic64_inc(&counter[CTINFO2DIR(ctinfo)].packets);
            atomic64_add(skb->len, &counter[CTINFO2DIR(ctinfo)].bytes);
        }
    }
}
```

### 2. 垃圾回收工作队列

```c
/* net/netfilter/nf_conntrack_core.c */

static struct workqueue_struct *nf_conntrack_wq;

/* GC工作函数 */
static void gc_worker(struct work_struct *work)
{
    unsigned int min_interval = max(HZ / GC_MAX_BUCKETS_DIV, 1u);
    unsigned int i, goal, buckets = 0, expired_count = 0;
    unsigned int nf_conntrack_max95 = 0;
    struct conntrack_gc_work *gc_work;
    unsigned int ratio, scanned = 0;
    unsigned long next_run;

    gc_work = container_of(work, struct conntrack_gc_work, dwork.work);

    goal = nf_conntrack_htable_size / GC_MAX_BUCKETS_DIV;
    i = gc_work->last_bucket;
    
    if (gc_work->early_drop)
        nf_conntrack_max95 = nf_conntrack_max * 95 / 100;

    do {
        struct nf_conntrack_tuple_hash *h;
        struct hlist_nulls_head *ct_hash;
        struct hlist_nulls_node *n;
        unsigned int hashsz;
        struct nf_conn *tmp;

        i++;
        rcu_read_lock();

        nf_conntrack_get_ht(&ct_hash, &hashsz);
        if (i >= hashsz)
            i = 0;

        hlist_nulls_for_each_entry_rcu(h, n, &ct_hash[i], hnnode) {
            struct net *net;

            tmp = nf_ct_tuplehash_to_ctrack(h);

            scanned++;
            
            /* 跳过未确认的连接 */
            if (!nf_ct_is_confirmed(tmp))
                continue;

            /* 跳过正在被删除的连接 */
            if (nf_ct_is_dying(tmp))
                continue;

            /* 检查是否过期 */
            if (nf_ct_is_expired(tmp)) {
                nf_ct_gc_expired(tmp);
                expired_count++;
                continue;
            }

            /* 早期丢弃检查 */
            if (nf_conntrack_max95 &&
                atomic_read(&net->ct.count) > nf_conntrack_max95) {
                /* 表快满了，尝试早期丢弃 */
                if (!test_bit(IPS_ASSURED_BIT, &tmp->status) &&
                    !nf_ct_is_dying(tmp) &&
                    atomic_inc_not_zero(&tmp->ct_general.use)) {
                    /* 删除未确保的连接 */
                    nf_ct_kill(tmp);
                    nf_ct_put(tmp);
                }
            }
        }

        rcu_read_unlock();
        cond_resched();
    } while (++buckets < goal);

    gc_work->last_bucket = i;

    /* 计算下次运行时间 */
    ratio = scanned ? expired_count * 100 / scanned : 0;
    if (ratio > GC_EVICT_RATIO) {
        /* 很多过期连接，加快GC */
        next_run = min_interval;
    } else {
        /* 计算自适应间隔 */
        unsigned int max = GC_MAX_SCAN_JIFFIES / GC_MAX_BUCKETS_DIV;
        
        next_run = min_interval + (max - min_interval) * 
                   (GC_EVICT_RATIO - ratio) / GC_EVICT_RATIO;
    }

    gc_work->next_gc_run = next_run;
    
    /* 重新调度 */
    queue_delayed_work(nf_conntrack_wq, &gc_work->dwork, next_run);
}

/* 启动GC */
static void nf_conntrack_gc_init(struct net *net)
{
    struct conntrack_gc_work *gc_work;

    gc_work = kmalloc(sizeof(*gc_work), GFP_KERNEL);
    if (!gc_work)
        return;

    gc_work->net = net;
    gc_work->last_bucket = 0;
    gc_work->early_drop = false;
    INIT_DEFERRABLE_WORK(&gc_work->dwork, gc_worker);
    
    queue_delayed_work(nf_conntrack_wq, &gc_work->dwork, HZ);
    
    net->ct.gc_work = gc_work;
}
```

### 3. 连接销毁

```c
/* net/netfilter/nf_conntrack_core.c */

/* 销毁连接 */
static void destroy_conntrack(struct nf_conntrack *nfct)
{
    struct nf_conn *ct = (struct nf_conn *)nfct;
    struct nf_conntrack_l4proto *l4proto;

    pr_debug("destroy_conntrack(%p)\n", ct);
    WARN_ON(atomic_read(&nfct->use) != 0);

    /* 调用扩展的销毁函数 */
    nf_ct_ext_destroy(ct);

    /* 调用协议特定的销毁函数 */
    l4proto = nf_ct_l4proto_find(nf_ct_protonum(ct));
    if (l4proto->destroy)
        l4proto->destroy(ct);

    /* 从主连接断开 */
    if (ct->master) {
        spin_lock_bh(&nf_conntrack_expect_lock);
        list_del(&ct->master_list);
        spin_unlock_bh(&nf_conntrack_expect_lock);
        nf_ct_put(ct->master);
    }

    /* 发送销毁事件 */
    nf_conntrack_event(IPCT_DESTROY, ct);

    /* 更新统计 */
    NF_CT_STAT_INC(net, delete);

    /* 释放内存 */
    nf_conntrack_free(ct);
}

/* 删除连接 */
bool nf_ct_delete(struct nf_conn *ct, u32 portid, int report)
{
    struct nf_conn_tstamp *tstamp;

    /* 设置DYING标志 */
    if (!nf_ct_is_dying(ct) &&
        !test_and_set_bit(IPS_DYING_BIT, &ct->status)) {
        
        /* 设置删除时间戳 */
        tstamp = nf_conn_tstamp_find(ct);
        if (tstamp && tstamp->stop == 0)
            tstamp->stop = ktime_get_real_ns();

        /* 从哈希表删除 */
        if (nf_ct_is_confirmed(ct))
            nf_ct_hash_delete(ct);

        /* 发送销毁事件 */
        nf_ct_add_to_dying_list(ct);
        nf_conntrack_event_report(IPCT_DESTROY, ct, portid, report);

        /* 删除定时器 */
        if (del_timer(&ct->timeout))
            nf_ct_put(ct);

        return true;
    }
    
    return false;
}
```

## NAT集成

### 1. NAT连接扩展

```c
/* include/net/netfilter/nf_nat.h */

/* NAT连接信息 */
struct nf_conn_nat {
    /* 原始方向的NAT hook信息 */
    struct nf_nat_hook_ops *nat_hooks[NF_NAT_MANIP_MAX];
    
    /* masquerade接口索引 */
    int masq_index;
    
    /* NAT序列调整 */
    struct nf_nat_seq seq[IP_CT_DIR_MAX];
};

/* NAT操作类型 */
enum nf_nat_manip_type {
    NF_NAT_MANIP_SRC,  /* SNAT */
    NF_NAT_MANIP_DST,  /* DNAT */
    NF_NAT_MANIP_MAX
};
```

### 2. NAT规则处理

```c
/* net/netfilter/nf_nat_core.c */

/* NAT规则应用 */
unsigned int
nf_nat_setup_info(struct nf_conn *ct,
                  const struct nf_nat_range2 *range,
                  enum nf_nat_manip_type maniptype)
{
    struct nf_conntrack_tuple curr_tuple, new_tuple;
    struct nf_conn_nat *nat;

    /* 已经做过NAT了 */
    if (nf_ct_is_confirmed(ct))
        return NF_ACCEPT;

    WARN_ON(maniptype != NF_NAT_MANIP_SRC &&
            maniptype != NF_NAT_MANIP_DST);

    /* 获取当前tuple */
    curr_tuple = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple;

    /* 计算新的tuple */
    if (!nf_nat_used_tuple(&new_tuple, ct, maniptype, range)) {
        pr_debug("Can't find free tuple.\n");
        return NF_DROP;
    }

    /* 如果没有改变，直接返回 */
    if (nf_ct_tuple_equal(&new_tuple, &curr_tuple)) {
        pr_debug("Tuple unchanged.\n");
        return NF_ACCEPT;
    }

    /* 获取NAT扩展 */
    nat = nf_ct_nat_ext_add(ct);
    if (!nat)
        return NF_DROP;

    /* 设置NAT标志 */
    if (maniptype == NF_NAT_MANIP_SRC) {
        ct->status |= IPS_SRC_NAT;
    } else {
        ct->status |= IPS_DST_NAT;
    }

    /* 如果是masquerade，记录接口 */
    if (range->flags & NF_NAT_RANGE_MASK)
        nat->masq_index = range->masq_index;

    /* 更新回复方向的tuple */
    ct->tuplehash[IP_CT_DIR_REPLY].tuple = new_tuple;

    /* 调整期望连接 */
    if (ct->master)
        nf_nat_follow_master(ct);

    return NF_ACCEPT;
}

/* NAT数据包修改 */
static unsigned int nf_nat_packet(struct nf_conn *ct,
                                  enum ip_conntrack_info ctinfo,
                                  unsigned int hooknum,
                                  struct sk_buff *skb)
{
    enum nf_nat_manip_type maniptype = HOOK2MANIP(hooknum);
    enum ip_conntrack_dir dir = CTINFO2DIR(ctinfo);
    unsigned int verdict = NF_ACCEPT;

    /* 检查是否需要NAT */
    if (!nf_nat_initialized(ct, maniptype)) {
        /* 初始化NAT */
        verdict = nf_nat_rule_find(skb, ct, hooknum);
        if (verdict != NF_ACCEPT)
            return verdict;
    }

    /* 执行NAT转换 */
    return nf_nat_manip_pkt(skb, ct, maniptype, dir);
}

/* 修改数据包 */
static int nf_nat_manip_pkt(struct sk_buff *skb,
                            struct nf_conn *ct,
                            enum nf_nat_manip_type mtype,
                            enum ip_conntrack_dir dir)
{
    struct iphdr *iph;
    unsigned int hdroff;
    struct nf_conntrack_tuple target;

    /* 获取目标tuple */
    if (dir == IP_CT_DIR_ORIGINAL) {
        /* 原始方向，使用回复tuple */
        target = ct->tuplehash[IP_CT_DIR_REPLY].tuple;
    } else {
        /* 回复方向，使用原始tuple */
        target = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple;
    }

    /* 修改IP头 */
    if (!skb_make_writable(skb, hdroff + sizeof(*iph)))
        return 0;

    iph = (void *)skb->data + hdroff;

    if (maniptype == NF_NAT_MANIP_SRC) {
        /* SNAT：修改源地址 */
        csum_replace4(&iph->check, iph->saddr, target.src.u3.ip);
        iph->saddr = target.src.u3.ip;
    } else {
        /* DNAT：修改目的地址 */
        csum_replace4(&iph->check, iph->daddr, target.dst.u3.ip);
        iph->daddr = target.dst.u3.ip;
    }

    /* 调用协议特定的NAT处理 */
    return nf_nat_proto_manip_pkt(skb, ct, mtype, dir);
}
```

## 性能优化

### 1. Per-CPU优化

```c
/* net/netfilter/nf_conntrack_core.c */

/* Per-CPU统计 */
struct ct_pcpu {
    spinlock_t lock;
    struct hlist_nulls_head unconfirmed;  /* 未确认连接列表 */
    struct hlist_nulls_head dying;        /* 正在销毁的连接 */
};

static DEFINE_PER_CPU(struct ct_pcpu, nf_conntrack_pcpu);

/* Per-CPU列表操作 */
static void nf_ct_add_to_unconfirmed_list(struct nf_conn *ct)
{
    struct ct_pcpu *pcpu;

    /* 禁用抢占，获取当前CPU的列表 */
    pcpu = this_cpu_ptr(&nf_conntrack_pcpu);
    
    spin_lock(&pcpu->lock);
    hlist_nulls_add_head(&ct->tuplehash[IP_CT_DIR_ORIGINAL].hnnode,
                        &pcpu->unconfirmed);
    spin_unlock(&pcpu->lock);
}

/* 确认连接（从per-cpu列表移到全局哈希表） */
int __nf_conntrack_confirm(struct sk_buff *skb)
{
    struct nf_conn *ct;
    enum ip_conntrack_info ctinfo;
    struct nf_conn_help *help;
    struct hlist_nulls_node *n;
    struct nf_conntrack_tuple_hash *h;
    struct ct_pcpu *pcpu;
    unsigned int hash, reply_hash;
    int ret = NF_DROP;

    ct = nf_ct_get(skb, &ctinfo);

    /* 已经确认过了 */
    if (nf_ct_is_confirmed(ct))
        return NF_ACCEPT;

    /* 计算哈希值 */
    hash = hash_conntrack(net, &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple);
    reply_hash = hash_conntrack(net, &ct->tuplehash[IP_CT_DIR_REPLY].tuple);

    /* 从per-cpu列表删除 */
    pcpu = this_cpu_ptr(&nf_conntrack_pcpu);
    spin_lock(&pcpu->lock);
    
    /* 再次检查是否已确认 */
    if (nf_ct_is_confirmed(ct)) {
        spin_unlock(&pcpu->lock);
        return NF_ACCEPT;
    }

    /* 从未确认列表删除 */
    hlist_nulls_del_rcu(&ct->tuplehash[IP_CT_DIR_ORIGINAL].hnnode);
    
    spin_unlock(&pcpu->lock);

    /* 插入到全局哈希表 */
    ret = __nf_conntrack_hash_insert(ct, hash, reply_hash);
    if (ret != 0)
        goto out;

    /* 设置确认标志 */
    set_bit(IPS_CONFIRMED_BIT, &ct->status);

    /* 辅助器处理 */
    help = nfct_help(ct);
    if (help && help->helper)
        nf_conntrack_event_cache(IPCT_HELPER, ct);

    /* 发送NEW事件 */
    nf_conntrack_event_cache(IPCT_NEW, ct);
    
    return NF_ACCEPT;

out:
    nf_ct_add_to_dying_list(ct);
    NF_CT_STAT_INC(net, insert_failed);
    return ret;
}
```

### 2. RCU优化

```c
/* net/netfilter/nf_conntrack_core.c */

/* RCU保护的查找 */
static struct nf_conntrack_tuple_hash *
____nf_conntrack_find(struct net *net,
                     const struct nf_conntrack_zone *zone,
                     const struct nf_conntrack_tuple *tuple,
                     u32 hash)
{
    struct nf_conntrack_tuple_hash *h;
    struct hlist_nulls_head *ct_hash;
    struct hlist_nulls_node *n;
    unsigned int bucket, hsize;

begin:
    /* RCU读锁已经持有 */
    nf_conntrack_get_ht(&ct_hash, &hsize);
    bucket = reciprocal_scale(hash, hsize);

    /* RCU遍历 */
    hlist_nulls_for_each_entry_rcu(h, n, &ct_hash[bucket], hnnode) {
        struct nf_conn *ct;

        ct = nf_ct_tuplehash_to_ctrack(h);
        
        if (nf_ct_key_equal(h, tuple, zone, net)) {
            /* 找到匹配的连接 */
            NF_CT_STAT_INC_ATOMIC(net, found);
            return h;
        }
        NF_CT_STAT_INC_ATOMIC(net, searched);
    }

    /*
     * 如果走到nulls节点，检查是否因为resize导致
     * 如果是，需要重新开始查找
     */
    if (get_nulls_value(n) != bucket) {
        NF_CT_STAT_INC_ATOMIC(net, search_restart);
        goto begin;
    }

    return NULL;
}

/* RCU保护的哈希表resize */
int nf_conntrack_hash_resize(unsigned int hashsize)
{
    int i, bucket;
    unsigned int old_size;
    struct hlist_nulls_head *hash, *old_hash;
    struct nf_conntrack_tuple_hash *h;
    struct nf_conn *ct;

    if (!hashsize)
        return -EINVAL;

    /* 分配新哈希表 */
    hash = nf_ct_alloc_hashtable(&hashsize, 1);
    if (!hash)
        return -ENOMEM;

    /* 同步RCU，确保没有读者访问旧表 */
    synchronize_rcu();

    /* 锁定写操作 */
    nf_conntrack_all_lock();
    
    /* 保存旧表信息 */
    old_size = nf_conntrack_htable_size;
    old_hash = nf_conntrack_hash;

    /* 迁移所有连接到新表 */
    for (i = 0; i < old_size; i++) {
        while (!hlist_nulls_empty(&old_hash[i])) {
            h = hlist_nulls_entry(old_hash[i].first,
                                 struct nf_conntrack_tuple_hash, hnnode);
            ct = nf_ct_tuplehash_to_ctrack(h);
            
            /* 从旧表删除 */
            hlist_nulls_del_rcu(&h->hnnode);
            
            /* 计算在新表中的位置 */
            bucket = __hash_conntrack(nf_ct_net(ct),
                                     &h->tuple, hashsize);
            
            /* 插入到新表 */
            hlist_nulls_add_head_rcu(&h->hnnode, &hash[bucket]);
        }
    }

    /* 更新全局指针 */
    nf_conntrack_htable_size = hashsize;
    nf_conntrack_hash = hash;

    nf_conntrack_all_unlock();

    /* 等待RCU宽限期 */
    synchronize_rcu();

    /* 释放旧表 */
    nf_ct_free_hashtable(old_hash, old_size);
    
    return 0;
}
```

### 3. 批处理优化

```c
/* net/netfilter/nf_conntrack_core.c */

/* 批量确认连接 */
static void nf_ct_confirm_batch(struct list_head *head)
{
    struct nf_conn *ct, *tmp;
    
    /* 批量处理确认 */
    list_for_each_entry_safe(ct, tmp, head, confirm_list) {
        struct nf_conn_help *help;
        
        /* 设置确认标志 */
        set_bit(IPS_CONFIRMED_BIT, &ct->status);
        
        /* 从列表删除 */
        list_del(&ct->confirm_list);
        
        /* 插入到哈希表 */
        __nf_conntrack_hash_insert(ct, 
                                   ct->hash,
                                   ct->reply_hash);
        
        /* 发送事件 */
        help = nfct_help(ct);
        if (help && help->helper)
            nf_conntrack_event_cache(IPCT_HELPER, ct);
        
        nf_conntrack_event_cache(IPCT_NEW, ct);
    }
}

/* 批量超时处理 */
static void nf_ct_gc_batch(struct list_head *head)
{
    struct nf_conn *ct, *tmp;
    
    list_for_each_entry_safe(ct, tmp, head, gc_list) {
        /* 从列表删除 */
        list_del(&ct->gc_list);
        
        /* 从哈希表删除 */
        nf_ct_hash_delete(ct);
        
        /* 销毁连接 */
        nf_ct_put(ct);
    }
}
```

## 总结

Linux Conntrack模块是一个复杂而高效的连接跟踪系统，其主要特点包括：

### 架构特点
1. **模块化设计**：支持多种协议，易于扩展
2. **分层架构**：L3/L4协议处理分离
3. **事件驱动**：通过Netfilter钩子处理数据包

### 性能优化
1. **Per-CPU数据结构**：减少锁竞争
2. **RCU机制**：无锁读操作
3. **批处理**：减少系统调用开销
4. **自适应GC**：根据负载调整回收频率
5. **哈希表动态调整**：支持在线resize

### 关键机制
1. **双向连接跟踪**：同时跟踪原始和回复方向
2. **状态机管理**：精确跟踪连接状态
3. **超时管理**：自动清理过期连接
4. **NAT集成**：无缝支持网络地址转换
5. **期望连接**：支持复杂协议（如FTP）

### 使用场景
1. **状态防火墙**：基于连接状态的包过滤
2. **NAT/Masquerade**：网络地址转换
3. **负载均衡**：连接分发
4. **流量统计**：连接级别的流量监控

通过深入理解Conntrack的实现原理，可以更好地：
- 优化防火墙规则
- 调整系统参数以提高性能
- 开发基于Netfilter的网络应用
- 排查网络连接相关问题

Conntrack模块的设计充分考虑了性能和可扩展性，是Linux网络栈的重要组成部分。