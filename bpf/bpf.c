// +build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
// #include <linux/in.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <arpa/inet.h>
#include <string.h>

#define DEBUG
#define DEBUG_1

#define MAX_TARGETS 64
#define MAX_SIZE 99
#define MTU 1500
// static volatile unsigned const short PORT;

// Ensure map references are available.
/*
				These will be initiated from go and
				referenced in the end BPF opcodes by file descriptor
*/

typedef __u64 u64;
typedef __u32 u32;
typedef __u16 u16;

struct target_info
{
	__u32 ip;
	__u16 port;
	char mac[ETH_ALEN];
};

struct targets
{
	struct target_info target_list[MAX_TARGETS];
	__u16 max_count;
};

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, struct targets);
	__uint(max_entries, 1);
} targets_map SEC(".maps"); // map for targets

struct 
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
} metadata_map SEC(".maps"); // map for metadata


static inline __u16 compute_ip_checksum(struct iphdr *ip)
{
	__u32 csum = 0;
	__u16 *next_ip_u16 = (__u16 *)ip;

	ip->check = 0;
#pragma clang loop unroll(full)
	for (int i = 0; i < (sizeof(*ip) >> 1); i++)
	{
		csum += *next_ip_u16++;
	}

	return ~((csum & 0xffff) + (csum >> 16));
}

int is_broadcast_packet(const char *payload)
{
	// Search for the key in the payload
	if ( payload[0] != '{' ){
		return 0;
	} else {
		if ( payload[2] == 'I' && payload[8] == 'd' && payload[14] == ':' && payload[15] == '1') {
			return 1;
		}
	}
	return 0;
}

static __always_inline int parse_ip_src_addr(struct xdp_md *ctx, __u32 *ip_src_addr)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	// First, parse the ethernet header.
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
	{
		return 0;
	}

	if (eth->h_proto != bpf_htons(ETH_P_IP))
	{
		// The protocol is not IPv4, so we can't parse an IPv4 source address.
		return 0;
	}

	// Then parse the IP header.
	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
	{
		return 0;
	}

	// Return the source IP address in network byte order.
	*ip_src_addr = (__u32)(ip->saddr);
	return 1;
}

SEC("classifier")
int fastbroadcast(struct __sk_buff *skb)
{
	const int l3_off = ETH_HLEN;					  // IP header offset
	const int l4_off = l3_off + sizeof(struct iphdr); // L4 header offset

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	if (data_end < data + l4_off)
		return TC_ACT_OK;

	struct ethhdr *eth = data;
	if (eth->h_proto != htons(ETH_P_IP))
	{
#ifdef DEBUG
		bpf_printk("[fastbroad_prog] not ip packet\n");
#endif
		return TC_ACT_OK;
	}

	struct iphdr *ip = data + l3_off;
	if (ip->protocol != IPPROTO_UDP)
	{
#ifdef DEBUG
		bpf_printk("[fastbroad_prog] not udp packet\n");
#endif
		return TC_ACT_OK;
	}

	struct udphdr *udp = data + l4_off;
	char *payload = data + l4_off + sizeof(struct udphdr);
	if (payload + sizeof(__u64) > data_end)
	{
#ifdef DEBUG
		bpf_printk("[fastbroad_prog] payload + sizeof(__u64) > data_end\n");
#endif
		return TC_ACT_OK;
	}

	if (payload + 30 >= data_end)
	{
#ifdef DEBUG
		bpf_printk("[fastbroad_prog] type_str + 5 >= data_end\n");
#endif
		return TC_ACT_OK;
	}

	if (payload > data_end)
	{
#ifdef DEBUG
		bpf_printk("[fastbroad_prog] payload > data_end\n");
#endif
		return TC_ACT_OK;
	}

	if (is_broadcast_packet(payload) == 0)
	{
		// Valid packet but not broadcast packet
#ifdef DEBUG_1
		bpf_printk("[fastbroad_prog] is not a broadcast packet\n");
#endif
		return TC_ACT_OK;
	}

	__u32 ip_src = ip->saddr;
	struct targets *tgt_list = bpf_map_lookup_elem(&targets_map, &ip_src);
	if (!tgt_list)
	{
		bpf_printk("[fastbroad_prog] No target list found for %u\n", ip_src);
		bpf_printk("[fastbroad_prog] dest ip %u\n", ip->daddr);
		return TC_ACT_OK;
	}

	char nxt;
	u16 curr = payload[25];
	bpf_printk("count: %d\n", payload[25]);
	if (curr < tgt_list->max_count)
	{
		nxt = payload[25] + 1;
		payload[25] = nxt;
#ifdef DEBUG
		__u16 udp_total_len = ntohs(udp->len);
		__u16 udp_payload_len = udp_total_len - sizeof(struct udphdr);
		bpf_printk("[fastbroad_prog] clone packet, payload size %d, %d\n", udp_payload_len, tgt_list->max_count);

		int res = bpf_clone_redirect(skb, skb->ifindex, 0);
#else
		bpf_clone_redirect(skb, skb->ifindex, 0);
#endif
	}
	else
	{
		bpf_printk("[fastbroad_prog] no clone curr >= tgt_list->max_count, %d\n", curr);
	}

	// keep handle packet data
	data_end = (void *)(long)skb->data_end;
	data = (void *)(long)skb->data;
	eth = data;
	ip = data + l3_off;
	udp = data + l4_off;
	payload = data + l4_off + sizeof(struct udphdr);

	if (payload + sizeof(__u64) > data_end)
		return TC_ACT_OK;

	if (payload + 30 >= data_end)
	{
#ifdef DEBUG
		bpf_printk("[fastbroad_prog] TC_ACT_SHOT (type_str + 5 >= data_end)\n");
#endif
		return TC_ACT_SHOT;
	}

	if (payload > data_end)
	{
#ifdef DEBUG
		bpf_printk("[fastbroad_prog] TC_ACT_SHOT (payload > data_end)\n");
#endif
		return TC_ACT_SHOT;
	}

	int num = tgt_list->max_count - curr;

#ifdef DEBUG
	bpf_printk("[fastbroad_prog] egress packet: num:%d, payload[25]: %d, %c, max_count:%d\n", num, payload[25], payload[25], tgt_list->max_count);
#endif

	if (num < 0 || num >= MAX_TARGETS)
	{
#ifdef DEBUG
		bpf_printk("[fastbroad_prog] TC_ACT_SHOT (num<0 or num>=MAX_TARGETS)\n");
#endif
		return TC_ACT_SHOT;
	}

	udp->dest = htons(tgt_list->target_list[num].port);
	udp->check = 0;
	ip->daddr = tgt_list->target_list[num].ip;
	ip->check = compute_ip_checksum(ip);
	// memcpy(eth->h_dest, tgt_list->target_list[num].mac, ETH_ALEN);

#ifdef DEBUG
	bpf_printk("[fastbroad_prog] egress packet acceptd, info: port:%d, ip:%d, mac:%s\n", udp->dest, ip->daddr, eth->h_dest);
#endif

	return TC_ACT_OK;
}

SEC("xdp")
int fastdrop(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	// First, parse the ethernet header.
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
	{
		return XDP_PASS;
	}

	if (eth->h_proto != bpf_htons(ETH_P_IP))
	{
		// The protocol is not IPv4, so we can't parse an IPv4 source address.
		return XDP_PASS;
	}

	// Then parse the IP header.
	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
	{
		return XDP_PASS;
	}

	// Return the source IP address in network byte order.
	// *ip_src_addr = (__u32)(ip->saddr);
	__u32 ip_src_addr = (__u32)(ip->saddr);
	return XDP_PASS;

}

// Basic license just for compiling the object code
char __license[] SEC("license") = "GPL";