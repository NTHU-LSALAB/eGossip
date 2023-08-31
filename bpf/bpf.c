// +build ignore

#include <linux/bpf.h>
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
} targets_map SEC(".maps");




// static inline int message_type_checker(char *payload, void *data_end)
// {
//     return 0;
// }

static inline __u16 compute_ip_checksum(struct iphdr *ip)
{
	__u32 csum = 0;
	__u16 *next_ip_u16 = (__u16 *)ip;

	ip->check = 0;
	// #pragma clang loop unroll(full)
	for (int i = 0; i < (sizeof(*ip) >> 1); i++)
	{
		csum += *next_ip_u16++;
	}

	return ~((csum & 0xffff) + (csum >> 16));
}

SEC("classifier")
int fastbroadcast(struct __sk_buff *skb)
{
#ifdef DEBUG
	bpf_printk("[fastbroad_prog] ingress packet received\n");
#endif
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

	if (payload + 5 >= data_end)
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

	if (payload[1] != 'B' && payload[2] != 'A')
	{
		// Not a broadcast packet
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

	// #ifdef DEBUG
	//     bpf_printk("[fastbroad_prog] ingress packet accepted, magic bit: %c\n Dump tgt_list data: \n max_count: %d \nIP[0]:%d Port[0]:%d MAX[0]:%s\n",
	//                     type_str[0],
	//                     tgt_list->max_count,
	//                     tgt_list->target_list[0].ip,
	//                     tgt_list->target_list[0].port,
	//                     tgt_list->target_list[0].mac);
	// #endif

	char nxt;
	int curr = payload[0];
	if (curr < tgt_list->max_count)
	{
		nxt = payload[0] + 1;
		payload[0] = nxt;
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

	if (payload + 5 >= data_end)
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
	bpf_printk("[fastbroad_prog] egress packet: num:%d, typ_str[0]: %d, %c, max_count:%d\n", num, payload[0], payload[0], tgt_list->max_count);
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

// Basic license just for compiling the object code
char __license[] SEC("license") = "GPL";