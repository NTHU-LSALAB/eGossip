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

// #define DEBUG
#define DEBUG_SEND
// #define DEBUG_1
// #define DEBUG_XDP

#define MAX_TARGETS 64
#define MAX_SIZE 99
#define MTU 1500
#define MAX_PAYLOAD 1000
#define MAX_INT64_LEN 20
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
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, int64_t);
	__uint(max_entries, 1);
} metadata_map SEC(".maps"); // map for metadata

static __always_inline __u16 compute_ip_checksum(struct iphdr *ip)
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

static __always_inline int type_checker(const char *payload)
{
	// Search for the key in the payload
	if ( payload[0] != '{' ){
		return -1;
	} else {
		if ( payload[2] == 'T' && payload[5] == 'e' && payload[7] == ':') {
			if (payload[8] == '0'){
				return 0;
			} else if (payload[7] == '1'){
				return 1;
			} else if (payload[7] >= '1'){
				return 2;
			}
		}
	}
	return -1;
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
		return TC_ACT_OK;
	}

	struct iphdr *ip = data + l3_off;
	if (ip->protocol != IPPROTO_UDP)
	{
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

	if (type_checker(payload) != 0)
	{
		// Valid packet but not broadcast packet
#ifdef DEBUG
		bpf_printk("[fastbroad_prog] is not a broadcast packet\n");
#endif
		return TC_ACT_OK;
	}

	__u32 ip_src = ip->saddr;
	struct targets *tgt_list = bpf_map_lookup_elem(&targets_map, &ip_src);
	if (!tgt_list)
	{
		//bpf_printk("[fastbroad_prog] No target list found for %u\n", ip_src);
		//bpf_printk("[fastbroad_prog] dest ip %u\n", ip->daddr);
		return TC_ACT_OK;
	}

	char nxt;
	u16 curr = payload[18];
#ifdef DEBUG_SEND
	bpf_printk("Count: %c%c%c%c\n", payload[16], payload[17], payload[18], payload[19]);
#endif
	if (curr < tgt_list->max_count)
	{
		nxt = payload[18] + 1;
		payload[18] = nxt;
#ifdef DEBUG_SEND
		__u16 udp_total_len = ntohs(udp->len);
		__u16 udp_payload_len = udp_total_len - sizeof(struct udphdr);
		bpf_printk("[fastbroad_prog] clone packet, payload size: %d, max_count: %d\n", udp_payload_len, tgt_list->max_count);

		int res = bpf_clone_redirect(skb, skb->ifindex, 0);
#else
		bpf_clone_redirect(skb, skb->ifindex, 0);
#endif
	}
	else
	{
		//bpf_printk("[fastbroad_prog] no clone curr >= tgt_list->max_count, %d\n", curr);
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
	bpf_printk("[fastbroad_prog] egress packet: num:%d, payload[18]: %d, %c, max_count:%d\n", num, payload[18], payload[18], tgt_list->max_count);
#endif

	if (num < 0 || num >= MAX_TARGETS)
	{
#ifdef DEBUG
		bpf_printk("[fastbroad_prog] TC_ACT_SHOT (num<0 or num>=MAX_TARGETS)\n");
#endif
		return TC_ACT_SHOT;
	}

	if(udp->dest == htons(tgt_list->target_list[num].port) && ip->daddr == tgt_list->target_list[num].ip){
		udp->dest == htons(111111);
#ifdef DEBUG_SEND
		bpf_printk("same port or ip\n");
#endif
		return TC_ACT_OK;
	}

	udp->dest = htons(tgt_list->target_list[num].port);
	udp->check = 0;
	ip->daddr = tgt_list->target_list[num].ip;
	ip->check = compute_ip_checksum(ip);
	// memcpy(eth->h_dest, tgt_list->target_list[num].mac, ETH_ALEN);

#ifdef DEBUG_SEND
	bpf_printk("[fastbroad_prog] egress packet acceptd, info: port:%d, ip:%d, mac:%s\n", udp->dest, ip->daddr, eth->h_dest);
#endif

	return TC_ACT_OK;
}

SEC("xdp")
int fastdrop(struct xdp_md *ctx)
{
	const int l3_off = ETH_HLEN;					  // IP header offset
	const int l4_off = l3_off + sizeof(struct iphdr); // L4 header offset

	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	if (data_end < data + l4_off)
		return XDP_PASS;

	struct ethhdr *eth = data;
	if (eth->h_proto != htons(ETH_P_IP))
	{
		return XDP_PASS;
	}

	if (eth->h_proto != htons(ETH_P_IP))
	{
		return XDP_PASS; // Non-IP packet, allow it
	}

	struct iphdr *ip = (struct iphdr *)(eth + 1);
	if (ip->protocol != IPPROTO_UDP)
	{
		return XDP_PASS; // Non-UDP packet, allow it
	}

	struct udphdr *udp = (struct udphdr *)(ip + 1);
	if (udp + 10 > data_end)
	{
		return XDP_DROP; // Malformed packet
	}

	unsigned char *payload = (unsigned char *)(udp + 1);
	if (payload + 1 > data_end)
	{
		return XDP_DROP; // Malformed packet
	}

	// Packet too small to contain the key
	if (type_checker(payload) <= 1)
	{
		return XDP_PASS;
	}

	if(payload + 40 > data_end){
		return XDP_DROP;
	}
	__u8 *cursor = payload + 40;
	if (cursor + 2 > data_end){ 
		return XDP_DROP;
	}
	if (*cursor != ':')
	{
		return XDP_DROP; // no start 
	}
	cursor++;

	int64_t value = 0;
#pragma clang loop unroll(full)
	for (int i = 0; i < MAX_INT64_LEN; i++) {
		if (cursor + (i + 1) > data_end){
			return XDP_DROP;			
		}

		if (*cursor < '0' || *cursor > '9'){
			return XDP_DROP; // not a number
		}

		if(*(cursor+i) == ','){
			break;
		}
		//bpf_printk("[fastdrop_prog]i: %d cursor: %c\n", i, *(cursor+i));
		value = value * 10 + (*(cursor+i) - '0');
	}

	// Search for the key in the payload
	__u32 key = 0;
	int64_t *update_time = bpf_map_lookup_elem(&metadata_map, &key);
	if (!update_time)
	{
		return XDP_PASS;
	}

	if (*update_time == value)
	{
#ifdef DEBUG_XDP
		bpf_printk("[fastdrop_prog] update_time == value drop\n");
#endif
		return XDP_DROP;
	}

	return XDP_PASS;
}

// Basic license just for compiling the object code
char __license[] SEC("license") = "GPL";