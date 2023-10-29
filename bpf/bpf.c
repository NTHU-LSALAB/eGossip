// +build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <arpa/inet.h>
#include <string.h>


/* Debug flag*/
//#define DEBUG_B1
#define DEBUG_SEND

/* Contorl definition */
#define MAX_TARGETS 10
#define MAX_SIZE 200
#define MTU 1500
#define MAX_PAYLOAD 1000
#define MAX_INT64_LEN 20

typedef __u64 u64;
typedef __u32 u32;
typedef __u16 u16;

/* Node info struct for store node information. */
struct node_info {
	__u32 ip;
	__u16 port;
	char mac[ETH_ALEN];
};

/* Broadcast target struct, including node info and current count. */
struct targets {
	struct node_info target_list[MAX_TARGETS];
	__u16 max_count;
};

/* Metadat struct for store latest metadata. */
struct metadata {
	char metadata[MAX_SIZE];
	int64_t update_time;
};

/* Message struct for commucation between kerenlspace and userspace. */
struct message {
	char type;
	struct node_info node;
};

/* BPF_MAP_TYPE_HASH for nodelist */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u16);
	__type(value, struct targets);
	__uint(max_entries, 1024);
} nodelist_map SEC(".maps"); 

/* BPF_MAP_TYPE_HASH for broadcast target */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u16);
	__type(value, struct targets);
	__uint(max_entries, 1024);
} targets_map SEC(".maps"); // map for targets

/* BPF_MAP_TYPE_HASH for metadata store */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u16);
	__type(value, struct metadata);
	__uint(max_entries, 1);
} metadata_map SEC(".maps"); // map for metadata

/* Compute ip checksum for cloned packet before TC_ACT_OK. */
static __always_inline __u16 compute_ip_checksum(struct iphdr *ip)
{
	__u32 csum = 0;
	__u16 *next_ip_u16 = (__u16 *)ip;

	ip->check = 0;
#pragma clang loop unroll(full)
	for (int i = 0; i < (sizeof(*ip) >> 1); i++) {
		csum += *next_ip_u16++;
	}

	return ~((csum & 0xffff) + (csum >> 16));
}

/* Type handler for checking packet type. */
static __always_inline int type_checker(const char *payload)
{
	// Search for the key in the payload
	if ( payload[0] != '{' ) {
		return -1;
	} else {
		if ( payload[2] == 'T' && payload[5] == 'e' && payload[7] == ':') {
			if (payload[8] == '1'){
				return 1;
			} else if (payload[8] == '2'){
				return 2;
			} else if (payload[8] == '3'){
				return 3;
			}
		}
	}
	return -1;
}

/* Map key handler for checking broadcast target map key. */
static __always_inline __u16 mapkey_checker(const char *payload)
{
	if (payload[21] != 'M' || payload[23] != 'p' || payload[26] != 'y') {
		return 1;
	}

	// Extract the four digits from the payload
	int hundreds = payload[29] - '0';
	int tens = payload[30] - '0';
	int ones = payload[31] - '0';

	// Convert to an actual number
	return hundreds * 100 + tens * 10 + ones;
}

/* Debug function for convet u32 type ip variable into readable number. */
static inline void ip_to_bytes(__u32 ip_addr, __u8 *byte1, __u8 *byte2, __u8 *byte3, __u8 *byte4)
{
	*byte1 = (ip_addr & 0xFF000000) >> 24;
	*byte2 = (ip_addr & 0x00FF0000) >> 16;
	*byte3 = (ip_addr & 0x0000FF00) >> 8;
	*byte4 = ip_addr & 0x000000FF;
}

/* ebpf TC Hook for Fastbroadcast. */
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
	if (eth->h_proto != htons(ETH_P_IP)) {
		return TC_ACT_OK;
	}

	struct iphdr *ip = data + l3_off;
	if (ip->protocol != IPPROTO_UDP) {
		return TC_ACT_OK;
	}

	struct udphdr *udp = data + l4_off;
	char *payload = data + l4_off + sizeof(struct udphdr);
	if (payload + sizeof(__u64) > data_end) {
		return TC_ACT_OK;
	}

	if (payload + 40 >= data_end) {
		return TC_ACT_OK;
	}

	if (payload > data_end) { 
		return TC_ACT_OK;
	}

	if (type_checker(payload) != 1) {
		return TC_ACT_OK; // Valid packet but not broadcast packet, allow it
	}

	__u16 key = mapkey_checker(payload);
	if(key == 1) {
#ifdef DEBUG_B1
		if (payload+50 > data_end) return TC_ACT_OK;
		bpf_printk("[fastbroad_prog] key == 1, type=%d", type_checker(payload));
		for (int i = 21; i<32; i++){
			bpf_printk("%c", payload[i]);
		}
#endif
		return TC_ACT_OK;
	}
	struct targets *tgt_list = bpf_map_lookup_elem(&targets_map, &key);
	if (!tgt_list) {
#ifdef DEBUG_SEND
		__u8 b1, b2, b3, b4;
		__u8 c1, c2, c3, c4;
		ip_to_bytes(ip->saddr, &b1, &b2, &b3, &b4);
		ip_to_bytes(ip->daddr, &c1, &c2, &c3, &c4);
		bpf_printk("[fastbroad_prog] No target list found before clone packet key=%d, from %u.%u.%u.%u ->  %u.%u.%u.%u \n", key, b3, b2, b1, c4, c3, c2, c1);
#endif
		return TC_ACT_OK;
	}


	/* Clone packet if curr < max_count */
	char nxt;
	u16 curr = payload[18];
	char curr_char = payload[18];

	if (curr < tgt_list->max_count) {
		nxt = payload[18] + 1;
		payload[18] = nxt;
#ifdef DEBUG_SEND
		//__u16 udp_total_len = ntohs(udp->len);
		//__u16 udp_payload_len = udp_total_len - sizeof(struct udphdr);
		//bpf_printk("[fastbroad_prog] clone packet, payload size: %d, max_count: %d\n", udp_payload_len, tgt_list->max_count);

		int res = bpf_clone_redirect(skb, skb->ifindex, 0);
		bpf_printk("[fastbroad_prog] clone packet, res: %d, curr: %d, max: %d\n", res, curr - '0', tgt_list->max_count - '0');
#else
		bpf_clone_redirect(skb, skb->ifindex, 0);
#endif
	}


	/* bpf_redirect may change the content of skb, so we need to re-initialize */
	data_end = (void *)(long)skb->data_end;
	data = (void *)(long)skb->data;
	eth = data;
	ip = data + l3_off;
	udp = data + l4_off;
	payload = data + l4_off + sizeof(struct udphdr);

	if (payload + sizeof(__u64) > data_end)
		return TC_ACT_OK;

	if (payload + 45 >= data_end) {
		return TC_ACT_SHOT;
	}

	if (payload > data_end) {
		return TC_ACT_SHOT;
	}

	if (tgt_list->max_count - '0' < tgt_list->max_count - curr) {
#ifdef DEBUG_SEND
		bpf_printk("[fastbroad_prog] TC_ACT_SHOT (Counting error)\n");
#endif
		return TC_ACT_SHOT;
	}

	int num = (tgt_list->max_count - '0') - (tgt_list->max_count - curr);

#ifdef DEBUG_SEND
	bpf_printk("[fastbroad_prog] egress packet: num:%d, curr: %d, max_count:%d\n", num, payload[18] - '0', tgt_list->max_count - '0');
#endif

	if (num < 0 || num >= MAX_TARGETS) {
		return TC_ACT_SHOT;
	}

	if (tgt_list->target_list[num].ip == 0 || tgt_list->target_list[num].port == 0) {
#ifdef DEBUG_SEND
		__u8 b1, b2, b3, b4;
		ip_to_bytes(ip->saddr, &b1, &b2, &b3, &b4);
		bpf_printk("ERROR key=%d, max=%d, num=%d, ip:%u.%u.%u.%u\n", key, tgt_list->max_count-'0', num, b4, b3, b2, b1);
#endif
		return TC_ACT_OK;
	}

	/* Update cloned packet content */
	udp->dest = htons(tgt_list->target_list[num].port);
	udp->check = 0;
	ip->daddr = tgt_list->target_list[num].ip;
	ip->check = compute_ip_checksum(ip);
	// memcpy(eth->h_dest, tgt_list->target_list[num].mac, ETH_ALEN);

#ifdef DEBUG_SEND
	__u8 b1, b2, b3, b4;
	__u8 c1, c2, c3, c4;
	ip_to_bytes(ip->saddr, &b1, &b2, &b3, &b4);
	ip_to_bytes(ip->daddr, &c1, &c2, &c3, &c4);

	bpf_printk("[fastbroad_prog] egress packet acceptd, info: key=%d, max=%d, num=%d, from:%u.%u.%u.%u -> %u.%u.%u.%u \n", key, tgt_list->max_count - '0', num, b4,b3,b2,b1, c4,c3,c2,c1);
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
	if (eth->h_proto != htons(ETH_P_IP)){
		return XDP_PASS;
	}

	if (eth->h_proto != htons(ETH_P_IP)){
		return XDP_PASS; // Non-IP packet, allow it
	}

	struct iphdr *ip = (struct iphdr *)(eth + 1);
	if (ip->protocol != IPPROTO_UDP){
		return XDP_PASS; // Non-UDP packet, allow it
	}

	struct udphdr *udp = (struct udphdr *)(ip + 1);
	if (udp + 10 > data_end){
		return XDP_DROP; // Malformed packet
	}

	unsigned char *payload = (unsigned char *)(udp + 1);
	if (payload + 1 > data_end){
		return XDP_DROP; // Malformed packet
	}

	if(payload + 40 > data_end){
		return XDP_DROP;
	}

	if (type_checker(payload) < 2) {
		return XDP_PASS; //Broadcast packet, allow it
	}




	return XDP_PASS;
}

// Basic license just for compiling the object code
char __license[] SEC("license") = "GPL";