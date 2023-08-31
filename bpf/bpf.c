// +build ignore

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>


#define MAX_SOCKS 64
#define FAST_BROADCAST_MAX 100

//static volatile unsigned const short PORT;

// Ensure map references are available.
/*
				These will be initiated from go and
				referenced in the end BPF opcodes by file descriptor
*/

typedef __u64 u64;
typedef __u32 u32;
typedef __u16 u16;

struct gossip_configure
{
	__u32 addr; // ipv4.
	__u16 port;
	char eth[ETH_ALEN];
};

// struct {
// 	__uint(type, BPF_MAP_TYPE_XSKMAP);
// 	__uint(key_size, sizeof(u32));
// 	__uint(value_size, sizeof(u32));
// 	__uint(max_entries, MAX_SOCKS);
// } xsks_map SEC(".maps");

// struct {
// 	__uint(type, BPF_MAP_TYPE_ARRAY);
// 	__uint(key_size, sizeof(u32));
// 	__uint(value_size, sizeof(u32));
// 	__uint(max_entries, MAX_SOCKS);
// } qidconf_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct gossip_configure));
	__uint(max_entries, FAST_BROADCAST_MAX);
} map_configure SEC(".maps");


static inline int message_type_checker(char *payload, void *data_end)
{
	return 0;
}

// SEC("xdp_sock")
// int xdp_sock_prog(struct xdp_md *ctx)
// {
// 	int index = ctx->rx_queue_index;

// 	// A set entry here means that the correspnding queue_id
// 	// has an active XDP socket bound to it.
// 	if (bpf_map_lookup_elem(&qidconf_map, &index))
// 	{
// 		// redirect packets to an xdp socket that match the given IPv4 or IPv6 protocol; pass all other packets to the kernel
// 		bpf_printk("hello\n");
// 		void *data = (void *)(long)ctx->data;
// 		void *data_end = (void *)(long)ctx->data_end;
// 		struct ethhdr *eth = data;
// 		__u16 h_proto = eth->h_proto;
// 		if ((void *)eth + sizeof(*eth) > data_end)
// 			goto out;

// 		if (bpf_htons(h_proto) != ETH_P_IP)
// 			goto out;

// 		struct iphdr *ip = data + sizeof(*eth);
// 		if ((void *)ip + sizeof(*ip) > data_end)
// 			goto out;

// 		// Only UDP
// 		if (ip->protocol != IPPROTO_UDP)
// 			goto out;

// 		struct udphdr *udp = (void *)ip + sizeof(*ip);
// 		if ((void *)udp + sizeof(*udp) > data_end)
// 			goto out;

// 		if (udp->dest == bpf_htons(8080)) {
// 			bpf_printk("xdp_sock_prog: %d \n", udp->dest);
// 			return bpf_redirect_map(&xsks_map, index, 0);
// 		}
// 	}

// out:
// 	return XDP_PASS;
// }

SEC("fastbroadcast")
int fastboradcast_prog(struct __sk_buff *skb)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;

	struct ethhdr *eth = data;
	struct iphdr *ip = data + sizeof(*eth);
	//struct udphdr *udp = (void *)ip + sizeof(*ip);
	
	if ((void *)eth + sizeof(*eth) > data_end)
		return TC_ACT_OK;
	
	if(ip->protocol != IPPROTO_UDP)
		return TC_ACT_OK;
	
	if (bpf_htons(eth->h_proto) != ETH_P_IP)
		return TC_ACT_OK;

	char *payload = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
	
	int type = message_type_checker(payload, data_end);
	int id = 0;
	struct paxos_configure *replicaInfo = bpf_map_lookup_elem(&map_configure, &id);

	bpf_trace_printk("fastbroadcast_prog: %d, %d \n", type);
	if (replicaInfo == NULL)
		return TC_ACT_OK;

	return TC_ACT_OK;
}

// Basic license just for compiling the object code
char __license[] SEC("license") = "GPL";