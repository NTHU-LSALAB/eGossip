// +build ignore

#include <arpa/inet.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <linux/udp.h>

// BPF Header files
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include <string.h>

/* Debug flag*/
// #define DEBUG_TC
// #define DEBUG_XDP

/* Control definition */
#define MAX_TARGETS 64 // Max targets for broadcast
#define MAX_SIZE 200
#define MTU 1500
#define MAX_PAYLOAD 1000
#define MAX_METADATA 256
#define MAX_INT64_LEN 20
#define MAX_SOCKS 64
#define MAX_SEGMENT_SIZE 256

typedef __u64 u64;
typedef __u32 u32;
typedef __u16 u16;

/* PORT value by definition */
static volatile unsigned const short PORT = 8000;

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
  char metadata[MAX_METADATA];
  int64_t update_time;
};

/* Message struct for commucation between kerenlspace and userspace. */
struct message {
  char type;
  struct node_info node;
};

/* BPF_MAP_TYPE_HASH for broadcast target */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u16);
  __type(value, struct targets);
  __uint(max_entries, 1024);
} targets_map SEC(".maps"); // map for targets

/* BPF_MAP_TYPE_HASH for nodelist (Not use for now.) */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u16);
  __type(value, struct targets);
  __uint(max_entries, 1024);
} nodelist_map SEC(".maps");

/* BPF_MAP_TYPE_HASH for metadata store (Not use for now.) */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u16);
  __type(value, struct metadata);
  __uint(max_entries, 1);
} metadata_map SEC(".maps"); // map for metadata

/* BPF_MAP_TYPE_XSKMAP for xsk_map */
struct {
  __uint(type, BPF_MAP_TYPE_XSKMAP);
  __type(key, int);
  __type(value, int);
  __uint(max_entries, MAX_SOCKS);
} xsks_map SEC(".maps"); // map for xsk sockets

/* BPF_MAP_TYPE_ARRAY for qidconf */
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, int);
  __type(value, int);
  __uint(max_entries, MAX_SOCKS);
} qidconf_map SEC(".maps"); // map for qidconf

/* Compute ip checksum for cloned packet before TC_ACT_OK. */
static __always_inline __u16 compute_ip_checksum(struct iphdr *ip) {
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
static __always_inline int type_handler(const char *payload) {
  // Search for the key in the payload
  if (payload[0] != '{') {
    return -1;
  } else {
    if (payload[2] == 'T' && payload[5] == 'e' && payload[7] == ':') {
      if (payload[8] == '1') {
        return 1;
      } else if (payload[8] == '2') {
        return 2;
      } else if (payload[8] == '3') {
        return 3;
      }
    }
  }
  return -1;
}

/* Map key handler for checking broadcast target map key. */
static __always_inline __u16 mapkey_handler(const char *payload) {
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
/* Metadata handler */
static __always_inline int64_t metadata_handler(const char *payload,
                                                __u8 *cursor, void *data_end) {
  int64_t value = 0;
#pragma clang loop unroll(full)
  for (int i = 0; i < MAX_INT64_LEN; i++) {
    if (cursor + (i + 1) > data_end) {
      return XDP_DROP;
    }

    if (*cursor < '0' || *cursor > '9') {
      return XDP_DROP; // not a number
    }

    if (*(cursor + i) == ',') {
      break;
    }

    value = value * 10 + (*(cursor + i) - '0');
  }

  return value;
}

/* Debug function for convet u32 type ip variable into readable number. */
static __always_inline void ip_to_bytes(__u32 ip_addr, __u8 *byte1, __u8 *byte2,
                                        __u8 *byte3, __u8 *byte4) {
  *byte1 = (ip_addr & 0xFF000000) >> 24;
  *byte2 = (ip_addr & 0x00FF0000) >> 16;
  *byte3 = (ip_addr & 0x0000FF00) >> 8;
  *byte4 = ip_addr & 0x000000FF;
}

/* Swap src mac to dst */
static __always_inline void swap_src_dst_mac(void *data) {
  unsigned short *p = data;
  unsigned short dst[3];
  dst[0] = p[0];
  dst[1] = p[1];
  dst[2] = p[2];
  p[0] = p[3];
  p[1] = p[4];
  p[2] = p[5];
  p[3] = dst[0];
  p[4] = dst[1];
  p[5] = dst[2];
}

// Function to extract a JSON segment
static __always_inline int
extractJsonSegment(const char *payload, int payloadSize, struct xdp_md *ctx) {
  char output[MAX_SEGMENT_SIZE]; // Fixed-size buffer
  int i = 0, j = 0, startFound = 0;
  char target[] = "\"Metadata\":{";
  int targetLength = sizeof(target) - 1; // Length of the target string

  // Search for the target segment
  if (payloadSize < targetLength) {
    bpf_printk("Payload too small.\n");
    return XDP_DROP;
  }

  for (i = 0; i < payloadSize - targetLength; i++) {
    startFound = 1;

    // if (payload + (i + 1) > payloadSize) {
    //     bpf_printk("Payload too small.\n");
    //     return XDP_DROP;
    // }

    for (j = 0; j < targetLength; j++) {
      if (payload[i + j] != target[j]) {
        startFound = 0;
        break;
      }
    }

    if (startFound) {
      int outputIndex = 0;
      int bracketCount = 1;

      // Copy the content starting from the '{'
      for (j = i + targetLength;
           j < payloadSize && outputIndex < MAX_SEGMENT_SIZE - 1; j++) {
        output[outputIndex++] = payload[j];

        // Counting brackets to find the end of the JSON segment
        if (payload[j] == '{') {
          bracketCount++;
        } else if (payload[j] == '}') {
          bracketCount--;
          if (bracketCount == 0)
            break;
        }
      }

      output[outputIndex] = '\0'; // Null-terminate the string
      bpf_printk("Extracted content: %s\n", output);
      return 1;
    }
  }

  bpf_printk("Target segment not found.\n");
}

/* ebpf TC Hook for Fastbroadcast. */
SEC("classifier")
int fastbroadcast(struct __sk_buff *skb) {
  const int l3_off = ETH_HLEN;                      // IP header offset
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

  if (type_handler(payload) != 1) {
    return TC_ACT_OK; // Valid packet but not broadcast packet, allow it
  }

  __u16 key = mapkey_handler(payload);
  if (key == 1) {
    return TC_ACT_OK;
  }

  /* Lookup ebpf map */
  struct targets *tgt_list = bpf_map_lookup_elem(&targets_map, &key);
  if (!tgt_list) {
#ifdef DEBUG_TC
    __u8 b1, b2, b3, b4;
    __u8 c1, c2, c3, c4;
    ip_to_bytes(ip->saddr, &b1, &b2, &b3, &b4);
    ip_to_bytes(ip->daddr, &c1, &c2, &c3, &c4);
    bpf_printk("[fastbroad_prog] No target list found before clone packet "
               "key=%d, from %u.%u.%u.%u ->  %u.%u.%u.%u \n",
               key, b3, b2, b1, c4, c3, c2, c1);
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
#ifdef DEBUG_TC
    int res = bpf_clone_redirect(skb, skb->ifindex, 0);
    bpf_printk("[fastbroad_prog] clone packet, res: %d, curr: %d, max: %d\n",
               res, curr - '0', tgt_list->max_count - '0');
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
#ifdef DEBUG_TC
    bpf_printk("[fastbroad_prog] TC_ACT_SHOT (Counting error)\n");
#endif
    return TC_ACT_SHOT;
  }

  int num = (tgt_list->max_count - '0') - (tgt_list->max_count - curr);

#ifdef DEBUG_TC
  bpf_printk("[fastbroad_prog] egress packet: num:%d, curr: %d, max_count:%d\n",
             num, payload[18] - '0', tgt_list->max_count - '0');
#endif

  if (num < 0 || num >= MAX_TARGETS) {
    return TC_ACT_SHOT;
  }

  if (tgt_list->target_list[num].ip == 0 ||
      tgt_list->target_list[num].port == 0) {
#ifdef DEBUG_TC
    __u8 b1, b2, b3, b4;
    ip_to_bytes(ip->saddr, &b1, &b2, &b3, &b4);
    bpf_printk("ERROR key=%d, max=%d, num=%d, ip:%u.%u.%u.%u\n", key,
               tgt_list->max_count - '0', num, b4, b3, b2, b1);
#endif
    return TC_ACT_OK;
  }

  /* Update cloned packet content */
  udp->dest = htons(tgt_list->target_list[num].port);
  udp->check = 0;
  ip->daddr = tgt_list->target_list[num].ip;
  ip->check = compute_ip_checksum(ip);
  memcpy(eth->h_dest, tgt_list->target_list[num].mac, ETH_ALEN);

#ifdef DEBUG_TC
  __u8 b1, b2, b3, b4;
  __u8 c1, c2, c3, c4;
  ip_to_bytes(ip->saddr, &b1, &b2, &b3, &b4);
  ip_to_bytes(ip->daddr, &c1, &c2, &c3, &c4);

  bpf_printk("[fastbroad_prog] egress packet acceptd, info: key=%d, max=%d, "
             "num=%d, from:%u.%u.%u.%u -> %u.%u.%u.%u \n",
             key, tgt_list->max_count - '0', num, b4, b3, b2, b1, c4, c3, c2,
             c1);
#endif

  return TC_ACT_OK;
}

/* ebpf XDP Hook for Fastdrop. */
SEC("xdp")
int xdp_sock_prog(struct xdp_md *ctx) {

  int index = ctx->rx_queue_index;

  // A set entry here means that the correspnding queue_id
  // has an active AF_XDP socket bound to it.
  if (bpf_map_lookup_elem(&qidconf_map, &index)) {
    // redirect packets to an xdp socket that match the given IPv4 or IPv6
    // protocol; pass all other packets to the kernel
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    __u16 h_proto = eth->h_proto;
    if ((void *)eth + sizeof(*eth) > data_end)
      goto out;

    if (bpf_htons(h_proto) != ETH_P_IP)
      goto out;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end) {
#ifdef DEBUG_XDP
      bpf_printk("ip + sizeof(*ip) > data_end\n");
#endif
      goto out;
    }

    if (ip->protocol != IPPROTO_UDP) { // Only UDP packets
#ifdef DEBUG_XDP
      bpf_printk("ip->protocol != IPPROTO_UDP\n");
#endif
      goto out;
    }

    struct udphdr *udp = (void *)ip + sizeof(*ip);
    if ((void *)udp + sizeof(*udp) > data_end) {
      goto out;
    }

    if (udp->dest != bpf_htons(PORT)) {
#ifdef DEBUG_XDP
      bpf_printk("Not the port.\n");
#endif
      goto out;
    }

    return bpf_redirect_map(&xsks_map, index, 0);
  }

drop:
  return XDP_DROP;

out:
  return XDP_PASS;
}

// Basic license just for compiling the object code
char __license[] SEC("license") = "GPL"; 