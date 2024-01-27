// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */
#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define ETH_P_IP   0x0800 /* Internet Protocol v4 packet */
#define ETH_P_IPV6 0x86DD /* Internet Protocol v6 packet */
#define AF_INET 2
#define AF_INET6 10

#define PROTO_TCP 6
#define PROTO_UDP 17
#define PROTO_ICMP 1
#define PROTO_GRE 47
#define PROTO_ESP 50
#define PROTO_ICMP6 58

/* ICMP Types */
enum ICMP_TYPES {
	ICMP_TYPE_ECHO_REPLY = 0,
	ICMP_TYPE_DEST_UNREACHABLE = 3,
	ICMP_TYPE_ECHO_REQUEST = 8,
	ICMP_TYPE_TIME_EXCEEDED = 11,
	ICMP_TYPE_PARAM_PROBLEM = 12
};

/* ICMPv6 Codes */
enum ICMP6_TYPES {
	ICMP6_TYPE_DEST_UNREACH = 1,
	ICMP6_TYPE_TOO_BIG = 2,
	ICMP6_TYPE_TIME_EXCEEDED = 3,
	ICMP6_TYPE_PARAM_PROBLEM = 4,
	/* Codes below this are errors */
	_ICMP6_TYPE_ERROR_MAX = 5,
	ICMP6_TYPE_ECHO_REQUEST = 128,
	ICMP6_TYPE_ECHO_REPLY = 129,
};

/* MAPS */
struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __type(key, u32);
        __type(value, struct in6_addr);
        __uint(max_entries, 2);
} addrs SEC(".maps");



/* Process packets in the 6->4 direction */
static inline int tc_nat64(struct __sk_buff *skb)
{
	void *data_end = (void *)(__u64)skb->data_end;
	void *data = (void *)(__u64)skb->data;
	struct ethhdr *l2;
	struct ipv6hdr *ip6;


	/* Read and validate headers
	 * If we have any errors at this stage,
	 * We will just pass the packet back to the kernel
	 */
	l2 = data;
	if ((void *)(l2 + 1) > data_end) return TC_ACT_OK;

	ip6 = (struct ipv6hdr *)(l2 + 1);
	if ((void *)(ip6 + 1) > data_end) return TC_ACT_OK;

	/* Header must be IPv6 */
	if(ip6->version != 6) return TC_ACT_OK;

	/* Get the first map (local clat address) */
	{
		int idx = 0;
		struct in6_addr *local = bpf_map_lookup_elem(&addrs,&idx);
		if(!local){
			bpf_printk("Unable to read local addr");
			return TC_ACT_OK;
		}

		/* Compare 4 words to local clat */
		if((ip6->daddr.in6_u.u6_addr32[0] != local->in6_u.u6_addr32[0]) ||
		(ip6->daddr.in6_u.u6_addr32[1] != local->in6_u.u6_addr32[1]) ||
		(ip6->daddr.in6_u.u6_addr32[2] != local->in6_u.u6_addr32[2]) ||
		(ip6->daddr.in6_u.u6_addr32[3] != local->in6_u.u6_addr32[3]))
		{
			bpf_printk("Rogue packet tried to sneak by the clat for %04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",
				bpf_htons(ip6->daddr.in6_u.u6_addr16[0]),bpf_htons(ip6->daddr.in6_u.u6_addr16[1]),
				bpf_htons(ip6->daddr.in6_u.u6_addr16[2]),bpf_htons(ip6->daddr.in6_u.u6_addr16[3]),
				bpf_htons(ip6->daddr.in6_u.u6_addr16[4]),bpf_htons(ip6->daddr.in6_u.u6_addr16[5]),
				bpf_htons(ip6->daddr.in6_u.u6_addr16[6]),bpf_htons(ip6->daddr.in6_u.u6_addr16[7]));
			return TC_ACT_OK;
		}
	}

	int idx = 1;
	struct in6_addr *prefix = bpf_map_lookup_elem(&addrs,&idx);
	if(!prefix){
		bpf_printk("Unable to read prefix addr");
		return TC_ACT_OK;
	}

	/* Check if the received source was the PLAT/NAT64, otherwise drop it */
	{
		/* Compare 3 words to local clat */
		if((ip6->saddr.in6_u.u6_addr32[0] != prefix->in6_u.u6_addr32[0]) ||
		   (ip6->saddr.in6_u.u6_addr32[1] != prefix->in6_u.u6_addr32[1]) ||
		   (ip6->saddr.in6_u.u6_addr32[2] != prefix->in6_u.u6_addr32[2]))
		{
			bpf_printk("Rogue packet tried to sneak by the clat from source %04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",
				bpf_htons(ip6->saddr.in6_u.u6_addr16[0]),bpf_htons(ip6->saddr.in6_u.u6_addr16[1]),
				bpf_htons(ip6->saddr.in6_u.u6_addr16[2]),bpf_htons(ip6->saddr.in6_u.u6_addr16[3]),
				bpf_htons(ip6->saddr.in6_u.u6_addr16[4]),bpf_htons(ip6->saddr.in6_u.u6_addr16[5]),
				bpf_htons(ip6->saddr.in6_u.u6_addr16[6]),bpf_htons(ip6->saddr.in6_u.u6_addr16[7]));
			return TC_ACT_SHOT;
		}
	};


	/* Create a v4 header struct and copy over parameters */
	struct iphdr ip4_temp = {
		.version = 4,
		.ihl = sizeof(struct iphdr)/sizeof(__u32),
		.tos = (ip6->priority << 4) + (ip6->flow_lbl[0] >> 4),
		.tot_len = ip6->payload_len + 20,
		.protocol = ((ip6->nexthdr == PROTO_ICMP6) ? PROTO_ICMP : ip6->nexthdr),
		/* Per RFCs we should act as a router and decrement TTL
		 * However, we are acting as a CLAT on the local system
		 * So we are not decrementing ttl (Android follows this as well)
		 */
		.ttl = ip6->hop_limit,
		/* Extract sadr/dadr from local config */
		.saddr = ip6->saddr.in6_u.u6_addr32[3],
		.daddr = prefix->in6_u.u6_addr32[3],
	};
	
	/* At this point we are committed to NATing, so change proto */
	if(bpf_skb_change_proto(skb,bpf_htons(ETH_P_IP),0)) {
		bpf_printk("Had an error changing proto, oops");
		/* Oops, well this packet got lost */
		return TC_ACT_SHOT;
	}

	bpf_printk("In the NAT64 Realm");
	
	/* At this point we need to re-validate all pointers and need to fill in everything again */
	data_end = (void *)(__u64)skb->data_end;
	data = (void *)(__u64)skb->data;
	l2 = data;
	if ((void *)(l2 + 1) > data_end) return TC_ACT_SHOT;

	/* Update L2 EtherType to IP */
	l2->h_proto = bpf_htons(ETH_P_IP);

	/* Struct copy temp header into real header */
	struct iphdr * ip4 = (struct iphdr *)(l2 + 1);
	if ((void *)(ip4 + 1) > data_end) return TC_ACT_SHOT;
	*(struct iphdr*)(ip4) = ip4_temp;

	/* ICMP requires hella lot of translation at this point */
	if(ip4->protocol == PROTO_ICMP) {
		/* Read old header */
		struct icmphdr *icmp = (struct icmphdr *)(ip4 + 1);
		if ((void *)(icmp + 1) > data_end) return TC_ACT_SHOT;
		/* Map ICMPv4 Codes to ICMPv6 Types+Codes */
		switch(icmp->type)
		{
			/* Pings are straightforward to translate, do these in-place */
			case ICMP6_TYPE_ECHO_REPLY:
				icmp->type = ICMP_TYPE_ECHO_REPLY;
				break;
			case ICMP6_TYPE_ECHO_REQUEST:
				icmp->type = ICMP_TYPE_ECHO_REQUEST;
				break;
			/* Error codes */
			case ICMP6_TYPE_DEST_UNREACH:
				/* Replace Code with v6 equivalents
				 * Most are ICMP type 3 (errors)
				 */
				icmp->type = 3;
				switch(icmp->code)
				{
					/* RFC 7915 describes these as type/code numbers, so I will not
					 * make enums for all of these stupid things
					 * Most of them result in No Route which is code 0
					 */
					case 0:
					case 2:
					case 3:
						icmp->code = 1;
						break;
					case 1:
						icmp->code = 10;
						break;
					case 4:
						icmp->code = 3;
						break;
					default:
						return TC_ACT_SHOT;
						break;
				}
			case ICMP6_TYPE_TOO_BIG:
				/* Set Type to 3, adjust checksum, leave code unchanged */
				icmp->type = 3;
				icmp->code = 4;
				bpf_printk("TODO Need to fix the Too Big message to properly include MTU");
				break;
			case ICMP6_TYPE_TIME_EXCEEDED:
				icmp->type = 11;
				break;
			case ICMP6_TYPE_PARAM_PROBLEM:
				switch(icmp->code)
				{
					case 0:
						icmp->type = 12;
						icmp->code = 0;
						bpf_printk("I didn't read Figure 6 to update PARAM PROBLEM");
						break;
					case 1:
						icmp->type = 3;
						icmp->code = 2;
						break;
					default:
						return TC_ACT_SHOT;
				}
			default:
				/* We are supposed to silently drop all other codes or unknown types */
				bpf_printk("ICMPv6 Unknown Type %d Code %d (dropping)",icmp->type,icmp->code);
				return TC_ACT_SHOT;
				break;
		}
		/* Recalc ICMPv4 checksum */
		
	}

	/* Nothing else requires translation? */

	/* If execution gets here packet is fully translated, we should redirect it to loopback */
	return bpf_redirect(1,BPF_F_INGRESS);
	return TC_ACT_OK;
}



/* Process packets in the 4->6 direction */
static inline int tc_nat46(struct __sk_buff *skb)
{
	void *data_end = (void *)(__u64)skb->data_end;
	void *data = (void *)(__u64)skb->data;
	struct ethhdr *l2;
	struct iphdr *ip4;
	struct ipv6hdr *ip6;

	/* Read and validate headers
	 * If we have any errors at this stage,
	 * We will just pass the packet back to the kernel
	 */
	l2 = data;
	if ((void *)(l2 + 1) > data_end) return TC_ACT_OK;

	ip4 = (struct iphdr *)(l2 + 1);
	if ((void *)(ip4 + 1) > data_end) return TC_ACT_OK;

	/* Header must be IPv4 */
	if(ip4->version != 4) return TC_ACT_OK;

	/* SA must be the address of the clat, otherwise let the kernel deal with it */
	if(ip4->saddr != bpf_htonl(0xC0000004))
	{
		bpf_printk("Rogue packet tried to sneak by the clat from %08x",bpf_htonl(ip4->saddr));
		return TC_ACT_OK;
	}

	bpf_printk("In the NAT46 Realm");
	/* Create a v6 header struct and copy over parameters */
	struct ipv6hdr ip6_temp = 
	{
		.version = 6,
		.priority = ip4->tos >> 4,
		.flow_lbl = {(ip4->tos & 0xF) << 4,0,0},
		/* IPv4 is total len, this is payload len, sub IPv4 header */
		.payload_len = bpf_htons(bpf_ntohs(ip4->tot_len) - 20),
		.nexthdr = ((ip4->protocol == PROTO_ICMP) ? PROTO_ICMP6 : ip4->protocol),
		/* Per RFCs we should act as a router and decrement TTL
		 * However, we are acting as a CLAT on the local system
		 * So we are not decrementing ttl (Android follows this as well)
		 */
		.hop_limit = ip4->ttl,
	};

	/* Translate addresses */
	ip6_temp.saddr.in6_u.u6_addr32[0] = bpf_htonl(0x2601040e);
	ip6_temp.saddr.in6_u.u6_addr32[1] = bpf_htonl(0x8102ccc0);
	ip6_temp.saddr.in6_u.u6_addr32[3] = bpf_htonl(0x00006464);
	ip6_temp.daddr.in6_u.u6_addr32[0] = bpf_htonl(0x0064ff9b);
	ip6_temp.daddr.in6_u.u6_addr32[3] = ip4->daddr;
	
	/* Do Early FIB lookup to determine if we must send ICMP rejection back up */
	struct bpf_fib_lookup fib_params = {
		.family = AF_INET6, /* It will be INET6 when we are done */
		.flowinfo = *(__be32 *)&ip6_temp & bpf_htonl(0x0fffffff), /* flow label + priority */
		.l4_protocol = ip6_temp.nexthdr,
		.sport = 0,
		.dport = 0,
		.tot_len = bpf_ntohs(ip6_temp.payload_len),
		/* If the incoming ifindex is invalid, set it to localhost */
		.ifindex = ((!skb->ingress_ifindex) ? 1 : skb->ingress_ifindex),
	};
	/* Copy addresses over (memcpy does not exist in ebpf) */
	for(int i = 0; i < 4; i++)
	{
		fib_params.ipv6_src[i] = ip6_temp.saddr.in6_u.u6_addr32[i];
		fib_params.ipv6_dst[i] = ip6_temp.daddr.in6_u.u6_addr32[i];
	}

	/* Do FIB lookup and check results */
	int rc = bpf_fib_lookup(skb, &fib_params, sizeof(fib_params), 0);

	/* Check if FIB lookup failed, and either drop or create ICMP reply */
	if(rc != BPF_FIB_LKUP_RET_SUCCESS)
	{
		switch(rc)
		{
		/* These cases should get ICMP messages returned to sender
		 * But that's a probllem for future apalrd
		 * Really we should do the FIB lookup *early*
		 * so we can transform the current packet into an ICMP and 
		 * hairpin it back to the source before we do 4->6 translate
		 */
			case BPF_FIB_LKUP_RET_UNREACHABLE:
			case BPF_FIB_LKUP_RET_PROHIBIT:
			case BPF_FIB_LKUP_RET_NO_NEIGH:
			case BPF_FIB_LKUP_RET_FRAG_NEEDED:
			/* The remainder can get dropped */
			case BPF_FIB_LKUP_RET_BLACKHOLE:
			default:
				/* Did not find a destination */
				bpf_printk("FIB lookup failed with code %d",rc);
				return TC_ACT_SHOT;
			}
	}

	/* At this point we are committed to NATing, so change proto */
	if(bpf_skb_change_proto(skb,bpf_htons(ETH_P_IPV6),0)) {
		bpf_printk("Had an error changing proto, oops");
		/* Oops, well this packet got lost */
		return TC_ACT_SHOT;
	}
	
	/* At this point we need to re-validate all pointers and need to fill in everything again */
	data_end = (void *)(__u64)skb->data_end;
	data = (void *)(__u64)skb->data;
	l2 = data;
	if ((void *)(l2 + 1) > data_end) return TC_ACT_SHOT;

	/* Copy in MACs we learned earlier from the FIB */
	for(int i = 0; i < 6; i++)
	{
		l2->h_dest[i] = fib_params.dmac[i];
		l2->h_source[i] = fib_params.smac[i];
	}

	/* Update L2 EtherType to IPv6 */
	l2->h_proto = bpf_htons(ETH_P_IPV6);

	/* Struct copy temp header into real header */
	ip6 = (struct ipv6hdr *)(l2 + 1);
	if ((void *)(ip6 + 1) > data_end) return TC_ACT_SHOT;
	*(struct ipv6hdr*)(ip6) = ip6_temp;

	/* ICMP requires hella lot of translation at this point */
	if(ip6->nexthdr == PROTO_ICMP6) {
		/* Read old header */
		struct icmphdr *icmp = (struct icmphdr *)(ip6 + 1);
		struct icmp6hdr *icmp6 = (struct icmp6hdr *)icmp;
		if ((void *)(icmp + 1) > data_end) return TC_ACT_SHOT;
		/* Map ICMPv4 Codes to ICMPv6 Types+Codes */
		switch(icmp->type)
		{
			/* Pings are straightforward to translate, do these in-place */
			case ICMP_TYPE_ECHO_REPLY:
				icmp->type = ICMP6_TYPE_ECHO_REPLY;
				break;
			case ICMP_TYPE_ECHO_REQUEST:
				icmp->type = ICMP6_TYPE_ECHO_REQUEST;
				break;
			/* Error codes */
			case ICMP_TYPE_DEST_UNREACHABLE:
				/* Replace Code with v6 equivalents
				 * Most are ICMP type 1 (errors)
				 */
				icmp->type = 1;
				switch(icmp->code)
				{
					/* RFC 7915 describes these as type/code numbers, so I will not
					 * make enums for all of these stupid things
					 * Most of them result in No Route which is code 0
					 */
					case 0:
					case 1:
					case 5:
					case 6:
					case 7:
					case 8:
					case 11:
					case 12:
						icmp->code = 0;
						break;
					case 2:
						/* Translate to an ICMPv6 Parameter Problem, Pointer = IPv6 Next Header */
						bpf_printk("TODO AGP 4->6 Port Unreach");
						icmp->type = 4;
						icmp->code = 1;
						break;
					case 3:
						icmp->code = 4;
						break;
					case 4:
						/* Fragmentation Needed */
						bpf_printk("TODO AGP 4->6 Fragment Needed");
						break;
					/* Administratively Prohibited */
					case 9:
					case 10:
					case 13:
					case 15:
						icmp->code = 1;
						break;
					/* Silently Drop */
					case 14:
					default:
						return TC_ACT_SHOT;
						break;
				}
			case ICMP_TYPE_TIME_EXCEEDED:
				/* Set Type to 3, adjust checksum, leave code unchanged */
				icmp->type = 3;
				break;
			case ICMP_TYPE_PARAM_PROBLEM:
				/* Set Type to 4, translate code as follows */
				icmp->type = 4;
				switch(icmp->code)
				{
					/* RFC 7915 tells us to look at figure 3
					 * I have not yet looked at figure 3, so tbd
					 */
					case 0:
					case 2:
						bpf_printk("FRC7915 told me to look at figure 3 and I didn't yet");
						return TC_ACT_SHOT;
						break;
					/* For unknown codes drop silently */
					default:
						return TC_ACT_SHOT;
						break;
				}
				break;
			default:
				/* We are supposed to silently drop all other codes or unknown types */
				bpf_printk("ICMPv4 Unknown Type %d Code %d (dropping)",icmp->type,icmp->code);
				return TC_ACT_SHOT;
				break;
		}
	}

	/* Nothing else requires translation? */

	/* If execution gets here packet is fully translated, we should redirect it */
	return bpf_redirect(fib_params.ifindex,0);
}

SEC("tc")
int tc_nat(struct __sk_buff *skb)
{
	/* If v4, go to nat46 */
	if(skb->protocol == bpf_htons(ETH_P_IP))
		return tc_nat46(skb);
	else if(skb->protocol == bpf_htons(ETH_P_IPV6))
		return tc_nat64(skb);
	else
		bpf_printk("Unknown Proto in tc_nat %04x",bpf_htons(skb->protocol));

	return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";
