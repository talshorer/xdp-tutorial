/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/in6.h>
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
/* Defines xdp_stats_map from packet04 */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
	void *pos;
};

/* Packet parsing helpers.
 *
 * Each helper parses a packet header, including doing bounds checking, and
 * returns the type of its contents if successful, and -1 otherwise.
 *
 * For Ethernet and IP headers, the content type is the type of the payload
 * (h_proto for Ethernet, nexthdr for IPv6), for ICMP it is the ICMP type field.
 * All return values are in host byte order.
 */
struct vlan_hdr {
	__be16	h_vlan_TCI;
	__be16	h_vlan_encapsulated_proto;
};

static __always_inline int parse_vlan(struct hdr_cursor *nh, void *data_end)
{
	struct vlan_hdr *vlan = nh->pos;
	int hdrsize = sizeof(*vlan);

	if (vlan + 1 > data_end)
		return -1;

	nh->pos += hdrsize;

	return vlan->h_vlan_encapsulated_proto; /* network-byte-order */
}

static __always_inline int proto_is_vlan(__u16 h_proto)
{
	return !!(h_proto == bpf_htons(ETH_P_8021Q) ||
		h_proto == bpf_htons(ETH_P_8021AD));
}

#define VLAN_MAX_DEPTH 10

static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
					void *data_end,
					struct ethhdr **ethhdr)
{
	struct ethhdr *eth = nh->pos;
	int hdrsize = sizeof(*eth);
	int proto;
	int i;

	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if (eth + 1 > data_end)
		return -1;

	nh->pos += hdrsize;
	*ethhdr = eth;

	proto = eth->h_proto;
	#pragma unroll
	for (i = 0; i < VLAN_MAX_DEPTH; i++) {
		if (!proto_is_vlan(proto))
			break;
		proto = parse_vlan(nh, data_end);
	}

	return proto; /* network-byte-order */
}

/* Assignment 2: Implement and use this */
static __always_inline int parse_ip6hdr(struct hdr_cursor *nh,
					void *data_end,
					struct ipv6hdr **ip6hdr)
{
	struct ipv6hdr *ip6 = nh->pos;
	int hdrsize = sizeof(*ip6);

	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if (ip6 + 1 > data_end)
		return -1;

	nh->pos += hdrsize;
	*ip6hdr = ip6;

	return ip6->nexthdr;
}

/* Assignment 3: Implement and use this */
static __always_inline int parse_icmp6hdr(struct hdr_cursor *nh,
					  void *data_end,
					  struct icmp6hdr **icmp6hdr)
{
	struct icmp6hdr *icmp6 = nh->pos;
	int hdrsize = sizeof(*icmp6);

	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if (icmp6 + 1 > data_end)
		return -1;

	nh->pos += hdrsize;
	*icmp6hdr = icmp6;

	if (icmp6->icmp6_type != ICMPV6_ECHO_REQUEST)
		return -1;

	return icmp6->icmp6_sequence; /* network-byte-order */
}

static __always_inline int parse_ip4hdr(struct hdr_cursor *nh,
					void *data_end)
{
	struct iphdr *ip4 = nh->pos;
	int hdrsize = sizeof(*ip4);

	if (ip4 + 1 > data_end)
		return -1;

	hdrsize = ip4->ihl * 4;
	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;

	return ip4->protocol;
}

static __always_inline int parse_icmp4hdr(struct hdr_cursor *nh,
					  void *data_end)
{
	struct icmphdr *icmp4 = nh->pos;
	int hdrsize = sizeof(*icmp4);

	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if (icmp4 + 1 > data_end)
		return -1;

	nh->pos += hdrsize;

	if (icmp4->type != ICMP_ECHO)
		return -1;

	return icmp4->un.echo.sequence; /* network-byte-order */
}

SEC("xdp_packet_parser")
int  xdp_parser_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth;
	struct ipv6hdr *ip6;
	struct icmp6hdr *icmp6;

	/* Default action XDP_PASS, imply everything we couldn't parse, or that
	 * we don't want to deal with, we just pass up the stack and let the
	 * kernel deal with it.
	 */
	__u32 action = XDP_PASS; /* Default action */

        /* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int nh_type;

	/* Start next header cursor position at data start */
	nh.pos = data;

	/* Packet parsing in steps: Get each header one at a time, aborting if
	 * parsing fails. Each helper function does sanity checking (is the
	 * header type in the packet correct?), and bounds checking.
	 */
	nh_type = parse_ethhdr(&nh, data_end, &eth);
	if (nh_type == bpf_htons(ETH_P_IPV6)) {
		nh_type = parse_ip6hdr(&nh, data_end, &ip6);
		if (nh_type != IPPROTO_ICMPV6) {
			goto out;
		}

		nh_type = parse_icmp6hdr(&nh, data_end, &icmp6);
		if ((bpf_ntohs(nh_type) & 1) == 0) {
			goto out;
		}
	} else if (nh_type == bpf_htons(ETH_P_IP)) {
		nh_type = parse_ip4hdr(&nh, data_end);
		if (nh_type != IPPROTO_ICMP) {
			goto out;
		}

		nh_type = parse_icmp4hdr(&nh, data_end);
		if ((bpf_ntohs(nh_type) & 1) == 0) {
			goto out;
		}
	} else {
		goto out;
	}

	/* Assignment additions go below here */

	action = XDP_DROP;
out:
	return xdp_stats_record_action(ctx, action); /* read via xdp_stats */
}

char _license[] SEC("license") = "GPL";
