/*
 * defs.h
 *
 *  Created on: 20-May-2019
 *      Author: saurabh
 */
#ifndef _AIRCRACK_NG_PCAP_H_
#define _AIRCRACK_NG_PCAP_H_

#include <stdint.h>

#define FORMAT_CAP 1
#define FORMAT_IVS 2
#define FORMAT_IVS2 3
#define FORMAT_HCCAP 4
#define FORMAT_HCCAPX 5

#define HCCAPX_MAGIC "HCPX"
#define HCCAPX_CIGAM "XPCH"
#define TCPDUMP_MAGIC 0xA1B2C3D4
#define TCPDUMP_CIGAM 0xD4C3B2A1
#define IVSONLY_MAGIC "\xBF\xCA\x84\xD4"
#define IVS2_MAGIC "\xAE\x78\xD1\xFF"
#define IVS2_EXTENSION "ivs"
#define IVS2_VERSION 1

#define PCAP_VERSION_MAJOR 2
#define PCAP_VERSION_MINOR 4

#define LINKTYPE_ETHERNET 1
#define LINKTYPE_IEEE802_11 105
#define LINKTYPE_PRISM_HEADER 119
#define LINKTYPE_RADIOTAP_HDR 127
#define LINKTYPE_PPI_HDR 192

// BSSID const. length of 6 bytes; can be together with all the other types
#define IVS2_BSSID 0x0001

// ESSID var. length; alone, or with BSSID
#define IVS2_ESSID 0x0002

// wpa structure, const. length; alone, or with BSSID
#define IVS2_WPA 0x0004

// IV+IDX+KEYSTREAM, var. length; alone or with BSSID
#define IVS2_XOR 0x0008

/* [IV+IDX][i][l][XOR_1]..[XOR_i][weight] *
 * holds i possible keystreams for the same IV with a length of l for each
 * keystream (l max 32)  *
 * and an array "int weight[16]" at the end */
#define IVS2_PTW 0x0010

// unencrypted packet
#define IVS2_CLR 0x0020

// Maximum length of an Information Element
#define MAX_IE_ELEMENT_SIZE 256

struct pcap_file_header
{
	uint32_t magic;
	uint16_t version_major;
	uint16_t version_minor;
	int32_t thiszone;
	uint32_t sigfigs;
	uint32_t snaplen;
	uint32_t linktype;
};

struct pcap_pkthdr
{
	int32_t tv_sec;
	int32_t tv_usec;
	uint32_t caplen;
	uint32_t len;
};

struct ivs2_filehdr
{
	uint16_t version;
};

struct ivs2_pkthdr
{
	uint16_t flags;
	uint16_t len;
};

#endif /* common.h */
