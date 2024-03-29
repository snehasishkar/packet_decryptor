/*
 *  MD5, SHA-1, RC4 and AES implementations
 *
 *  Copyright (C) 2001-2004  Christophe Devine
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.

 */

#ifndef _CRYPTO_H
#define _CRYPTO_H

#ifdef USE_GCRYPT
#include "gcrypt-openssl-wrapper.h"
#endif
#include <stddef.h>
#define S_LLC_SNAP "\xAA\xAA\x03\x00\x00\x00"
#define S_LLC_SNAP_ARP (S_LLC_SNAP "\x08\x06")
#define S_LLC_SNAP_WLCCP "\xAA\xAA\x03\x00\x40\x96\x00\x00"
#define S_LLC_SNAP_IP (S_LLC_SNAP "\x08\x00")
#define S_LLC_SNAP_SPANTREE "\x42\x42\x03\x00\x00\x00\x00\x00"
#define S_LLC_SNAP_CDP "\xAA\xAA\x03\x00\x00\x0C\x20"
#define IEEE80211_FC1_DIR_FROMDS 0x02 /* AP ->STA */

#define TYPE_ARP 0
#define TYPE_IP 1

#define NULL_MAC (unsigned char *) "\x00\x00\x00\x00\x00\x00"
#define BROADCAST (unsigned char *) "\xFF\xFF\xFF\xFF\xFF\xFF"
#define SPANTREE (unsigned char *) "\x01\x80\xC2\x00\x00\x00"
#define CDP_VTP (unsigned char *) "\x01\x00\x0C\xCC\xCC\xCC"

#define IEEE80211_FC0_SUBTYPE_MASK 0xf0
#define IEEE80211_FC0_SUBTYPE_SHIFT 4

/* for TYPE_DATA (bit combination) */
#define IEEE80211_FC0_SUBTYPE_QOS 0x80
#define IEEE80211_FC0_SUBTYPE_QOS_NULL 0xc0

#define GET_SUBTYPE(fc)                                                        \
	(((fc) &IEEE80211_FC0_SUBTYPE_MASK) >> IEEE80211_FC0_SUBTYPE_SHIFT)        \
		<< IEEE80211_FC0_SUBTYPE_SHIFT

#define ROL32(A, n) (((A) << (n)) | (((A) >> (32 - (n))) & ((1UL << (n)) - 1)))
#define ROR32(A, n) ROL32((A), 32 - (n))

struct WPA_ST_info
{
	struct WPA_ST_info * next; /* next supplicant              */
	unsigned char stmac[6]; /* supplicant MAC               */
	unsigned char bssid[6]; /* authenticator MAC            */
	unsigned char snonce[32]; /* supplicant nonce             */
	unsigned char anonce[32]; /* authenticator nonce          */
	unsigned char keymic[20]; /* eapol frame MIC              */
	unsigned char eapol[256]; /* eapol frame contents         */
	unsigned char ptk[80]; /* pairwise transcient key      */
	unsigned eapol_size; /* eapol frame size             */
	unsigned long t_crc; /* last ToDS   frame CRC        */
	unsigned long f_crc; /* last FromDS frame CRC        */
	int32_t keyver, valid_ptk;
	unsigned char pn[6]; /* Packet Number (WPA-CCMP) */
};

struct Michael
{
	unsigned long key0;
	unsigned long key1;
	unsigned long left;
	unsigned long right;
	unsigned long nBytesInM;
	unsigned long message;
	unsigned char mic[8];
};

/* Used for own RC4 implementation */
struct rc4_state
{
	int32_t x, y, m[256];
};

struct AP_info;
const unsigned char ZERO[33] = "\x00\x00\x00\x00\x00\x00\x00\x00"
							   "\x00\x00\x00\x00\x00\x00\x00\x00"
							   "\x00\x00\x00\x00\x00\x00\x00\x00"
							   "\x00\x00\x00\x00\x00\x00\x00\x00";
void calc_pmk(char * key, char * essid, unsigned char pmk[40]);
int32_t decrypt_wep(unsigned char * data, int32_t len, unsigned char * key, int32_t keylen);
int32_t encrypt_wep(unsigned char * data, int32_t len, unsigned char * key, int32_t keylen);
int32_t check_crc_buf(unsigned char * buf, int32_t len);
int32_t calc_crc_buf(unsigned char * buf, int32_t len);
void calc_mic(struct AP_info * ap,
			  unsigned char * pmk,
			  unsigned char * ptk,
			  unsigned char * mic);
int32_t known_clear(
	void * clear, int32_t * clen, int32_t * weight, unsigned char * wh, size_t len);
int32_t add_crc32(unsigned char * data, int32_t length);
int32_t add_crc32_plain(unsigned char * data, int32_t length);
int32_t is_ipv6(void * wh);
int32_t is_dhcp_discover(void * wh, size_t len);
int32_t is_qos_arp_tkip(void * wh, int32_t len);
int32_t calc_tkip_ppk(unsigned char * h80211,
		          int32_t caplen,
				  unsigned char TK1[16],
				  unsigned char key[16]);
void encrypt_tkip(unsigned char * h80211, int32_t caplen, unsigned char PTK[80]);
int32_t decrypt_tkip(unsigned char * h80211, int32_t caplen, unsigned char TK1[16]);
int32_t encrypt_ccmp(unsigned char * h80211,
		         int32_t caplen,
				 unsigned char TK1[16],
				 unsigned char PN[6]);
int32_t decrypt_ccmp(unsigned char * h80211, int32_t caplen, unsigned char TK1[16]);
int32_t calc_ptk(struct WPA_ST_info * wpa, unsigned char pmk[32]);
int32_t calc_tkip_mic(unsigned char * packet,
		          int32_t length,
				  unsigned char ptk[80],
				  unsigned char value[8]);
int32_t michael_test(unsigned char key[8],
				 unsigned char * message,
				 int32_t length,
				 unsigned char out[8]);
int32_t calc_tkip_mic_key(unsigned char * packet, int32_t length, unsigned char key[8]);

extern const unsigned long int crc_tbl[256];
extern const unsigned char crc_chop_tbl[256][4];

#endif /* crypto.h */
