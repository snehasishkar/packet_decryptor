/*
 * decrypt_packet.h
 *
 *  Created on: 20-May-2019
 *      Author: saurabh
 */

#ifndef DECRYPT_PACKET_H_
#define DECRYPT_PACKET_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "vipl_printf.h"
#include "byteorder.h"
#include "crypto.h"
#include "pcap.h"
#include "common.h"

struct access_point{
	char essid[30];
	char password[20];
};

extern int32_t error_lvl;

struct decap_stats
{
	unsigned long nb_stations; /* # of stations seen */
	unsigned long nb_read; /* # of packets read       */
	unsigned long nb_wep; /* # of WEP data packets   */
	unsigned long nb_bad; /* # of bad data packets   */
	unsigned long nb_wpa; /* # of WPA data packets   */
	unsigned long nb_plain; /* # of plaintext packets  */
	unsigned long nb_unwep; /* # of decrypted WEP pkt  */
	unsigned long nb_unwpa; /* # of decrypted WPA pkt  */
	unsigned long nb_failed_tkip; /* # of failed WPA TKIP pkt decryptions */
	unsigned long nb_failed_ccmp; /* # of failed WPA CCMP pkt decryptions */
};
int8_t decrypt_packet(struct access_point *ap, int32_t len, char* pcap_filename, const char *homedir);
#endif /* DECRYPT_PACKET_H_ */
