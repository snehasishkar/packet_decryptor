/*
 * decrypt_packet.cpp
 *
 *  Created on: 20-May-2019
 *      Author: saurabh
 */
#include "../include/decrypt_packet.h"

struct decap_stats stats;
static struct WPA_ST_info *st_cur_list[100];
static int32_t eapol_count = 0;
/* this routine handles to 802.11 to Ethernet translation */

static int8_t write_packet(FILE * f_out, struct pcap_pkthdr * pkh, unsigned char * h80211, unsigned char buffer[])
{
	int n;
	unsigned char arphdr[12];
	int qosh_offset = 0;

	if (buffer != h80211) memcpy(buffer, h80211, pkh->caplen);
	else
	{
		/* create the Ethernet link layer (MAC dst+src) */

		switch (h80211[1] & 3)
		{
			case 0: /* To DS = 0, From DS = 0: DA, SA, BSSID */

				memcpy(arphdr + 0, h80211 + 4, sizeof(arphdr) / 2);
				memcpy(arphdr + 6, h80211 + 10, sizeof(arphdr) / 2);
				break;

			case 1: /* To DS = 1, From DS = 0: BSSID, SA, DA */

				memcpy(arphdr + 0, h80211 + 16, sizeof(arphdr) / 2);
				memcpy(arphdr + 6, h80211 + 10, sizeof(arphdr) / 2);
				break;

			case 2: /* To DS = 0, From DS = 1: DA, BSSID, SA */

				memcpy(arphdr + 0, h80211 + 4, sizeof(arphdr) / 2);
				memcpy(arphdr + 6, h80211 + 16, sizeof(arphdr) / 2);
				break;

			default: /* To DS = 1, From DS = 1: RA, TA, DA, SA */

				memcpy(arphdr + 0, h80211 + 16, sizeof(arphdr) / 2);
				memcpy(arphdr + 6, h80211 + 24, sizeof(arphdr) / 2);
				break;
		}

		/* check QoS header */
		if (GET_SUBTYPE(h80211[0]) == IEEE80211_FC0_SUBTYPE_QOS)
		{
			qosh_offset += 2;
		}

		/* remove the 802.11 + LLC header */

		if ((h80211[1] & 3) != 3)
		{
			pkh->len -= 24 + qosh_offset + 6;
			pkh->caplen -= 24 + qosh_offset + 6;

			/* can overlap */
			memmove(buffer + 12, h80211 + qosh_offset + 30, pkh->caplen);
		}
		else
		{
			pkh->len -= 30 + qosh_offset + 6;
			pkh->caplen -= 30 + qosh_offset + 6;

			memmove(buffer + 12, h80211 + qosh_offset + 36, pkh->caplen);
		}

		memcpy(buffer, arphdr, 12);

		pkh->len += 12;
		pkh->caplen += 12;
	}

	n = sizeof(struct pcap_pkthdr);

	if (fwrite(pkh, 1, n, f_out) != (size_t) n)
	{
		vipl_printf("error: fwrite(packet header) failed", error_lvl, __FILE__, __LINE__);
		return 1;
	}

	n = pkh->caplen;

	if (fwrite(buffer, 1, n, f_out) != (size_t) n)
	{
		vipl_printf("error: fwrite(packet data) failed", error_lvl, __FILE__, __LINE__);
		return 1;
	}

	return 0;
}

static int station_compare(const void * a, const void * b)
{
	return memcmp(a, b, 6);
}
int8_t decrypt_packet(struct access_point *ap, int32_t len, char* pcap_filename, const char *homedir){
	FILE *f_in, *f_out;
	unsigned magic;
	char *s, buf[128]={0x00};
	unsigned char buffer[65536]={0x00};
	int32_t n, linktype;
	unsigned z;
	unsigned long crc;
	unsigned char * h80211;
	struct pcap_file_header pfh;
	struct pcap_pkthdr pkh;
	struct WPA_ST_info * st_cur;
	unsigned char bssid[6], stmac[6];
	unsigned char pmk[40]={0x00};
	time_t tt;
	c_avl_tree_t * stations = c_avl_create(station_compare);
	for(int32_t i=0; i<len; i++){
		f_in = fopen(pcap_filename, "rb");
		if(f_in==NULL){
			vipl_printf("error: pcap file not found", error_lvl, __FILE__, __LINE__);
			return 1;
		}
		n = sizeof(pfh);
		if(fread(&pfh, 1, n, f_in) != (size_t) n){
			vipl_printf("error: reading pcap file header failed", error_lvl, __FILE__, __LINE__);
			return 1;
		}
		if (pfh.magic != TCPDUMP_MAGIC && pfh.magic != TCPDUMP_CIGAM)
		{
			vipl_printf("error: not a pcap file (expected TCPDUMP_MAGIC)", error_lvl, __FILE__, __LINE__);
			return 1;
		}
		if ((magic = pfh.magic) == TCPDUMP_CIGAM) SWAP32(pfh.linktype);

		if (pfh.linktype != LINKTYPE_IEEE802_11
			&& pfh.linktype != LINKTYPE_PRISM_HEADER
			&& pfh.linktype != LINKTYPE_RADIOTAP_HDR
			&& pfh.linktype != LINKTYPE_PPI_HDR)
		{
			vipl_printf("error: not a regular 802.11 (wireless) capture", error_lvl, __FILE__, __LINE__);
			return 1;
		}

		linktype = pfh.linktype;
		pfh.magic = TCPDUMP_MAGIC;
		pfh.version_major = PCAP_VERSION_MAJOR;
		pfh.version_minor = PCAP_VERSION_MINOR;
		pfh.thiszone = 0;
		pfh.sigfigs = 0;
		pfh.snaplen = 65535;
		pfh.linktype = LINKTYPE_IEEE802_11;

		n = sizeof(pfh);
		memset(pmk, 0x00, 40);
		calc_pmk(ap[i].password, ap[i].essid, pmk);   //calculate PMK
		char out_path[100];
		clock_t start = clock();
		sprintf(out_path, "%s/wpcap/wifidump%lu.pcap", homedir, (unsigned long)start);
		f_out = fopen(out_path, "wb+");
	    if(f_out==NULL){
	    	vipl_printf("error: fopen failed", error_lvl, __FILE__, __LINE__);
	    	return 1;
	    }
	    if (fwrite(&pfh, 1, n, f_out) != (size_t) n){
	    	vipl_printf("error: fwrite(pcap file header) failed", error_lvl, __FILE__, __LINE__);
	    	return 1;
	    }
	    memset(&stats, 0, sizeof(stats));
	    tt = time(NULL);
	    //deciphering packet
	    int l=0;
	    while(1){
	    	if (time(NULL) - tt > 0)
	    	{
	    		/* update the status line every second */

	    		//erase_line(0);
	    		printf("Read %lu packets...\r", stats.nb_read);
	    		fflush(stdout);
	    		tt = time(NULL);
	    	}
	    	/* read one packet */

	    	n = sizeof(pkh);
	    	if (fread(&pkh, 1, n, f_in) != (size_t) n) break;

	    	if (magic == TCPDUMP_CIGAM){
	    		SWAP32(pkh.caplen);
	    		SWAP32(pkh.len);
	    	}
	    	n = pkh.caplen;

	    	if (n<=0 || n>65535){
	    		char msg[300]={0x00};
	    		sprintf(msg, "error: Corrupted pcap file? Invalid packet length %d", n);
	    		vipl_printf(msg, error_lvl, __FILE__, __LINE__);
	    		break;
	    	}
	    	if (fread(buffer, 1, n, f_in) != (size_t) n)
	    		break;
	    	stats.nb_read++;
	    	h80211 = buffer;
	    	if (linktype == LINKTYPE_PRISM_HEADER){
	    		/* remove the prism header */
	    		if (h80211[7] == 0x40)
	    			n = 64; /* prism54 */
	    		else
	    		{
	    			n = *(int *) (h80211 + 4);

	    			if (magic == TCPDUMP_CIGAM) SWAP32(n);
	    		}

	    		if (n<8 || n>=(int) pkh.caplen) continue;

	    		h80211 += n;
	    		pkh.caplen -= n;
	    	}
	    	if (linktype == LINKTYPE_RADIOTAP_HDR){
	    		/* remove the radiotap header */
	    		n = *(unsigned short *) (h80211 + 2);

	    		if (n<=0 || n>=(int) pkh.caplen) continue;

	    		h80211 += n;
	    		pkh.caplen -= n;
	    	}
	    	if (linktype == LINKTYPE_PPI_HDR){
	    		/* Remove the PPI header */
	    		n = le16_to_cpu(*(unsigned short *) (h80211 + 2));

	    		if (n<=0 || n>=(int) pkh.caplen) continue;

	    		/* for a while Kismet logged broken PPI headers */
	    		if (n==24 && le16_to_cpu(*(unsigned short *) (h80211 + 8)) == 2)
	    			n = 32;

	    		if (n <= 0 || n >= (int) pkh.caplen) continue;

	    		h80211 += n;
	    		pkh.caplen -= n;
	    	}
	    	/* remove the FCS if present (madwifi) */

	    	if (check_crc_buf(h80211, pkh.caplen - 4) == 1)
	    	{
	    		pkh.len -= 4;
	    		pkh.caplen -= 4;
	    	}

	    	/* check if data */

	    	if ((h80211[0] & 0x0C) != 0x08) continue;

	    	/* check minimum size */

	    	z = ((h80211[1] & 3) != 3) ? 24 : 30;

	    	if (z + 16 > pkh.caplen) continue;

	    	/* check QoS header */
	    	if (GET_SUBTYPE(h80211[0]) == IEEE80211_FC0_SUBTYPE_QOS)
	    	{
	    		z += 2;
	    	}
	    	/* check the BSSID */

	    	switch (h80211[1] & 3)
	    	{
	    		case 0:
	    			memcpy(bssid, h80211 + 16, sizeof(bssid));
	    			break; // Adhoc
	    		case 1:
	    			memcpy(bssid, h80211 + 4, sizeof(bssid));
	    			break; // ToDS
	    		case 2:
	    			memcpy(bssid, h80211 + 10, sizeof(bssid));
	    			break; // FromDS
	    		case 3:
	    			memcpy(bssid, h80211 + 10, sizeof(bssid));
	    			break; // WDS -> Transmitter taken as BSSID
	    	}

	    	/* locate the station's MAC address */

	    	switch (h80211[1] & 3)
	    	{
	    		case 1:
	    			memcpy(stmac, h80211 + 10, sizeof(stmac));
	    			break;
	    		case 2:
	    			memcpy(stmac, h80211 + 4, sizeof(stmac));
	    			break;
	    		case 3:
	    			memcpy(stmac, h80211 + 10, sizeof(stmac));
	    			break;
	    		default:
	    			continue;
	    	}
	    	int not_found = c_avl_get(stations, stmac, (void **) &st_cur);

	    	/* if it's a new station, add it */

	    	if (not_found){
	    		if (!(st_cur
	    			  = (struct WPA_ST_info *) malloc(sizeof(struct WPA_ST_info))))
	    		{
	    			//perror("malloc failed");
	    			break;
	    		}

	    		memset(st_cur, 0, sizeof(struct WPA_ST_info));

	    		memcpy(st_cur->stmac, stmac, sizeof(st_cur->stmac));
	    		memcpy(st_cur->bssid, bssid, sizeof(st_cur->bssid));
	    		c_avl_insert(stations, st_cur->stmac, st_cur);
	    		stats.nb_stations++;
	    	}

	    	/* check if we haven't already processed this packet */

	    	crc = calc_crc_buf(h80211 + z, pkh.caplen - z);

			if ((h80211[1] & 3) == 2)
			{
				if (st_cur->t_crc == crc) continue;

				st_cur->t_crc = crc;
			}
			else
			{
				if (st_cur->f_crc == crc) continue;

				st_cur->f_crc = crc;
			}
			/* check the SNAP header to see if data is encrypted *
			 * as unencrypted data begins with AA AA 03 00 00 00 */

			if (h80211[z] != h80211[z + 1] || h80211[z + 2] != 0x03){
				/* check the extended IV flag */
                if ((h80211[z + 3] & 0x20) == 0){
                	stats.nb_wep++;
                	continue;
                }
                else{
                	stats.nb_wpa++;
                	/* if the PTK is valid, try to decrypt */
                	if(eapol_count==0)
                		continue;
                	bool cont = false;
                	for(int j=0; j<eapol_count; j++){
                		 st_cur_list[j]->valid_ptk = calc_ptk(st_cur_list[j], pmk);
                		 if (!st_cur_list[j]->valid_ptk){
                			 cont = true;
                			 continue;
                		 }
                		 if (st_cur_list[j]->keyver == 1)
                		 {
                			int32_t rtval1 = decrypt_tkip(h80211, pkh.caplen, st_cur_list[j]->ptk + 32);
                			if(rtval1==0){
                				stats.nb_failed_tkip++;
                				cont = true;
                				continue;
                			}
                			else{
                				cont = false;
                				break;
                			}

                		 	pkh.len -= 20;
                		 	pkh.caplen -= 20;
                		 }
                		 else if (st_cur_list[j]->keyver == 2)
                		 {
                			int32_t rtval2 = decrypt_ccmp(h80211, pkh.caplen, st_cur_list[j]->ptk + 32);
                			if(rtval2==0){
                				stats.nb_failed_ccmp++;
                				cont = true;
                				continue;
                			}
                			else{
                				cont = false;
                				break;
                			}

                		 	pkh.len -= 16;
                		 	pkh.caplen -= 16;
                		 }
                		 else
                		 {
                		 	char msg[200]={0x00};
                		 	sprintf(msg, "error: unsupported keyver: %d\n", st_cur_list[j]->keyver);
                		 	vipl_printf(msg, error_lvl, __FILE__, __LINE__);
                		 	cont = true;
                		 	continue;
                		 }
                	}

                    if(cont==true)
                    	continue;

                    /* WPA data packet was successfully decrypted, *
                     * remove the WPA Ext.IV & MIC, write the data */

                    if (pkh.caplen > z)
                    {
                    	/* can overlap */
                    	memmove(h80211 + z, h80211 + z + 8, pkh.caplen - z);
                    }
                    else
                    {
                    	/* overflow */
                    	continue;
                    }

                    stats.nb_unwpa++;

                    h80211[1] &= 0xBF;

                    if (write_packet(f_out, &pkh, h80211, buffer) != 0) break;
                }
			}
			else{
				z += 6;
				if (h80211[z] != 0x88 || h80211[z + 1] != 0x8E){
					stats.nb_plain++;
					continue;
				}
				z += 2;

				/* type == 3 (key), desc. == 254 (WPA) or 2 (RSN) */

				if (h80211[z + 1] != 0x03
					|| (h80211[z + 4] != 0xFE && h80211[z + 4] != 0x02))
					continue;

				/* frame 1: Pairwise == 1, Install == 0, Ack == 1, MIC == 0 */

				if ((h80211[z + 6] & 0x08) != 0 && (h80211[z + 6] & 0x40) == 0
					&& (h80211[z + 6] & 0x80) != 0
					&& (h80211[z + 5] & 0x01) == 0)
				{
					/* set authenticator nonce */

					memcpy(st_cur->anonce, &h80211[z + 17], 32);
				}
				/* frame 2 or 4: Pairwise == 1, Install == 0, Ack == 0, MIC == 1 */

				if ((h80211[z + 6] & 0x08) != 0 && (h80211[z + 6] & 0x40) == 0
					&& (h80211[z + 6] & 0x80) == 0
					&& (h80211[z + 5] & 0x01) != 0)
				{
					if (memcmp(&h80211[z + 17], ZERO, 32) != 0)
					{
						/* set supplicant nonce */

						memcpy(st_cur->snonce, &h80211[z + 17], 32);
					}

					/* copy the MIC & eapol frame */

					st_cur->eapol_size = (h80211[z + 2] << 8) + h80211[z + 3] + 4;

					if (pkh.len - z < st_cur->eapol_size || st_cur->eapol_size == 0
						|| st_cur->eapol_size > sizeof(st_cur->eapol))
					{
						// Ignore the packet trying to crash us.
						st_cur->eapol_size = 0;
						continue;
					}

					memcpy(st_cur->keymic, &h80211[z + 81], 16);
					memcpy(st_cur->eapol, &h80211[z], st_cur->eapol_size);
					memset(st_cur->eapol + 81, 0, 16);

					/* copy the key descriptor version */

					st_cur->keyver = h80211[z + 6] & 7;
				}
				/* frame 3: Pairwise == 1, Install == 1, Ack == 1, MIC == 1 */

				if ((h80211[z + 6] & 0x08) != 0 && (h80211[z + 6] & 0x40) != 0
					&& (h80211[z + 6] & 0x80) != 0
					&& (h80211[z + 5] & 0x01) != 0)
				{
					if (memcmp(&h80211[z + 17], ZERO, 32) != 0)
					{
						/* set authenticator nonce */

						memcpy(st_cur->anonce, &h80211[z + 17], 32);
					}

					/* copy the MIC & eapol frame */

					st_cur->eapol_size = (h80211[z + 2] << 8) + h80211[z + 3] + 4;

					if (pkh.len - z < st_cur->eapol_size || st_cur->eapol_size == 0
						|| st_cur->eapol_size > sizeof(st_cur->eapol))
					{
						// Ignore the packet trying to crash us.
						st_cur->eapol_size = 0;
						continue;
					}

					memcpy(st_cur->keymic, &h80211[z + 81], sizeof(st_cur->keymic));
					memcpy(st_cur->eapol, &h80211[z], st_cur->eapol_size);
					memset(
						st_cur->eapol + 81,
						0,
						16); // where does this size come from? eapol is char[256]

					/* copy the key descriptor version */

					st_cur->keyver = h80211[z + 6] & 7;
				}

				st_cur->valid_ptk = calc_ptk(st_cur, pmk);
				st_cur_list[eapol_count] = (struct WPA_ST_info *) malloc(sizeof(struct WPA_ST_info));
				st_cur_list[eapol_count++] = st_cur;
			}
	    }
		//printf("count: %d  eapol size: %d\n", l, st_cur->eapol_size);
	    /* cleanup avl tree */
	    void *key, *value;
	    while (c_avl_pick(stations, &key, &value) == 0)
	    {
	    	free(value);
	    }
	    c_avl_destroy(stations);
	    fclose(f_out);
	    fclose(f_in);
	    char log[500]={0x00};
	    sprintf(log, "\nTotal number of stations seen     %8lu\n"
	    		   "Total number of packets read      %8lu\n"
	    		   "Total number of WEP data packets  %8lu\n"
	    		   "Total number of WPA data packets  %8lu\n"
	    		   "Number of plaintext data packets  %8lu\n"
	    		   "Number of decrypted WEP  packets  %8lu\n"
	    		   "Number of corrupted WEP  packets  %8lu\n"
	    		   "Number of decrypted WPA  packets  %8lu\n"
	    		   "Number of bad TKIP (WPA) packets  %8lu\n"
	    		   "Number of bad CCMP (WPA) packets  %8lu\n",
	    		   stats.nb_stations,
	    		   stats.nb_read,
	    		   stats.nb_wep,
	    		   stats.nb_wpa,
	    		   stats.nb_plain,
	    		   stats.nb_unwep,
	    		   stats.nb_bad,
	    		   stats.nb_unwpa,
	    		   stats.nb_failed_tkip,
	    		   stats.nb_failed_ccmp);
	    if(error_lvl==3)
	    	vipl_printf(log, error_lvl, __FILE__, __LINE__);
	}
}
