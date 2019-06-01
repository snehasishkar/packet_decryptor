/*
 * common.h
 *
 *  Created on: 20-May-2019
 *      Author: saurabh
 */

#ifndef COMMON_H_
#define COMMON_H_

#include "eapol.h"
#include "aircrack-ptw-lib.h"
#include "avl_tree.h"
#define SWAP32(x)                                                              \
	x = (((x >> 24) & 0x000000FF) | ((x >> 8) & 0x0000FF00)                    \
		 | ((x << 8) & 0x00FF0000)                                             \
		 | ((x << 24) & 0xFF000000));
struct AP_info
{
	unsigned char bssid[6]; /* access point MAC address     */
	char essid[33]; /* access point identifier      */
	unsigned char lanip[4]; /* IP address if unencrypted    */
	unsigned char * ivbuf; /* table holding WEP IV data    */
	unsigned char ** uiv_root; /* IV uniqueness root struct    */
	long ivbuf_size; /* IV buffer allocated size     */
	long nb_ivs; /* total number of unique IVs   */
	long nb_ivs_clean; /* total number of unique IVs   */
	long nb_ivs_vague; /* total number of unique IVs   */
	int32_t crypt; /* encryption algorithm         */
	int32_t eapol; /* set if EAPOL is present      */
	int32_t target; /* flag set if AP is a target   */
	struct ST_info * st_1st; /* DEPRECATED: linked list of stations */
	c_avl_tree_t * stations; /* AVL tree of stations keyed on MAC*/
	struct WPA_hdsk wpa; /* valid WPA handshake data     */
	PTW_attackstate * ptw_clean;
	PTW_attackstate * ptw_vague;
};

struct ST_info
{
	struct AP_info * ap; /* parent AP                    */
	struct ST_info * next; /* DEPRECATED: next supplicant*/
	struct WPA_hdsk wpa; /* WPA handshake data          */
	unsigned char stmac[6]; /* client MAC address       */
};
#endif /* COMMON_H_ */
