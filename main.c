
/* lab_main - Starting point of server, establishes mempool and enables lcores and interfaces.
 * Copyright (C) 2016  Puneet Arora
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * puneet.arora@stud.tu-darmstadt.de, Technical University Darmstadt
 *
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <sys/types.h>
#include <errno.h>

#include <sys/queue.h>
#include <sys/stat.h>

#include <stdint.h>
#include <unistd.h>
#include <inttypes.h>

#include <rte_config.h>
#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_debug.h>
#include <rte_cycles.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_launch.h>
#include <rte_tailq.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_string_fns.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_jhash.h>

#define ETHDEV_ID	0
#define SNAPSHOT_BUF_SIZE	2*1024*1024	// 4MB


#include "../grt/grt_main.h"
#include "../grt/grt_redirect_table.h"
#include "../grt/grt_toolz.h"
grt_redirect_table* session_table;
grt_redirect_table* sessionRtn_table;
grt_redirect_table* ip_table;
grt_redirect_table* ip_free_table;


#define GRT_STUPD_TYPE_NEW_SESSIONENTRY		10
#define GRT_STUPD_TYPE_NEW_IPENTRY		11
#define GRT_STUPD_TYPE_NEW_SESSIONRTNENTRY	12
#define GRT_STUPD_TYPE_SESSION_UPDATE		13
#define GRT_STUPD_TYPE_IP_UPDATE		14
#define GRT_STUPD_TYPE_SESSIONRTN_UPDATE	15
#define GRT_STUPD_TYPE_NEW_IPFREENTRY		16

#include "pppoe.h"
#include "ippool.c"
#include "session.c"
#include "pppoe_dp.c"
#include "pppoe_auth.c"
#include "pppoeconfig.c"

pthread_mutex_t conn_lock;



int handle_snapshot_out() {

	grt_redirect_set_snap_state(session_table, GRT_RT_S_SNAPSHOTTING);
	grt_redirect_set_snap_state(sessionRtn_table, GRT_RT_S_SNAPSHOTTING);
	grt_redirect_set_snap_state(ip_table, GRT_RT_S_SNAPSHOTTING);
	grt_redirect_set_snap_state(ip_free_table, GRT_RT_S_SNAPSHOTTING);

	void* snapBuf = rte_zmalloc("SNAPSHOT_OUT_BUFFER", SNAPSHOT_BUF_SIZE, 0);
	void* snapBufOffsetMax = snapBuf + SNAPSHOT_BUF_SIZE;
	void* snapBufOffset = snapBuf;

	//if (DEBUG)
	//{
	void* offsetBefore = snapBufOffset;
	//}
	int retrn = grt_redirect_serialize_snapshot(session_table, &snapBufOffset, snapBufOffsetMax);

	retrn = grt_redirect_serialize_snapshot(sessionRtn_table, &snapBufOffset, snapBufOffsetMax);
	retrn = grt_redirect_serialize_snapshot(ip_table, &snapBufOffset, snapBufOffsetMax);
	retrn = grt_redirect_serialize_snapshot(ip_free_table, &snapBufOffset, snapBufOffsetMax);

	//Sending the buffered snapshot from here...

	grt_addDataToSnapshot(snapBuf, snapBufOffset-snapBuf);

	RTE_LOG(INFO, USER1, "Snapshot transfer finished.\n");
	rte_free(snapBuf);

	grt_redirect_set_snap_state(session_table, GRT_RT_S_IDLE);
	grt_redirect_set_snap_state(sessionRtn_table, GRT_RT_S_IDLE);
	grt_redirect_set_snap_state(ip_table, GRT_RT_S_IDLE);
	grt_redirect_set_snap_state(ip_free_table, GRT_RT_S_IDLE);

	return 0;
}

int handle_snapshot_in() {
	printf("[[I]] In handle_snapshot_in function...\n");

	int32_t iter = 0;
	int32_t return_val;
	int64_t next_timeout;
	void* snapBuf = rte_malloc("SNAPSHOT_IN_BUFFER", SNAPSHOT_BUF_SIZE, 0);
	ptrdiff_t snapSize = grt_getDataFromSnapshot(snapBuf, SNAPSHOT_BUF_SIZE);

	void* currentOffset = snapBuf;

	void* offsetBefore = currentOffset;
	int retrn = grt_redirect_deserialize_snapshot(session_table, &currentOffset);

	Session_key* next_key2;
	Session* next_value2;
	char ip_str_buf[20];
	char ether_addr_string[20];

	retrn = grt_redirect_deserialize_snapshot(sessionRtn_table, &currentOffset);

	retrn = grt_redirect_deserialize_snapshot(ip_table, &currentOffset);
	iter = 0;
	Ip_key* next_key3;
	Ip_value* next_value3;
	while (return_val = grt_redirect_iterate_snapshot(ip_table, (const void**)&next_key3, (void**)&next_value3, &next_timeout, &iter, 0) >= 0) {
		count_oct3 = next_value3->count_oct3;
    		count_oct4 = next_value3->count_oct4;
    		session_index = next_value3->session_index;
		printf("details %d .. %d .. %d", next_value3->count_oct3, next_value3->count_oct4, next_value3->session_index);
		break;
	}

	retrn = grt_redirect_deserialize_snapshot(ip_free_table, &currentOffset);

	RTE_LOG(INFO, USER1, "Snapshot received.\n");

	rte_free(snapBuf);

	return 0;
}

int handle_state_update(uint16_t type, void* stupd_vec, uint16_t len) {
	printf("[[I]] In handle_state_update function...\n");

	if (type == GRT_STUPD_TYPE_NEW_SESSIONENTRY) {

		grt_redirect_table_put_fromstupd(session_table, stupd_vec);
		return 1;
	}else if (type == GRT_STUPD_TYPE_NEW_SESSIONRTNENTRY) {

		grt_redirect_table_put_fromstupd(sessionRtn_table, stupd_vec);
		return 1;
	}else if (type == GRT_STUPD_TYPE_NEW_IPENTRY) {

		grt_redirect_table_put_fromstupd(ip_table, stupd_vec);
		return 1;
	} else if (type == GRT_STUPD_TYPE_SESSION_UPDATE) {

		grt_redirect_table_put_fromstupd(session_table, stupd_vec);
		return 1;
	} else if (type == GRT_STUPD_TYPE_SESSIONRTN_UPDATE) {

		grt_redirect_table_put_fromstupd(sessionRtn_table, stupd_vec);
		return 1;
	}else if (type == GRT_STUPD_TYPE_IP_UPDATE) {

		grt_redirect_table_put_fromstupd(ip_table, stupd_vec);
		return 1;
	} else if (type == GRT_STUPD_TYPE_NEW_IPFREENTRY) {

		grt_redirect_table_put_fromstupd(ip_free_table, stupd_vec);
		return 1;
	}else {
		//Unknown state update type
		rte_free(stupd_vec);
	}
	

	//printf("VNF got state update: type=%u, string='%s', len=%u\n", type, (char*)buf4Snapshots, lenOfBuf);
	return 0;
}

int prepare() {


}

int prepareInEAL() {
     static struct rte_hash_parameters defaultParamsSession = {
		.name = "GRT_SESSION_TABLE",
		.entries = 65536,
		.reserved = 0,
		.key_len = sizeof(Session_key),
		.hash_func = rte_jhash,
		.hash_func_init_val = 0,
		.socket_id = 0,
		.extra_flag = 0,
     };

     static struct rte_hash_parameters defaultParamsSessionRtn = {
		.name = "GRT_SESSIONRTN_TABLE",
		.entries = 65536,
		.reserved = 0,
		.key_len = sizeof(SessionRtn_key),
		.hash_func = rte_jhash,
		.hash_func_init_val = 0,
		.socket_id = 0,
		.extra_flag = 0,
     };

     static struct rte_hash_parameters defaultParamsIp = {
		.name = "GRT_IP_TABLE",
		.entries = 65536,
		.reserved = 0,
		.key_len = sizeof(Ip_key),
		.hash_func = rte_jhash,
		.hash_func_init_val = 0,
		.socket_id = 0,
		.extra_flag = 0,
     };
     
     static struct rte_hash_parameters defaultParamsIpFree = {
		.name = "GRT_IP_FREE_TABLE",
		.entries = 65536,
		.reserved = 0,
		.key_len = sizeof(Ip_free_key),
		.hash_func = rte_jhash,
		.hash_func_init_val = 0,
		.socket_id = 0,
		.extra_flag = 0,
     }; 

     session_table = grt_redirect_table_create(&defaultParamsSession, sizeof(Session_key), sizeof(Session));
     sessionRtn_table = grt_redirect_table_create(&defaultParamsSessionRtn, sizeof(SessionRtn_key), sizeof(SessionRtn));
     ip_table = grt_redirect_table_create(&defaultParamsIp, sizeof(Ip_key), sizeof(Ip_value));
     ip_free_table = grt_redirect_table_create(&defaultParamsIpFree, sizeof(Ip_free_key), sizeof(Ip_free_value));
     printf("[[I]] Table created successfully...\n");

     //initializing the receive side ring
     init_ring();

     //read configuration parameters from config file
     read_config();

     pthread_t s_tid;
     int error;
     if (pthread_mutex_init(&conn_lock, NULL) != 0)
     {
         if (DEBUG)
         {
             RTE_LOG(INFO, USER1, "=> Mutex init failed\n");
         }
         return 1;
     }

     error = pthread_create(&s_tid, NULL, &check_and_free_session, NULL);
     if (error != 0 && DEBUG)
     {
         RTE_LOG(INFO, USER1, "=> Session thread creation failed\n");
     }
}


int main(int argc, char **argv)
{
	prepare();

	grt_main(argc, argv, &prepareInEAL, &handle_packet, &handle_snapshot_out, &handle_snapshot_in, &handle_state_update);
}
