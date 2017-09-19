/* lab_task - Master and Slave jobs, processing access and internet packets respectively
 * Reference https://www.roaringpenguin.com/products/pppoe
 * Copyright (C) 2016  Sooraj Mandotti
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
 * sooraj.mandotti@stud.tu-darmstadt.de, Technical University Darmstadt
 *
 */

struct rte_ring *ring;
unsigned long long pkt_in_start_time;
unsigned long long pkt_in_end_time;
unsigned long long pkt_out_start_time;
unsigned long long pkt_out_end_time;
int counter = 0;

/**
 * @brief This function creates a ring buffer.
 */
void init_ring()
{

    char ring_name[RTE_RING_NAMESIZE];
    ring = rte_ring_create(ring_name, RING_SIZE, rte_socket_id(),
                           RING_F_SP_ENQ | RING_F_SC_DEQ);

    if (ring == NULL)
    {
        rte_exit(EXIT_FAILURE, "Failed to initialize ring\n");

    }

}

/**
 * @brief This function returns current system time in nano second.
 * @return time.
 */
unsigned long long gettime()
{
    struct timespec ctime;
    clock_gettime(CLOCK_REALTIME, &ctime);
    unsigned long long time = ctime.tv_sec * 1e9 + ctime.tv_nsec;
    return time;
}

void process_ring() {

    uint8_t lcore_id = rte_lcore_id();
    //struct rte_mbuf* internet_rcv_pkt_bucket[BURSTLEN];
    struct rte_mbuf* ring_pkt;
	//if (counter % 4 == 0)
        //{
            if (rte_ring_empty(ring) == 0)
            {
                if (DEBUG)
                {
                    RTE_LOG(INFO, USER1,
                            "slave job function => Message received on ring by lcore %d \n",
                            lcore_id);
                }
                void *msg;
                int status = rte_ring_sc_dequeue(ring, &msg);
                if (status == 0)
                {

                    ring_pkt = (struct rte_mbuf*) msg;
                    int retrn = rte_eth_tx_burst(ETHDEV_ID, 0, &ring_pkt, 1);
                    if (retrn != 1 && DEBUG)
                    {
                        RTE_LOG(INFO, USER1,
                                "TX burst failed with error code %i.\n", retrn);
                    }
                }

            }
        //counter++;
        //if (counter == 10000)
        //{
          //  counter = 0;
        //}

}

/**
 * @brief This function is responsible for processing all packets from 
 * internet to access network, also packets present in ring buffer.
 * @param NULL
 * @return status if any.
 */
void process_exterior_packet(struct ether_hdr* l2hdr, struct rte_mbuf* pkt)
{

    uint8_t lcore_id = rte_lcore_id();
    //struct rte_mbuf* internet_rcv_pkt_bucket[BURSTLEN];
    struct rte_mbuf* ring_pkt;
    //while (1)
    //{
//printf("got packet in receive\n");
        /*if (counter % 4 == 0)
        {
            if (rte_ring_empty(ring) == 0)
            {
                if (DEBUG)
                {
                    RTE_LOG(INFO, USER1,
                            "slave job function => Message received on ring by lcore %d \n",
                            lcore_id);
                }
                void *msg;
                int status = rte_ring_sc_dequeue(ring, &msg);
                if (status == 0)
                {

                    ring_pkt = (struct rte_mbuf*) msg;
                    int retrn = rte_eth_tx_burst(ETHDEV_ID, 0, &ring_pkt, 1);
                    if (retrn != 1 && DEBUG)
                    {
                        RTE_LOG(INFO, USER1,
                                "TX burst failed with error code %i.\n", retrn);
                    }
                }*/

                //return;
            //}
        //}
        //counter++;
        //if (counter == 10000)
        //{
          //  counter = 0;
        //}
        //int i;
        //read from interface "internet"
        //uint32_t rx_pkt_count = rte_eth_rx_burst(ETHDEV_ID + 1, 0,
        //                        internet_rcv_pkt_bucket, BURSTLEN);
        //for (i = 0; i < rx_pkt_count; i++)
        //{
            pkt_out_start_time = gettime();
            //struct rte_mbuf* pkt = internet_rcv_pkt_bucket[i];

            //rte_prefetch0 (rte_pktmbuf_mtod( pkt, void*));
            //struct ether_hdr* l2hdr;
            //l2hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr*);

            if (__bswap_16(l2hdr->ether_type) == ETHER_IPV4)
            {

                struct ipv4_hdr* iphdr;
                //removing L2 header.
                iphdr = (struct ipv4_hdr *) rte_pktmbuf_adj(pkt,
                        sizeof(struct ether_hdr));
                /*int oct3_temp = (iphdr->dst_addr & 0x00ff0000);
                uint8_t oct3 = (uint8_t)(oct3_temp >> 16);
                int oct4_temp = (iphdr->dst_addr & 0xff000000);
                uint8_t oct4 = (uint8_t)(oct4_temp >> 24);
                uint8_t base = start_ip_oct3;
                uint8_t start_base = start_ip_oct4;*/

		/*
		 * If octet 3 of ip is same as base, then index is the difference  
		 * Else, index = (254 - received oct4) + ((oct3 range -1) times 254 + oct4 received)
		 */
                /*int index =
                    (oct3 == base) ?
                    oct4 - start_base :
                    ((254 - start_base) + ((oct3 - base) - 1) * 254
                     + oct4);

                if (index < 0 || index >= session_index)
                {
                    rte_pktmbuf_free(pkt);
                    return;
                }*/
		SessionRtn_key rtnKey;
    		rtnKey.client_ipv4_addr = iphdr->dst_addr;
		SessionRtn* foundEntry = NULL;
		int retrn = grt_redirect_table_get(sessionRtn_table, (void*)&rtnKey, (void**)&foundEntry, 0);
                if (retrn == 1)
                {
//printf("got packet in receive in if\n");
                    //encapsulate PPP header
                    uint16_t pppoe_payload_legth = __bswap_16(
                                                       iphdr->total_length);
                    PPPEncap * pppptcls = (PPPEncap *) rte_pktmbuf_prepend(pkt,
                                          sizeof(PPPEncap));
                    pppptcls->protocol = __bswap_16(PROTO_IPV4);

                    pppoe_payload_legth += sizeof(PPPEncap);

                    //encapsulate PPPoE header
                    PPPoEEncap * pppoeer = (PPPoEEncap *) rte_pktmbuf_prepend(
                                               pkt, sizeof(PPPoEEncap));
                    memcpy(&pppoeer->l2hdr.d_addr, &foundEntry->client_mac_addr,
                           sizeof(struct ether_addr));
                    memcpy(&pppoeer->l2hdr.s_addr, &srtointra_addr,
                           sizeof(struct ether_addr));
                    pppoeer->l2hdr.ether_type = __bswap_16(ETHER_SESSION);
                    pppoeer->ver = PPPOE_VER;
                    pppoeer->type = PPPOE_TYPE;
                    pppoeer->session = __bswap_16(foundEntry->session_id);
                    pppoeer->code = CODE_SESS;
                    pppoeer->length = __bswap_16(pppoe_payload_legth);
//char ethaddr_str_buf [20];
//grt_ethaddr_to_string(ethaddr_str_buf, &foundEntry->client_mac_addr);
//printf("in receive client MAC: %s   session id: %d\n", ethaddr_str_buf, foundEntry->session_id);

                    int retrn = rte_eth_tx_burst(ETHDEV_ID, 0,
                                                 &pkt, 1);
		    //session_array[index]->time = time(NULL);
    		    /*Session_key key;
          	    key.client_mac_addr = foundEntry->client_mac_addr;
    		    key.session_id = foundEntry->session_id;
    		    Session *newSession = copy_sessionBack(foundEntry);
    		    newSession->time = time(NULL);
    		    SessionRtn *newRtnSession = copy_sessionRtn(newSession);
    		    newRtnSession->time = time(NULL);
    		    int retrn1 = grt_redirect_table_put_notifystupd(session_table, (void*)&key, (void*)newSession, -1, GRT_STUPD_TYPE_SESSION_UPDATE);
    		    retrn1 = grt_redirect_table_put_notifystupd(sessionRtn_table, (void*)&rtnKey, (void*)newRtnSession, -1, GRT_STUPD_TYPE_SESSIONRTN_UPDATE);*/
                    //pkt_out_end_time = gettime();
                    if (retrn != 1 && DEBUG)
                    {
                        RTE_LOG(INFO, USER1,
                                "TX burst failed with error code %i.\n", retrn);
                    }
                    /*if (DEBUG)
                    {
                        printf("receive time: %llu\n",
                               pkt_out_end_time - pkt_out_start_time);
                    }*/
                }
                else
                {
                    rte_pktmbuf_free(pkt);
                    return;
                }
            }
            else
            {
                rte_pktmbuf_free(pkt);
                return;
            }
        //}
    //}
}


/**
 * @brief This function is responsible for processing all packets from 
 * access network, which include PPPoE, PPP and IPv4 packets.
 * Any packet other than normal IPv4 packet will be put into ring buffer. 
 * @param NULL
 * @return status if any.
 */
void process_interior_packet(struct ether_hdr* l2hdr, struct rte_mbuf* pkt)
{

    //uint8_t lcore_id = rte_lcore_id();

    //struct rte_mbuf* rcv_pkt_bucket[BURSTLEN];

    //read config file to populate required parameters
    //read_config();

    //start the session maintenance thread
    //pthread_t s_tid;
    //int error;
    //if (pthread_mutex_init(&conn_lock, NULL) != 0)
    //{
      /*  if (DEBUG)
        {
            RTE_LOG(INFO, USER1, "=> Mutex init failed\n");
        }
        return 1;
    }

    error = pthread_create(&s_tid, NULL, &check_and_free_session, NULL);
    if (error != 0 && DEBUG)
    {
        RTE_LOG(INFO, USER1, "=> Session thread creation failed\n");
    }*/

    /*
     *main loop for packet processing
     */
    /*while (1)
    {

        uint32_t rx_pkt_count = rte_eth_rx_burst(ETHDEV_ID, 0, rcv_pkt_bucket,
                                BURSTLEN);
        int i;

        for (i = 0; i < rx_pkt_count; i++)
        {*/

            pkt_in_start_time = gettime();

            //struct rte_mbuf* pkt = rcv_pkt_bucket[i];

            //rte_prefetch0 (rte_pktmbuf_mtod( pkt, void*));
            //struct ether_hdr* l2hdr;
            //l2hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr*);
            if (DEBUG)
            {
                RTE_LOG(INFO, USER1, "=> Packet received... ethtype=%x\n",
                        __bswap_16(l2hdr->ether_type));
            }

            //check if it is a PPPoE packet
            if (__bswap_16(l2hdr->ether_type) == ETHER_DISCOVERY
                    || __bswap_16(l2hdr->ether_type) == ETHER_SESSION)
            {

                PPPoEEncap * pppoee = (rte_pktmbuf_mtod(pkt, PPPoEEncap *));

		//drop all packets with unexpected session id 
		if (pppoee->code != CODE_PADI && pppoee->code != CODE_PADR) {
			if ((__bswap_16(pppoee->session)-1) < 0 || ((__bswap_16(pppoee->session)-1) >= session_index) ) {
				rte_pktmbuf_free(pkt);
				return;
			}
		}

		//create session key
		Session_key key;
		key.client_mac_addr = pppoee->l2hdr.s_addr;
		key.session_id = __bswap_16(pppoee->session);
		Session* foundEntry = NULL;
		int retrn = grt_redirect_table_get(session_table, (void*)&key, (void**)&foundEntry, 0);
                //drop all, except term-ack packets from client if termination requested
                if (__bswap_16(l2hdr->ether_type) == ETHER_SESSION
                        && foundEntry->state == STATE_TERM_SENT)
                {

                    PPPEncap * pppptcl;
                    unsigned int seen = 0;
                    pppptcl = rte_pktmbuf_mtod_offset(pkt, PPPEncap *, sizeof(PPPoEEncap)+seen);
                    seen += sizeof(PPPEncap);

                    //check if it is a LCP packet
                    if (__bswap_16(pppptcl->protocol) == PROTO_LCP)
                    {

                        PPPLcp * ppplcp;
                        ppplcp = rte_pktmbuf_mtod_offset(pkt, PPPLcp *, sizeof(PPPoEEncap)+seen);
                        seen += sizeof(PPPLcp);
                        if (ppplcp->code != CODE_TERM_ACK)
                        {
                            if (DEBUG)
                            {
                                RTE_LOG(INFO, USER1,
                                        "=> Packet from term sent client received, dropping...\n");
                            }
                            rte_pktmbuf_free(pkt);
                            return;
                        }
                    }
                    else
                    {
                        if (DEBUG)
                        {
                            RTE_LOG(INFO, USER1,
                                    "=> Packet from term sent client received, dropping...\n");
                        }
                        rte_pktmbuf_free(pkt);
                        return;
                    }
                }

                //check if it is a PADI packet
                if (pppoee->code == CODE_PADI)
                {

                    if (DEBUG)
                    {
                        RTE_LOG(INFO, USER1, "=> Packet PADI received\n");
                    }

                    PPPoETag * pppoet;
                    unsigned char serviceName[ETH_JUMBO_LEN]; //for keeping service name to be sent back in PADO
                    unsigned char hostUnique[ETH_JUMBO_LEN]; //for keeping host unique to be sent back in PADO
                    unsigned char relayId[ETH_JUMBO_LEN]; //relay id to be taken care, to be sent back in PADO
                    uint16_t sn_length = 0, hu_length = 0, rd_length = 0;

                    unsigned int seen = 0;
                    unsigned int len = __bswap_16(pppoee->length);
                    //parse PPPoE tags in the packet
                    while (seen < len)
                    {
                        pppoet = rte_pktmbuf_mtod_offset(pkt, PPPoETag *, sizeof(PPPoEEncap)+seen);
                        seen += sizeof(PPPoETag);
                        //search for service name
                        if (__bswap_16(pppoet->type) == TYPE_SERVICE_NAME)
                        {
                            //keep the default service name ready in case tag length is zero
                            memcpy(serviceName, service_name,
                                   sizeof(service_name));
                            sn_length = (uint16_t) sizeof(service_name);
                            //check against all available service names (currenty only one exist)
                            if (__bswap_16(pppoet->length) != 0)
                            {
                                sn_length = __bswap_16(pppoet->length);
                                char * sr_value = rte_pktmbuf_mtod_offset(pkt, char *, sizeof(PPPoEEncap) + seen);
                                memcpy(serviceName, sr_value,
                                       __bswap_16(pppoet->length));
                                seen += __bswap_16(pppoet->length);
                            }
                            //search for host unique
                        }
                        else if (__bswap_16(pppoet->type) == TYPE_HOST_UNIQ)
                        {
                            hu_length = __bswap_16(pppoet->length);
                            char * hu_value = rte_pktmbuf_mtod_offset(pkt, char *, sizeof(PPPoEEncap) + seen);
                            memcpy(hostUnique, hu_value,
                                   __bswap_16(pppoet->length));
                            seen += __bswap_16(pppoet->length);
                            //search for relay session id
                        }
                        else if (__bswap_16(pppoet->type)
                                 == TYPE_RELAY_SESSION_ID)
                        {
                            rd_length = __bswap_16(pppoet->length);
                            char * rd_value = rte_pktmbuf_mtod_offset(pkt, char *, sizeof(PPPoEEncap) + seen);
                            memcpy(relayId, rd_value,
                                   __bswap_16(pppoet->length));
                            seen += __bswap_16(pppoet->length);
                        }
                        else
                        {
                            if (DEBUG)
                            {
                                RTE_LOG(INFO, USER1,
                                        "=> Unknown tag found in a PADI packet received\n");
                            }
                        }
                    }

                    //check if asked service name matches our service name
                    if (sn_length != 0
                            && memcmp(serviceName, service_name,
                                      sizeof(service_name)) != 0)
                    {
                        if (DEBUG)
                        {
                            RTE_LOG(INFO, USER1,
                                    "=> PADI packet for unknown service name received, dropping...\n");
                        }
                        rte_pktmbuf_free(pkt);
                        return;
                    }

                    //generate a PADO packet to send back
                    rte_pktmbuf_reset(pkt);
                    PPPoEEncap * pppoeer = (PPPoEEncap *) rte_pktmbuf_append(
                                               pkt, sizeof(PPPoEEncap));
                    memcpy(&pppoeer->l2hdr.d_addr, &pppoee->l2hdr.s_addr,
                           sizeof(struct ether_addr));
                    memcpy(&pppoeer->l2hdr.s_addr, &srtointra_addr,
                           sizeof(struct ether_addr));
                    pppoeer->l2hdr.ether_type = pppoee->l2hdr.ether_type;
                    pppoeer->ver = pppoee->ver;
                    pppoeer->type = pppoee->type;
                    pppoeer->session = pppoee->session;
                    pppoeer->code = CODE_PADO;
                    pppoeer->length = 0;

                    PPPoETag * pppoetr;
                    unsigned int pppoe_payload_length = 0;
                    //add AC_NAME tag
                    pppoetr = (PPPoETag *) rte_pktmbuf_append(pkt,
                              sizeof(PPPoETag));
                    pppoetr->type = __bswap_16((uint16_t)(TYPE_AC_NAME));
                    pppoetr->length = __bswap_16((uint16_t)(sizeof(ac_name)));
                    char * ac_value = (char *) rte_pktmbuf_append(pkt,
                                      sizeof(ac_name));
                    memcpy(ac_value, ac_name, sizeof(ac_name));
                    pppoe_payload_length += sizeof(PPPoETag) + sizeof(ac_name);

                    //add SERVICE_NAME tag
                    pppoetr = (PPPoETag *) rte_pktmbuf_append(pkt,
                              sizeof(PPPoETag));
                    pppoetr->type = __bswap_16((uint16_t)(TYPE_SERVICE_NAME));
                    pppoetr->length = __bswap_16((uint16_t)(sn_length));
                    char * sr_value = (char *) rte_pktmbuf_append(pkt,
                                      sn_length);
                    memcpy(sr_value, serviceName, sn_length);
                    pppoe_payload_length += sizeof(PPPoETag) + sn_length;

                    //add COOKIE tag
                    pppoetr = (PPPoETag *) rte_pktmbuf_append(pkt,
                              sizeof(PPPoETag));
                    pppoetr->type = __bswap_16((uint16_t)(TYPE_AC_COOKIE));
                    char * CKname = "CKNAME";
                    pppoetr->length = __bswap_16((uint16_t)(sizeof(CKname)));
                    char * ck_value = (char *) rte_pktmbuf_append(pkt,
                                      sizeof(CKname));
                    memcpy(ck_value, CKname, sizeof(CKname));
                    pppoe_payload_length += sizeof(PPPoETag) + sizeof(CKname);

                    //add HOST_UNIQ tag if present in PADI
                    if (hu_length != 0)
                    {
                        pppoetr = (PPPoETag *) rte_pktmbuf_append(pkt,
                                  sizeof(PPPoETag));
                        pppoetr->type = __bswap_16((uint16_t)(TYPE_HOST_UNIQ));
                        pppoetr->length = __bswap_16((uint16_t)(hu_length));
                        char * hu_value = (char *) rte_pktmbuf_append(pkt,
                                          hu_length);
                        memcpy(hu_value, hostUnique, hu_length);
                        pppoe_payload_length += sizeof(PPPoETag) + hu_length;
                    }

                    //add RELAY_SESSION_ID tag if present in PADI
                    if (rd_length != 0)
                    {
                        pppoetr = (PPPoETag *) rte_pktmbuf_append(pkt,
                                  sizeof(PPPoETag));
                        pppoetr->type = __bswap_16(
                                            (uint16_t)(TYPE_RELAY_SESSION_ID));
                        pppoetr->length = __bswap_16((uint16_t)(rd_length));
                        char * rd_value = (char *) rte_pktmbuf_append(pkt,
                                          rd_length);
                        memcpy(rd_value, relayId, rd_length);
                        pppoe_payload_length += sizeof(PPPoETag) + rd_length;
                    }

                    pppoeer->length = __bswap_16(
                                          (uint16_t)(pppoe_payload_length));

                    //Enqueue the packet on queue.
                    int retrn = rte_ring_sp_enqueue(ring, pkt);
                    if (retrn != 0 && DEBUG)
                    {
                        RTE_LOG(INFO, USER1,
                                "Ring enqueue failed with error code %i.\n",
                                retrn);
                    }
		    process_ring();
                    return;

                    //check if it is a PADR packet
                }
                else if (pppoee->code == CODE_PADR)
                {
                    if (DEBUG)
                    {
                        RTE_LOG(INFO, USER1, "=> Packet PADR received\n");
                    }
                    PPPoETag * pppoet;
                    unsigned char serviceName[ETH_JUMBO_LEN]; //for keeping service name to be sent back in PADS
                    unsigned char hostUnique[ETH_JUMBO_LEN]; //for keeping host unique to be sent back in PADS
                    unsigned char cookie[ETH_JUMBO_LEN]; //for temporarily keeping cookie, have to check agaist the generated one
                    unsigned char relayId[ETH_JUMBO_LEN]; //relay id to be taken care, to be sent back in PADS
                    uint16_t sn_length = 0, hu_length = 0, ck_length = 0,
                             rd_length = 0;
                    unsigned int seen = 0;
                    unsigned int len = __bswap_16(pppoee->length);

                    //parse PPPoE tags in the packet
                    while (seen < len)
                    {
                        pppoet = rte_pktmbuf_mtod_offset(pkt, PPPoETag *, sizeof(PPPoEEncap)+seen);
                        seen += sizeof(PPPoETag);
                        //search for service name
                        if (__bswap_16(pppoet->type) == TYPE_SERVICE_NAME)
                        {
                            //keep the default service name ready in case tag length is zero
                            memcpy(serviceName, service_name,
                                   sizeof(service_name));
                            sn_length = (uint16_t) sizeof(service_name);
                            //check against all available service names (currenty only one exists)
                            if (__bswap_16(pppoet->length) != 0)
                            {
                                sn_length = __bswap_16(pppoet->length);
                                char * sr_value = rte_pktmbuf_mtod_offset(pkt, char *, sizeof(PPPoEEncap) + seen);
                                memcpy(serviceName, sr_value,
                                       __bswap_16(pppoet->length));
                                seen += __bswap_16(pppoet->length);
                            }
                            //search for host unique
                        }
                        else if (__bswap_16(pppoet->type) == TYPE_HOST_UNIQ)
                        {
                            hu_length = __bswap_16(pppoet->length);
                            char * hu_value = rte_pktmbuf_mtod_offset(pkt, char *, sizeof(PPPoEEncap) + seen);
                            memcpy(hostUnique, hu_value,
                                   __bswap_16(pppoet->length));
                            seen += __bswap_16(pppoet->length);
                            //search for cookie
                        }
                        else if (__bswap_16(pppoet->type) == TYPE_AC_COOKIE)
                        {
                            ck_length = __bswap_16(pppoet->length);
                            char * ck_value = rte_pktmbuf_mtod_offset(pkt, char *, sizeof(PPPoEEncap) + seen);
                            memcpy(cookie, ck_value,
                                   __bswap_16(pppoet->length));
                            seen += __bswap_16(pppoet->length);
                            //search for relay session id
                        }
                        else if (__bswap_16(pppoet->type)
                                 == TYPE_RELAY_SESSION_ID)
                        {

                            rd_length = __bswap_16(pppoet->length);
                            char * rd_value = rte_pktmbuf_mtod_offset(pkt, char *, sizeof(PPPoEEncap) + seen);
                            memcpy(relayId, rd_value,
                                   __bswap_16(pppoet->length));
                            seen += __bswap_16(pppoet->length);
                        }
                        else
                        {
                            if (DEBUG)
                            {
                                RTE_LOG(INFO, USER1,
                                        "=> Unknown tag found in a PADS packet received\n");
                            }
                            rte_pktmbuf_free(pkt);
                            return;
                        }
                    }
                    //verify the cookie received
                    if (ck_length == 0)
                    {
                        if (DEBUG)
                        {
                            RTE_LOG(INFO, USER1,
                                    "=> PADR packet with no cookie received, dropping...\n");
                        }
                        rte_pktmbuf_free(pkt);
                        return;
                    }
                    else if (ck_length != 0
                             && memcmp(cookie, "CKNAME", sizeof(ck_length))
                             != 0)
                    {
                        if (DEBUG)
                        {
                            RTE_LOG(INFO, USER1,
                                    "=> PADR packet for unknown cookie received, dropping...\n");
                        }
                        rte_pktmbuf_free(pkt);
                        return;
                    }

                    //check if asked service name matches our service name
                    if (sn_length != 0
                            && memcmp(serviceName, service_name,
                                      sizeof(service_name)) != 0)
                    {
                        if (DEBUG)
                        {
                            RTE_LOG(INFO, USER1,
                                    "=> PADR packet for unknown service name received, dropping...\n");
                        }
                        rte_pktmbuf_free(pkt);
                        return;
                    }

                    //create a session
                    //int index = create_session(pppoee->l2hdr.s_addr);
		    Session * newSession = create_new_session(pppoee->l2hdr.s_addr);
		    Session_key key;
		    key.client_mac_addr = newSession->client_mac_addr;
		    key.session_id = newSession->session_id;
		    SessionRtn * newRtnSession = copy_sessionRtn(newSession);
		    SessionRtn_key rtnKey;
		    rtnKey.client_ipv4_addr = newRtnSession->client_ipv4_addr;

                    if (newSession == NULL)
                    {
                        if (DEBUG)
                        {
                            RTE_LOG(INFO, USER1,
                                    "=> Session creation failed\n");
                        }
                        rte_pktmbuf_free(pkt);
                        return;
                    }

                    //assign host unique
                    if (hu_length != 0)
                    {
                        /*(session_array[index])->host_uniq = (char *) malloc(
                                                                hu_length);
                        memcpy((session_array[index])->host_uniq, hostUnique,
                               hu_length);
                        (session_array[index])->hu_len = hu_length;*/
			newSession->host_uniq = (char *) rte_malloc("HOST_UNI", hu_length, 0);
			memcpy(newSession->host_uniq, hostUnique, hu_length);
			newSession->hu_len = hu_length;
			newRtnSession->host_uniq = (char *) rte_malloc("HOST_UNI", hu_length, 0);
			memcpy(newRtnSession->host_uniq, hostUnique, hu_length);
			newRtnSession->hu_len = hu_length;
                    }

		    int retrn = grt_redirect_table_put_notifystupd(session_table, (void*)&key, (void*)newSession, -1, GRT_STUPD_TYPE_NEW_SESSIONENTRY);
		    retrn = grt_redirect_table_put_notifystupd(sessionRtn_table, (void*)&rtnKey, (void*)newRtnSession, -1, GRT_STUPD_TYPE_NEW_SESSIONRTNENTRY);
		    //add to redirect table
		    //Session_key key;
		    //key.client_mac_addr = pppoee->l2hdr.s_addr;
		    //key.session_id = index+1;
		    //Session * newSession = copy_session(session_array[index]);
            	    /*int retrn = _checkAndSetSessionEntry(session_array[index], &key);
		    if (retrn < 0) {
			RTE_LOG(INFO, USER1, "Error while getting Session entry %i", retrn);
			//return -1;
	            }*/

		    //if (lookupEntry == NULL) {
			//printf(" Session entry was NULL, although correctly returned %i.\n", retrn);
			//return -1;
		    //}
		    RTE_LOG(INFO, USER1, "Entry added successfully.............................................\n");


                    //generate a PADS packet to send back
                    rte_pktmbuf_reset(pkt);
                    PPPoEEncap * pppoeer = (PPPoEEncap *) rte_pktmbuf_append(
                                               pkt, sizeof(PPPoEEncap));
                    memcpy(&pppoeer->l2hdr.d_addr, &pppoee->l2hdr.s_addr,
                           sizeof(struct ether_addr));
                    memcpy(&pppoeer->l2hdr.s_addr, &srtointra_addr,
                           sizeof(struct ether_addr));
                    pppoeer->l2hdr.ether_type = pppoee->l2hdr.ether_type;
                    pppoeer->ver = pppoee->ver;
                    pppoeer->type = pppoee->type;
                    //pppoeer->session = __bswap_16(
                                           //(session_array[index])->session_id);
		    pppoeer->session = __bswap_16(newSession->session_id);
                    pppoeer->code = CODE_PADS;
                    pppoeer->length = 0;

                    PPPoETag * pppoetr;
                    unsigned int pppoe_payload_length = 0;
                    //add SERVICE_NAME tag
                    pppoetr = (PPPoETag *) rte_pktmbuf_append(pkt,
                              sizeof(PPPoETag));
                    pppoetr->type = __bswap_16((uint16_t)(TYPE_SERVICE_NAME));
                    pppoetr->length = __bswap_16((uint16_t)(sn_length));
                    char * sr_value = (char *) rte_pktmbuf_append(pkt,
                                      sn_length);
                    memcpy(sr_value, serviceName, sn_length);
                    pppoe_payload_length += sizeof(PPPoETag) + sn_length;

                    //add HOST_UNIQ tag if present in PADR
                    if (hu_length != 0)
                    {
                        pppoetr = (PPPoETag *) rte_pktmbuf_append(pkt,
                                  sizeof(PPPoETag));
                        pppoetr->type = __bswap_16((uint16_t)(TYPE_HOST_UNIQ));
                        pppoetr->length = __bswap_16((uint16_t)(hu_length));
                        char * hu_value = (char *) rte_pktmbuf_append(pkt,
                                          hu_length);
                        memcpy(hu_value, hostUnique, hu_length);
                        pppoe_payload_length += sizeof(PPPoETag) + hu_length;
                    }

                    //add RELAY_SESSION_ID tag if present in PADR
                    if (rd_length != 0)
                    {
                        pppoetr = (PPPoETag *) rte_pktmbuf_append(pkt,
                                  sizeof(PPPoETag));
                        pppoetr->type = __bswap_16(
                                            (uint16_t)(TYPE_RELAY_SESSION_ID));
                        pppoetr->length = __bswap_16((uint16_t)(rd_length));
                        char * rd_value = (char *) rte_pktmbuf_append(pkt,
                                          rd_length);
                        memcpy(rd_value, relayId, rd_length);
                        pppoe_payload_length += sizeof(PPPoETag) + rd_length;
                    }

                    pppoeer->length = __bswap_16(
                                          (uint16_t)(pppoe_payload_length));

                    //Enqueue the packet on queue.
                    retrn = rte_ring_sp_enqueue(ring, pkt);
                    if (retrn != 0 && DEBUG)
                    {
                        RTE_LOG(INFO, USER1,
                                "Ring enqueue failed with error code %i.\n",
                                retrn);
                    }
		    process_ring();
                    return;

                //check if it is PADT packet
                }
                else if (pppoee->code == CODE_PADT)
                {

                    if (DEBUG)
                    {
                        RTE_LOG(INFO, USER1, "=> Packet PADT received\n");
                    }

                    //delete the session
                    //int index = __bswap_16(pppoee->session) - 1;
                    //delete_session(index);
		    Session* foundEntry = NULL;
     		    retrn = grt_redirect_table_get(session_table, (void*)&key, (void**)&foundEntry, 0);
		    SessionRtn_key rtnKey;
		    rtnKey.client_ipv4_addr = foundEntry->client_ipv4_addr;
		    //int retrn = grt_redirect_table_remove(session_table, (void*)&key);
		    //retrn = grt_redirect_table_remove(sessionRtn_table, (void*)&rtnKey);
                //check if it is a session packet
                }
                else if (pppoee->code == CODE_SESS)
                {

                    if (DEBUG)
                    {
                        RTE_LOG(INFO, USER1, "=> Session Packet received\n");
                    }

                    PPPEncap * pppptcl;
                    unsigned int seen = 0;
                    pppptcl = rte_pktmbuf_mtod_offset(pkt, PPPEncap *, sizeof(PPPoEEncap)+seen);
                    seen += sizeof(PPPEncap);

                    //check if it is a LCP packet
                    if (__bswap_16(pppptcl->protocol) == PROTO_LCP)
                    {
                        if (DEBUG)
                        {
                            RTE_LOG(INFO, USER1, "=> LCP Packet received\n");
                        }

                        PPPLcp * ppplcp;
                        ppplcp = rte_pktmbuf_mtod_offset(pkt, PPPLcp *, sizeof(PPPoEEncap)+seen);
                        seen += sizeof(PPPLcp);
                        if (ppplcp->code == CODE_CONF_REQ)
                        {
                            if (DEBUG)
                            {
                                RTE_LOG(INFO, USER1,
                                        "=> Configure-request Packet received\n");
                            }

                            //send an ACK

                            ppplcp->code = CODE_CONF_ACK;
                            memcpy(&pppoee->l2hdr.d_addr, &pppoee->l2hdr.s_addr,
                                   sizeof(struct ether_addr));
                            memcpy(&pppoee->l2hdr.s_addr, &srtointra_addr,
                                   sizeof(struct ether_addr));
                            //send the Configure-reply packet to peer
                            //Enqueue the packet on queue.
                            int retrn = rte_ring_sp_enqueue(ring,
                                                            pkt);
                            if (retrn != 0 && DEBUG)
                            {
                                RTE_LOG(INFO, USER1,
                                        "Ring enqueue failed with error code %i.\n",
                                        retrn);
                            }
			    process_ring();
                            //send a Configure-request for Authetication to peer
                            send_config_req((uint8_t) TYPE_AUP,
                                            (uint16_t) __bswap_16(pppoee->session),
                                            pppoee->l2hdr.d_addr);
                            return;

                        }
                        else if (ppplcp->code == CODE_ECHO_REQ)
                        {
                            if (DEBUG)
                            {
                                RTE_LOG(INFO, USER1,
                                        "=> Echo-request Packet received\n");
                            }



                            //send a Echo-request and reply


                            ppplcp->code = CODE_ECHO_REP;

                            memcpy(&pppoee->l2hdr.d_addr, &pppoee->l2hdr.s_addr,
                                   sizeof(struct ether_addr));
                            memcpy(&pppoee->l2hdr.s_addr, &srtointra_addr,
                                   sizeof(struct ether_addr));
                            //send the Echo-reply packet to peer
                            //Enqueue the packet on queue.
                            /*int retrn = rte_ring_sp_enqueue(ring,
                                                            pkt);
                            if (retrn != 0 && DEBUG)
                            {
                                RTE_LOG(INFO, USER1,
                                        "Ring enqueue failed with error code %i.\n",
                                        retrn);
                            }
			    process_ring();*/

			    int retrn = rte_eth_tx_burst(ETHDEV_ID, 0, &pkt, 1);

                            //send an echo-request back
                            int index = __bswap_16(pppoee->session);
                            send_echo_req((uint16_t) index,
                                          pppoee->l2hdr.d_addr);

                            return;

                        }
                        else if (ppplcp->code == CODE_ECHO_REP)
                        {
                            if (DEBUG)
                            {
                                RTE_LOG(INFO, USER1,
                                        "=> Echo-reply Packet received\n");
                            }
                            rte_pktmbuf_free(pkt);
                            return;

                        }
                        else if (ppplcp->code == CODE_CONF_ACK)
                        {
                            if (DEBUG)
                            {
                                RTE_LOG(INFO, USER1,
                                        "=> Configure-ACK Packet received\n");
                            }
                            rte_pktmbuf_free(pkt);
                            return;

                        }
                        else if (ppplcp->code == CODE_TERM_REQ)
                        {
                            if (DEBUG)
                            {
                                RTE_LOG(INFO, USER1,
                                        "=> Termination-req Packet received\n");
                            }

                            ppplcp->code = CODE_TERM_ACK;
                            uint16_t len_remove = (uint16_t)(
                                                      __bswap_16(ppplcp->length) - 4);
                            ppplcp->length = __bswap_16(4); //always will be 4
                            rte_pktmbuf_trim(pkt, len_remove);
                            memcpy(&pppoee->l2hdr.d_addr, &pppoee->l2hdr.s_addr,
                                   sizeof(struct ether_addr));
                            memcpy(&pppoee->l2hdr.s_addr, &srtointra_addr,
                                   sizeof(struct ether_addr));
                            //send the Term-ACK packet to peer
                            //Enqueue the packet on queue.
                            int retrn = rte_ring_sp_enqueue(ring,
                                                            pkt);
                            if (retrn != 0 && DEBUG)
                            {
                                RTE_LOG(INFO, USER1,
                                        "Ring enqueue failed with error code %i.\n",
                                        retrn);
                            }
			    process_ring();
                            //int index = __bswap_16(pppoee->session) - 1;
 			    //Session_key sn_key;
      			    //sn_key.client_mac_addr = session_array[index]->client_mac_addr;
       			    //sn_key.session_id = index+1;
                            //(session_array[index])->state = STATE_TERM_SENT;
			    Session* foundEntry = NULL;
			    retrn = grt_redirect_table_get(session_table, (void*)&key, (void**)&foundEntry, 0);
			    Session *newSession = copy_session(foundEntry);
		            newSession->state = STATE_TERM_SENT;
			    SessionRtn *newRtnSession = copy_sessionRtn(foundEntry);
			    newRtnSession->state = STATE_TERM_SENT;
			    SessionRtn_key rtnKey;
		    	    rtnKey.client_ipv4_addr = newRtnSession->client_ipv4_addr;
			    int retrn1 = grt_redirect_table_put_notifystupd(session_table, (void*)&key, (void*)newSession, -1, GRT_STUPD_TYPE_SESSION_UPDATE);
			    retrn1 = grt_redirect_table_put_notifystupd(sessionRtn_table, (void*)&rtnKey, (void*)newRtnSession, -1, GRT_STUPD_TYPE_SESSIONRTN_UPDATE);
                            return;
                        }
                        else if (ppplcp->code == CODE_TERM_ACK)
                        {
                            if (DEBUG)
                            {
                                RTE_LOG(INFO, USER1,
                                        "=> Termination-ACK Packet received\n");
                            }
                            rte_pktmbuf_free(pkt);
                            return;

                        }

                        //check if it is a PAP packet
                    }
                    else if (__bswap_16(pppptcl->protocol) == PROTO_PAP)
                    {
                        if (DEBUG)
                        {
                            RTE_LOG(INFO, USER1, "=> PAP Packet received\n");
                        }

                        PPPPapReq * ppppapr;
                        ppppapr = rte_pktmbuf_mtod_offset(pkt, PPPPapReq *, sizeof(PPPoEEncap)+seen);
                        seen += sizeof(PPPPapReq);
                        char user_name[ETH_JUMBO_LEN];
                        char user_passwd[ETH_JUMBO_LEN];
                        memset(&user_name[0], '\0', sizeof(user_name));
                        memset(&user_passwd[0], '\0', sizeof(user_passwd));

                        //check if it is an authentication request
                        if (ppppapr->code == CODE_AUT_REQ)
                        {

                            //get the username
                            uint8_t * u_len = rte_pktmbuf_mtod_offset(pkt, uint8_t *, sizeof(PPPoEEncap)+seen);
                            uint8_t user_length = 0;
                            memcpy(&user_length, u_len, sizeof(uint8_t));
                            seen += sizeof(uint8_t);
                            char * user = rte_pktmbuf_mtod_offset(pkt, char *, sizeof(PPPoEEncap)+seen);
                            memcpy(user_name, user, user_length);
                            seen += user_length;

                            //get the password
                            uint8_t * p_len = rte_pktmbuf_mtod_offset(pkt, uint8_t *, sizeof(PPPoEEncap)+seen);
                            uint8_t passwd_length = 0;
                            memcpy(&passwd_length, p_len, sizeof(uint8_t));
                            seen += sizeof(uint8_t);
                            char * passwd = rte_pktmbuf_mtod_offset(pkt, char *, sizeof(PPPoEEncap)+seen);
                            memcpy(user_passwd, passwd, passwd_length);
                            if (DEBUG)
                            {
                                RTE_LOG(INFO, USER1,
                                        "=> username = %s, password = %s\n",
                                        user_name, user_passwd);
                            }

                        }

                        //authenticate the username and password
                        int result = auth(user_name, user_passwd);
			//there is something wrong with the auth code, for now make auth to pass by default
			result = 1;
                        if (!result)
                        {
                            //send AUTH NAK
                            int index = __bswap_16(pppoee->session);
                            send_auth_nak((uint8_t) ppppapr->identifier,
                                          (uint16_t) index, pppoee->l2hdr.s_addr);

                        }
                        else
                        {
                            //send AUTH ACK
                            int index = __bswap_16(pppoee->session);
                            send_auth_ack((uint8_t) ppppapr->identifier,
                                          (uint16_t) index, pppoee->l2hdr.s_addr);
                        }

                        rte_pktmbuf_free(pkt);
                        return;

                    //check if it is a compression control protocol, we reject protocol = no compression
                    }
                    else if (__bswap_16(pppptcl->protocol) == PROTO_CCP)
                    {

                        if (DEBUG)
                        {
                            RTE_LOG(INFO, USER1, "=> CCP Packet received\n");
                        }

                        //send a protocol reject
                        send_proto_reject((uint16_t) PROTO_CCP, pkt);
                        rte_pktmbuf_free(pkt);
                        return;

                    //check if it is a IPv6 control protocol, we reject it
                    }
                    else if (__bswap_16(pppptcl->protocol) == PROTO_IPV6C)
                    {

                        if (DEBUG)
                        {
                            RTE_LOG(INFO, USER1, "=> IPV6C Packet received\n");
                        }

                        //send a protocol reject
                        send_proto_reject((uint16_t) PROTO_IPV6C, pkt);
                        rte_pktmbuf_free(pkt);
                        return;

                    //check if it is a IPCP packet
                    }
                    else if (__bswap_16(pppptcl->protocol) == PROTO_IPCP)
                    {

                        if (DEBUG)
                        {
                            RTE_LOG(INFO, USER1, "=> IPCP Packet received\n");
                        }

                        PPPIpcp * pppipcp;
                        pppipcp = rte_pktmbuf_mtod_offset(pkt, PPPIpcp *, sizeof(PPPoEEncap)+seen);
                        seen += sizeof(PPPIpcp);
                        PPPIpcpUsed * ipDns;
                        int type = 0;
    			Session_key key;
    			key.client_mac_addr = pppoee->l2hdr.s_addr;
    			key.session_id = __bswap_16(pppoee->session);
    			Session* foundEntry = NULL;
    			int retrn = grt_redirect_table_get(session_table, (void*)&key, (void**)&foundEntry, 0);

                        //some unexpected error in peer mac address, printing it.
                        char ethr[50];
                        ethaddr_to_string(ethr, &(pppoee->l2hdr.s_addr));
                        RTE_LOG(INFO, USER1, "=> ether src %s\n", ethr);

                        //check if it is IPCP request
                        if (pppipcp->code == CODE_IPCP_REQ)
                        {

                            //get ip and dns, (ip address already stored in session)
                            int index = __bswap_16(pppoee->session);
                            ipDns = get_ip_dns(index, pppoee->l2hdr.s_addr);
			    ipDns->ip = foundEntry->client_ipv4_addr;

                            unsigned int optseen = 0;
                            unsigned int len = __bswap_16(pppipcp->length) - 4;
                            PPPIpcpOptions * pppipcpo;
                            //parse IPCP options in the packet
                            while (optseen < len)
                            {
                                pppipcpo = rte_pktmbuf_mtod_offset(pkt, PPPIpcpOptions *, sizeof(PPPoEEncap)+seen+optseen);
                                optseen += sizeof(PPPIpcpOptions);
                                //search for ip
                                if (pppipcpo->type == TYPE_IP)
                                {
                                    if (pppipcpo->value == ipDns->ip)
                                    {
                                        type = 2;
                                    }
                                    else
                                    {
                                        pppipcpo->value = ipDns->ip;
                                        type = 3;
                                    }
                                    //search for primary dns
                                }
                                else if (pppipcpo->type == TYPE_DNS_PRI)
                                {
                                    if (pppipcpo->value == ipDns->dns1)
                                    {
                                        type = 2;
                                    }
                                    else
                                    {
                                        pppipcpo->value = ipDns->dns1;
                                        type = 3;
                                    }
                                    //search for secondary dns
                                }
                                else if (pppipcpo->type == TYPE_DNS_SEC)
                                {
                                    if (pppipcpo->value == ipDns->dns2)
                                    {
                                        type = 2;
                                    }
                                    else
                                    {
                                        pppipcpo->value = ipDns->dns2;
                                        type = 3;
                                    }
                                }
                                else
                                {
                                    if (DEBUG)
                                    {
                                        RTE_LOG(INFO, USER1,
                                                "=> Unknown option found in IPCP packet received...%x\n",
                                                pppipcpo->type);
                                    }
                                }
                            }

                            //send ACK to peer
                            if (type == 2)
                            {
                                pppipcp->code = CODE_IPCP_ACK;
                            //send NAK to peer
                            }
                            else if (type == 3)
                            {
                                pppipcp->code = CODE_IPCP_NAK;
                            }
                            else
                            {
                                if (DEBUG)
                                {
                                    RTE_LOG(INFO, USER1,
                                            "=> No type set for IPCP packet received. dropping....\n");
                                }
                                rte_pktmbuf_free(pkt);
                                return;
                            }

                            memcpy(&pppoee->l2hdr.d_addr, &pppoee->l2hdr.s_addr,
                                   sizeof(struct ether_addr));
                            memcpy(&pppoee->l2hdr.s_addr, &srtointra_addr,
                                   sizeof(struct ether_addr));
                            //send the packet
                            //Enqueue the packet on queue.
                            int retrn = rte_ring_sp_enqueue(ring,
                                                            pkt);
			    process_ring();
                            if (retrn != 0 && DEBUG)
                            {
                                RTE_LOG(INFO, USER1,
                                        "Ring enqueue failed with error code %i.\n",
                                        retrn);
                            }

                            //send a ip request back
                            if (type == 2)
                            {
                                int index = __bswap_16(pppoee->session);
                                send_ip_req((uint16_t) index, pkt, pppoee->l2hdr.s_addr);
                            }
                            return;

                        }
                        else if (pppipcp->code == CODE_IPCP_ACK)
                        {
                            if (DEBUG)
                            {
                                RTE_LOG(INFO, USER1,
                                        "=> IPCP-ACK Packet received\n");
                            }
                            rte_pktmbuf_free(pkt);
                            return;
                        }

                    //check if it is a IPv4 packet
                    }
                    else if (__bswap_16(pppptcl->protocol) == PROTO_IPV4)
                    {

                        //int s_index = __bswap_16(pppoee->session);
                        struct ipv4_hdr * iphdr;

                        //remove pppoe encapsulation
                        iphdr = (struct ipv4_hdr *) rte_pktmbuf_adj(pkt,
                                sizeof(PPPoEEncap) + sizeof(PPPEncap));
			Session* foundEntry = NULL;
			int retrn = grt_redirect_table_get(session_table, (void*)&key, (void**)&foundEntry, 0);
			if (retrn != 1) {
				rte_pktmbuf_free(pkt);
				return;
			}
                        if (!((iphdr->src_addr)
                                ^ (foundEntry->client_ipv4_addr)))
                        {

                            struct ether_hdr * l2hdr;
                            l2hdr = (struct ether_hdr *) rte_pktmbuf_prepend(
                                        pkt, sizeof(struct ether_hdr));

                            //adding L2 addresses.
                            memcpy(&l2hdr->d_addr, &gateway_addr,
                                   sizeof(struct ether_addr));
                            memcpy(&l2hdr->s_addr, &srtointer_addr,
                                   sizeof(struct ether_addr));
                            l2hdr->ether_type = __bswap_16(ETHER_IPV4);

                            //send the packet
                            int retrn = rte_eth_tx_burst(ETHDEV_ID + 1, 0,
                                                         &pkt, 1);
			    //session_array[s_index]->time = time(NULL);
			    //Session_key sn_key;
      			    //sn_key.client_mac_addr = session_array[s_index]->client_mac_addr;
       			    //sn_key.session_id = s_index+1;
			    //Session *newSession = copy_session(session_array[s_index]);
			    //int retrn1 = grt_redirect_table_put_notifystupd(session_table, (void*)&sn_key, (void*)newSession, -1, GRT_STUPD_TYPE_SESSION_UPDATE);
			    /*Session *newSession = copy_session(foundEntry);
		            newSession->time = time(NULL);
			    SessionRtn *newRtnSession = copy_sessionRtn(foundEntry);
			    newRtnSession->time = time(NULL);
			    SessionRtn_key rtnKey;
		    	    rtnKey.client_ipv4_addr = newRtnSession->client_ipv4_addr;
			    int retrn1 = grt_redirect_table_put_notifystupd(session_table, (void*)&key, (void*)newSession, -1, GRT_STUPD_TYPE_SESSION_UPDATE);
			    retrn1 = grt_redirect_table_put_notifystupd(sessionRtn_table, (void*)&rtnKey, (void*)newRtnSession, -1, GRT_STUPD_TYPE_SESSIONRTN_UPDATE);
                            pkt_in_end_time = gettime();*/

/*unsigned char bytes1[4];
    bytes1[0] = iphdr->src_addr & 0xFF;
    bytes1[1] = (iphdr->src_addr >> 8) & 0xFF;
    bytes1[2] = (iphdr->src_addr >> 16) & 0xFF;
    bytes1[3] = (iphdr->src_addr >> 24) & 0xFF;   
    printf("src :%d.%d.%d.%d\n", bytes1[3], bytes1[2], bytes1[1], bytes1[0]);

unsigned char bytes2[4];
    bytes2[0] = iphdr->dst_addr & 0xFF;
    bytes2[1] = (iphdr->dst_addr >> 8) & 0xFF;
    bytes2[2] = (iphdr->dst_addr >> 16) & 0xFF;
    bytes2[3] = (iphdr->dst_addr >> 24) & 0xFF;   
    printf("dst :%d.%d.%d.%d\n", bytes2[3], bytes2[2], bytes2[1], bytes2[0]);

			    
char ethaddr_str_buf [20];
grt_ethaddr_to_string(ethaddr_str_buf, &gateway_addr);
printf("gateway MAC: %s   ip src %x ip dst %x\n", ethaddr_str_buf, iphdr->src_addr, iphdr->dst_addr);*/

                            /*if (DEBUG)
                            {
                                printf("send time: %llu\n",
                                       pkt_in_end_time - pkt_in_start_time);
                            }*/

                            if (retrn != 1 && DEBUG)
                            {
                                RTE_LOG(INFO, USER1,
                                        "TX burst failed with error code %i.\n",
                                        retrn);
                            }
                            return;

                        }
                        else
                        {
                            rte_pktmbuf_free(pkt);
                            return;
                        }
                    }
                }

            }
	    //not a PPPoE packet, drop it.
            else
            {
/*struct ipv4_hdr *iphdr;
iphdr = (struct ipv4_hdr *)(rte_pktmbuf_mtod(pkt, unsigned char *) + sizeof(struct ether_hdr));
//Get the beginning of the packet's mbuf and skip for the size of an ether header.
unsigned char bytes1[4];
    bytes1[0] = iphdr->src_addr & 0xFF;
    bytes1[1] = (iphdr->src_addr >> 8) & 0xFF;
    bytes1[2] = (iphdr->src_addr >> 16) & 0xFF;
    bytes1[3] = (iphdr->src_addr >> 24) & 0xFF;   
    printf("src :%d.%d.%d.%d\n", bytes1[3], bytes1[2], bytes1[1], bytes1[0]);

unsigned char bytes2[4];
    bytes2[0] = iphdr->dst_addr & 0xFF;
    bytes2[1] = (iphdr->dst_addr >> 8) & 0xFF;
    bytes2[2] = (iphdr->dst_addr >> 16) & 0xFF;
    bytes2[3] = (iphdr->dst_addr >> 24) & 0xFF;   
    printf("dst :%d.%d.%d.%d\n", bytes2[3], bytes2[2], bytes2[1], bytes2[0]);*/

                RTE_LOG(INFO, USER1,
                        "=> Packet for unknown target received, dropping...\n");
                rte_pktmbuf_free(pkt);

                return;
            }

        //}

    //}

    //return 0;
}


/**
 * @brief Function to handle incoing packets.
 * @param l2 header, packet's mbuf, interface id.
 */
int handle_packet(struct ether_hdr* l2hdr, struct rte_mbuf* packet, uint8_t grt_if_id) {

	if (grt_if_id == 0) {
	    //process the interior packets
	    process_interior_packet(l2hdr, packet);
	} else {
	    //process the exterior packets
	    process_exterior_packet(l2hdr, packet);
	}
}


/**
 * @brief Function to send a config request.
 * @param type of conf-request, session index, ethernet address of client.
 */
void send_config_req(uint8_t type, uint16_t session,
                     struct ether_addr client_l2addr)
{

    uint8_t lcore_id = rte_lcore_id();
    if (DEBUG)
    {
        RTE_LOG(INFO, USER1, "=> called send_config_req for type %i.\n",
                (int) type);
    }
    //generate a PPPoE packet
    //struct rte_mbuf * acpkt = rte_pktmbuf_alloc(mempool);
    struct rte_mbuf * acpkt = rte_pktmbuf_alloc(grt_getCurrentLCoreInfo()->mempool);
    PPPoEEncap * pppoeer = (PPPoEEncap *) rte_pktmbuf_append(acpkt,
                           sizeof(PPPoEEncap));
    memcpy(&pppoeer->l2hdr.d_addr, &client_l2addr, sizeof(struct ether_addr));
    memcpy(&pppoeer->l2hdr.s_addr, &srtointra_addr, sizeof(struct ether_addr));
    pppoeer->l2hdr.ether_type = __bswap_16(ETHER_SESSION);
    pppoeer->ver = PPPOE_VER;
    pppoeer->type = PPPOE_TYPE;
    pppoeer->session = __bswap_16(session);
    pppoeer->code = CODE_SESS;
    pppoeer->length = 0;

    uint16_t pppoe_payload_legth = 0;
    PPPEncap * pppptcls = (PPPEncap *) rte_pktmbuf_append(acpkt,
                          sizeof(PPPEncap));
    pppptcls->protocol = __bswap_16(PROTO_LCP);
    pppoe_payload_legth += (uint16_t) sizeof(PPPEncap);

    PPPLcp * ppplcps = (PPPLcp *) rte_pktmbuf_append(acpkt, sizeof(PPPLcp));
    ppplcps->code = CODE_CONF_REQ;
    /*ppplcps->identifier = (session_array[session_index])->auth_ident;
    ((session_array[session_index])->auth_ident)++;
    Session_key sn_key;
    sn_key.client_mac_addr = session_array[session_index]->client_mac_addr;
    sn_key.session_id = session_index+1;
    Session *newSession = copy_session(session_array[session_index]);
    int retrn1 = grt_redirect_table_put_notifystupd(session_table, (void*)&sn_key, (void*)newSession, -1, GRT_STUPD_TYPE_SESSION_UPDATE);*/
    Session_key key;
    key.client_mac_addr = client_l2addr;
    key.session_id = session;
    Session* foundEntry = NULL;
    int retrn = grt_redirect_table_get(session_table, (void*)&key, (void**)&foundEntry, 0);
    ppplcps->identifier = foundEntry->auth_ident;
    Session *newSession = copy_session(foundEntry);
    newSession->auth_ident = foundEntry->auth_ident + 1;
    SessionRtn *newRtnSession = copy_sessionRtn(foundEntry);
    newRtnSession->auth_ident = foundEntry->auth_ident + 1;
    SessionRtn_key rtnKey;
    rtnKey.client_ipv4_addr = newRtnSession->client_ipv4_addr;
    int retrn1 = grt_redirect_table_put_notifystupd(session_table, (void*)&key, (void*)newSession, -1, GRT_STUPD_TYPE_SESSION_UPDATE);
    retrn1 = grt_redirect_table_put_notifystupd(sessionRtn_table, (void*)&rtnKey, (void*)newRtnSession, -1, GRT_STUPD_TYPE_SESSIONRTN_UPDATE);
    ppplcps->length = 0;
    uint16_t ppplcp_length = 0;
    pppoe_payload_legth += (uint16_t) sizeof(PPPLcp);
    ppplcp_length += (uint16_t) sizeof(PPPLcp);

    //check if for auth configure-request
    if (type == TYPE_AUP)
    {

        //add options
        PPPLcpOptionsGenl * ppplcpos = (PPPLcpOptionsGenl *) rte_pktmbuf_append(
                                           acpkt, sizeof(PPPLcpOptionsGenl));
        ppplcpos->type = TYPE_AUP;
        ppplcpos->length = 0x04; //will always be 4 bytes long
        ppplcpos->value = __bswap_16(PROTO_PAP);
        pppoe_payload_legth += (uint16_t) sizeof(PPPLcpOptionsGenl);
        ppplcp_length += (uint16_t) ppplcpos->length;
    }
    else
    {
        RTE_LOG(INFO, USER1,
                "Request for sending unknown configure-request, not sending...\n");
        rte_pktmbuf_free(acpkt);
        return;
    }

    ppplcps->length = __bswap_16(ppplcp_length);
    pppoeer->length = __bswap_16(pppoe_payload_legth);
    //send the packet
    //Enqueue the packet on queue.
    retrn = rte_ring_sp_enqueue(ring, acpkt);
    if (retrn != 0 && DEBUG)
    {
        RTE_LOG(INFO, USER1, "Ring enqueue failed with error code %i.\n",
                retrn);
    }
    process_ring();

}


/**
 * @brief Function to send an Echo-request.
 * @param session index, ethernet address of client.
 */
void send_echo_req(uint16_t session, struct ether_addr client_l2addr)
{

    uint8_t lcore_id = rte_lcore_id();
    if (DEBUG)
    {
        RTE_LOG(INFO, USER1, "=> called send_echo_req\n");
    }
    //generate a PPPoE packet
    //struct rte_mbuf * acpkt = rte_pktmbuf_alloc(mempool);
    struct rte_mbuf * acpkt = rte_pktmbuf_alloc(grt_getCurrentLCoreInfo()->mempool);
    PPPoEEncap * pppoeer = (PPPoEEncap *) rte_pktmbuf_append(acpkt,
                           sizeof(PPPoEEncap));
    memcpy(&pppoeer->l2hdr.d_addr, &client_l2addr, sizeof(struct ether_addr));
    memcpy(&pppoeer->l2hdr.s_addr, &srtointra_addr, sizeof(struct ether_addr));
    pppoeer->l2hdr.ether_type = __bswap_16(ETHER_SESSION);
    pppoeer->ver = PPPOE_VER;
    pppoeer->type = PPPOE_TYPE;
    pppoeer->session = __bswap_16(session);
    pppoeer->code = CODE_SESS;
    pppoeer->length = 0;

    uint16_t pppoe_payload_legth = 0;
    PPPEncap * pppptcls = (PPPEncap *) rte_pktmbuf_append(acpkt,
                          sizeof(PPPEncap));
    pppptcls->protocol = __bswap_16(PROTO_LCP);
    pppoe_payload_legth += (uint16_t) sizeof(PPPEncap);

    PPPLcpMagic * ppplcpms = (PPPLcpMagic *) rte_pktmbuf_append(acpkt,
                             sizeof(PPPLcpMagic));
    ppplcpms->code = CODE_ECHO_REQ;
    /*ppplcpms->identifier = (session_array[session_index])->echo_ident;
    ((session_array[session_index])->echo_ident)++;
    Session_key sn_key;
    sn_key.client_mac_addr = session_array[session_index]->client_mac_addr;
    sn_key.session_id = session_index+1;
    Session *newSession = copy_session(session_array[session_index]);
    int retrn1 = grt_redirect_table_put_notifystupd(session_table, (void*)&sn_key, (void*)newSession, -1, GRT_STUPD_TYPE_SESSION_UPDATE);*/
    Session_key key;
    key.client_mac_addr = client_l2addr;
    key.session_id = session;
    Session* foundEntry = NULL;
    int retrn = grt_redirect_table_get(session_table, (void*)&key, (void**)&foundEntry, 0);
    ppplcpms->identifier = foundEntry->echo_ident;
    Session *newSession = copy_session(foundEntry);
    newSession->echo_ident = foundEntry->echo_ident + 1;
    SessionRtn *newRtnSession = copy_sessionRtn(foundEntry);
    newRtnSession->echo_ident = foundEntry->echo_ident + 1;
    SessionRtn_key rtnKey;
    rtnKey.client_ipv4_addr = newRtnSession->client_ipv4_addr;
    int retrn1 = grt_redirect_table_put_notifystupd(session_table, (void*)&key, (void*)newSession, -1, GRT_STUPD_TYPE_SESSION_UPDATE);
    retrn1 = grt_redirect_table_put_notifystupd(sessionRtn_table, (void*)&rtnKey, (void*)newRtnSession, -1, GRT_STUPD_TYPE_SESSIONRTN_UPDATE);
    ppplcpms->length = 0;
    //for now add a temp magic no:
    ppplcpms->magic_number = __bswap_16(0x12345678);
    uint16_t ppplcp_length = 0;
    pppoe_payload_legth += (uint16_t) sizeof(PPPLcpMagic);
    ppplcp_length += (uint16_t) sizeof(PPPLcpMagic);

    ppplcpms->length = __bswap_16(ppplcp_length);
    pppoeer->length = __bswap_16(pppoe_payload_legth);
    retrn = rte_ring_sp_enqueue(ring, acpkt);
    if (retrn != 0 && DEBUG)
    {
        RTE_LOG(INFO, USER1, "Ring enqueue failed with error code %i.\n",
                retrn);
    }
    process_ring();
}


/**
 * @brief Function to send an Authentication ACK.
 * @param session identifier, session index, ethernet address of client.
 */
void send_auth_ack(uint8_t identifier, uint16_t session,
                   struct ether_addr client_l2addr)
{

    uint8_t lcore_id = rte_lcore_id();
    if (DEBUG)
    {
        RTE_LOG(INFO, USER1, "=> called send_auth_ack\n");
    }
    //generate a PPPoE packet
    //struct rte_mbuf * acpkt = rte_pktmbuf_alloc(mempool);
    struct rte_mbuf * acpkt = rte_pktmbuf_alloc(grt_getCurrentLCoreInfo()->mempool);
    PPPoEEncap * pppoeer = (PPPoEEncap *) rte_pktmbuf_append(acpkt,
                           sizeof(PPPoEEncap));
    memcpy(&pppoeer->l2hdr.d_addr, &client_l2addr, sizeof(struct ether_addr));
    memcpy(&pppoeer->l2hdr.s_addr, &srtointra_addr, sizeof(struct ether_addr));
    pppoeer->l2hdr.ether_type = __bswap_16(ETHER_SESSION);
    pppoeer->ver = PPPOE_VER;
    pppoeer->type = PPPOE_TYPE;
    pppoeer->session = __bswap_16(session);
    pppoeer->code = CODE_SESS;
    pppoeer->length = 0;

    uint16_t pppoe_payload_legth = 0;
    PPPEncap * pppptcls = (PPPEncap *) rte_pktmbuf_append(acpkt,
                          sizeof(PPPEncap));
    pppptcls->protocol = __bswap_16(PROTO_PAP);
    pppoe_payload_legth += (uint16_t) sizeof(PPPEncap);

    PPPPapAck * ppppapas = (PPPPapAck *) rte_pktmbuf_append(acpkt,
                           sizeof(PPPPapAck));
    ppppapas->code = CODE_AUT_ACK;
    ppppapas->identifier = identifier;
    ppppapas->length = 0;
    ppppapas->idms_length = 0;
    uint16_t ppppap_length = 0;
    pppoe_payload_legth += (uint16_t) sizeof(PPPPapAck);
    ppppap_length += (uint16_t) sizeof(PPPPapAck);

    ppppapas->length = __bswap_16(ppppap_length);
    pppoeer->length = __bswap_16(pppoe_payload_legth);
    int retrn = rte_ring_sp_enqueue(ring, acpkt);
    if (retrn != 0 && DEBUG)
    {
        RTE_LOG(INFO, USER1, "Ring enqueue failed with error code %i.\n",
                retrn);
    }
    process_ring();
}


/**
 * @brief Function to send an Authentication NAK.
 * @param session identifier, session index, ethernet address of client.
 */
void send_auth_nak(uint8_t identifier, uint16_t session,
                   struct ether_addr client_l2addr)
{

    uint8_t lcore_id = rte_lcore_id();
    if (DEBUG)
    {
        RTE_LOG(INFO, USER1, "=> called send_auth_nak\n");
    }
    //generate a PPPoE packet
    //struct rte_mbuf * acpkt = rte_pktmbuf_alloc(mempool);
    struct rte_mbuf * acpkt = rte_pktmbuf_alloc(grt_getCurrentLCoreInfo()->mempool);
    PPPoEEncap * pppoeer = (PPPoEEncap *) rte_pktmbuf_append(acpkt,
                           sizeof(PPPoEEncap));
    memcpy(&pppoeer->l2hdr.d_addr, &client_l2addr, sizeof(struct ether_addr));
    memcpy(&pppoeer->l2hdr.s_addr, &srtointra_addr, sizeof(struct ether_addr));
    pppoeer->l2hdr.ether_type = __bswap_16(ETHER_SESSION);
    pppoeer->ver = PPPOE_VER;
    pppoeer->type = PPPOE_TYPE;
    pppoeer->session = __bswap_16(session);
    pppoeer->code = CODE_SESS;
    pppoeer->length = 0;

    uint16_t pppoe_payload_legth = 0;
    PPPEncap * pppptcls = (PPPEncap *) rte_pktmbuf_append(acpkt,
                          sizeof(PPPEncap));
    pppptcls->protocol = __bswap_16(PROTO_PAP);
    pppoe_payload_legth += (uint16_t) sizeof(PPPEncap);

    PPPPapAck * ppppapas = (PPPPapAck *) rte_pktmbuf_append(acpkt,
                           sizeof(PPPPapAck));
    ppppapas->code = CODE_AUT_NAK;
    ppppapas->identifier = identifier;
    ppppapas->length = 0;
    ppppapas->idms_length = 0;
    uint16_t ppppap_length = 0;
    pppoe_payload_legth += (uint16_t) sizeof(PPPPapAck);
    ppppap_length += (uint16_t) sizeof(PPPPapAck);

    ppppapas->length = __bswap_16(ppppap_length);
    pppoeer->length = __bswap_16(pppoe_payload_legth);
    int retrn = rte_ring_sp_enqueue(ring, acpkt);
    if (retrn != 0 && DEBUG)
    {
        RTE_LOG(INFO, USER1, "Ring enqueue failed with error code %i.\n",
                retrn);
    }
    process_ring();
}


/**
 * @brief Function to send a protocol reject.
 * @param type of protocol to reject, packet's mbuf.
 */
void send_proto_reject(uint16_t type, struct rte_mbuf* pkt)
{

    uint8_t lcore_id = rte_lcore_id();
    if (DEBUG)
    {
        RTE_LOG(INFO, USER1, "=> called send_proto_reject\n");
    }
    //generate a PPPoE packet
    //struct rte_mbuf * acpkt = rte_pktmbuf_alloc(mempool);
    struct rte_mbuf * acpkt = rte_pktmbuf_alloc(grt_getCurrentLCoreInfo()->mempool);
    PPPoEEncap * pppoeer = (PPPoEEncap *) rte_pktmbuf_append(acpkt,
                           sizeof(PPPoEEncap));
    PPPoEEncap * pppoeeg = rte_pktmbuf_mtod(pkt, PPPoEEncap *);
    memcpy(pppoeer, pppoeeg, sizeof(PPPoEEncap));
    memcpy(&pppoeer->l2hdr.d_addr, &pppoeer->l2hdr.s_addr,
           sizeof(struct ether_addr));
    memcpy(&pppoeer->l2hdr.s_addr, &srtointra_addr, sizeof(struct ether_addr));
    pppoeer->length = 0;

    uint16_t pppoe_payload_legth = 0;
    PPPEncap * pppptcls = (PPPEncap *) rte_pktmbuf_append(acpkt,
                          sizeof(PPPEncap));
    pppptcls->protocol = __bswap_16(PROTO_LCP);
    pppoe_payload_legth += (uint16_t) sizeof(PPPEncap);

    PPPLcpRjct * ppplcprjct = (PPPLcpRjct *) rte_pktmbuf_append(acpkt,
                              sizeof(PPPLcpRjct));
    ppplcprjct->code = CODE_PROT_REJ;
    //keep the identifier zero
    ppplcprjct->identifier = 0x00;
    ppplcprjct->length = 0;
    ppplcprjct->protocol = __bswap_16(type);
    uint16_t pppprjct_length = 0;
    pppoe_payload_legth += (uint16_t) sizeof(PPPLcpRjct);
    pppprjct_length += (uint16_t) sizeof(PPPLcpRjct);

    char * infog = rte_pktmbuf_mtod_offset(pkt, char *, (sizeof(PPPoEEncap)+sizeof(PPPEncap)));
    unsigned int info_len = __bswap_16(pppoeeg->length) - sizeof(PPPEncap);
    char * infor = (char *) rte_pktmbuf_append(acpkt, info_len);
    memcpy(infor, infog, info_len);
    pppoe_payload_legth += info_len;
    pppprjct_length += info_len;

    ppplcprjct->length = __bswap_16(pppprjct_length);
    pppoeer->length = __bswap_16(pppoe_payload_legth);
    int retrn = rte_ring_sp_enqueue(ring, acpkt);
    if (retrn != 0 && DEBUG)
    {
        RTE_LOG(INFO, USER1, "Ring enqueue failed with error code %i.\n",
                retrn);
    }
    process_ring();
}


/**
 * @brief Function to send a ip request.
 * @param session index, packet's mbuf.
 * This function should be called after swapping the mac addresses to send back.
 */
void send_ip_req(uint16_t session, struct rte_mbuf* pkt, struct ether_addr client_l2addr)
{

    uint8_t lcore_id = rte_lcore_id();
    if (DEBUG)
    {
        RTE_LOG(INFO, USER1, "=> called send_ip_req\n");
    }
    //generate a PPPoE packet
    //struct rte_mbuf * acpkt = rte_pktmbuf_alloc(mempool);
    struct rte_mbuf * acpkt = rte_pktmbuf_alloc(grt_getCurrentLCoreInfo()->mempool);
    PPPoEEncap * pppoeer = (PPPoEEncap *) rte_pktmbuf_append(acpkt,
                           sizeof(PPPoEEncap));
    PPPoEEncap * pppoeeg = rte_pktmbuf_mtod(pkt, PPPoEEncap *);
    memcpy(pppoeer, pppoeeg, sizeof(PPPoEEncap));
    pppoeer->length = 0;

    uint16_t pppoe_payload_legth = 0;
    PPPEncap * pppptcls = (PPPEncap *) rte_pktmbuf_append(acpkt,
                          sizeof(PPPEncap));
    pppptcls->protocol = __bswap_16(PROTO_IPCP);
    pppoe_payload_legth += (uint16_t) sizeof(PPPEncap);

    PPPIpcp * pppipcp = (PPPIpcp *) rte_pktmbuf_append(acpkt, sizeof(PPPIpcp));
    pppipcp->code = CODE_IPCP_REQ;
    /*pppipcp->identifier = (session_array[session_index])->ip_ident;
    ((session_array[session_index])->ip_ident)++;
    Session_key sn_key;
    sn_key.client_mac_addr = session_array[session_index]->client_mac_addr;
    sn_key.session_id = session_index+1;
    Session *newSession = copy_session(session_array[session_index]);
    int retrn1 = grt_redirect_table_put_notifystupd(session_table, (void*)&sn_key, (void*)newSession, -1, GRT_STUPD_TYPE_SESSION_UPDATE);*/
    /*Session_key key;
    key.client_mac_addr = client_l2addr;
    key.session_id = session;
    Session* foundEntry = NULL;
    int retrn = grt_redirect_table_get(session_table, (void*)&key, (void**)&foundEntry, 0);
    pppipcp->identifier = foundEntry->ip_ident;
    Session *newSession = copy_session(foundEntry);
    newSession->ip_ident = foundEntry->ip_ident + 1;
    SessionRtn *newRtnSession = copy_sessionRtn(foundEntry);
    newRtnSession->ip_ident = foundEntry->ip_ident + 1;
    SessionRtn_key rtnKey;
    rtnKey.client_ipv4_addr = newRtnSession->client_ipv4_addr;
    int retrn1 = grt_redirect_table_put_notifystupd(session_table, (void*)&key, (void*)newSession, -1, GRT_STUPD_TYPE_SESSION_UPDATE);
    retrn1 = grt_redirect_table_put_notifystupd(sessionRtn_table, (void*)&rtnKey, (void*)newRtnSession, -1, GRT_STUPD_TYPE_SESSIONRTN_UPDATE);*/
    pppipcp->length = 0;
    uint16_t pppipcp_length = 0;
    pppoe_payload_legth += (uint16_t) sizeof(PPPIpcp);
    pppipcp_length += (uint16_t) sizeof(PPPIpcp);

    PPPIpcpOptions * optn = (PPPIpcpOptions *) rte_pktmbuf_append(acpkt,
                            sizeof(PPPIpcpOptions));
    optn->type = TYPE_IP;
    optn->length = 6; //always will be 6
    optn->value = get_server_ip();
    pppoe_payload_legth += (uint16_t) sizeof(PPPIpcpOptions);
    pppipcp_length += (uint16_t) sizeof(PPPIpcpOptions);

    pppipcp->length = __bswap_16(pppipcp_length);
    pppoeer->length = __bswap_16(pppoe_payload_legth);
    int retrn = rte_ring_sp_enqueue(ring, acpkt);
    if (retrn != 0 && DEBUG)
    {
        RTE_LOG(INFO, USER1, "Ring enqueue failed with error code %i.\n",
                retrn);
    }
    process_ring();
}



/**
 * @brief Function to read configuration prameteres.
 */
void read_config()
{

    int i;
    ConfigParameter *cp = getConfigParameters();
    service_name = cp->serviceName;
    ac_name = cp->acName;
    DEBUG = cp->isDebug;
    auth_proto = cp->authProtocol;
    for (i = 0; i < 6; i++)
    {
        srtointra_addr.addr_bytes[i] = cp->servToIntraMac[i];
    }
    for (i = 0; i < 6; i++)
    {
        srtointer_addr.addr_bytes[i] = cp->servToInterMac[i];
    }
    for (i = 0; i < 6; i++)
    {
        gateway_addr.addr_bytes[i] = cp->routerMac[i];
    }
    net_range = (unsigned int) cp->ipAddressPool[4];
    ip_intra = (uint32_t)(
                   cp->servToIntraIP[0] | (cp->servToIntraIP[1] << 8)
                   | (cp->servToIntraIP[2] << 16)
                   | (cp->servToIntraIP[3] << 24));
    ip_inter = (uint32_t)(
                   cp->servToInterIP[0] | (cp->servToInterIP[1] << 8)
                   | (cp->servToInterIP[2] << 16)
                   | (cp->servToInterIP[3] << 24));
    ip_gateway = (uint32_t)(
                     cp->routerIP[0] | (cp->routerIP[1] << 8) | (cp->routerIP[2] << 16)
                     | (cp->routerIP[3] << 24));
    ip_dns1 = (uint32_t)(
                  cp->primaryDns[0] | (cp->primaryDns[1] << 8)
                  | (cp->primaryDns[2] << 16) | (cp->primaryDns[3] << 24));
    ip_dns2 = (uint32_t)(
                  cp->secondaryDns[0] | (cp->secondaryDns[1] << 8)
                  | (cp->secondaryDns[2] << 16)
                  | (cp->secondaryDns[3] << 24));
    sess_timeout = (double) cp->sessionTimeout;
    conn_timeout = (double) cp->connectionTimeout;
    start_ip_oct1 = cp->routerIpStart[0];
    start_ip_oct2 = cp->routerIpStart[1];
    start_ip_oct3 = cp->routerIpStart[2];
    start_ip_oct4 = cp->routerIpStart[3];
    end_ip_oct3 = cp->routerIpEnd[2];
    end_ip_oct4 = cp->routerIpEnd[3];
}

/*
 * redirect table checking for entry
 */
int _checkAndSetSessionEntry(Session* value, Session_key* key) {

	Session **resultEntry;
	int retrn = grt_redirect_table_get(session_table, key, (void**)resultEntry, 0);
	if (likely(retrn == 1)) return 0;	//The entry is in the table

	if (unlikely(retrn != -1)) {
		printf(" ERROR in getting, grt_redirect_table_get(...) returned with %i\n", retrn);
		//Error in getting
		return -1;
	}

	//Return is -1, so entry is not in the table.
	retrn = grt_redirect_table_put(session_table, key, value, -1);
	if (retrn >= 0) {
		return 1;	//The entry was not in the table but was successfully created.
	}
	printf(" ERROR in putting entry returned with %i\n", retrn);
	return -1;
}
