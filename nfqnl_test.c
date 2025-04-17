#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>

#include <string.h>
#include <glib.h>
#include <time.h>

#include <libnet.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

GHashTable* block;

void load_blocked_urls(const char* filename)
{
    FILE* fp = fopen(filename, "r");
    if (!fp)
    {
        perror("failed");
        exit(1);
    }

    char line[512];
    while (fgets(line, sizeof(line), fp))
    {
        char* comma = strchr(line, ',');
        if (!comma) continue;

        char* url = comma + 1;
        url[strcspn(url, "\r\n")] = 0;

        char* key = g_strdup(url);
        g_hash_table_insert(block, key, key);
    }
    fclose(fp);
}

int is_blocked(const char* host)
{
    gboolean found = g_hash_table_contains(block, host);
    printf("[DEBUG] is_blocked('%s') → %d\n", host, found);
    return found;
}

void dump(unsigned char* buf, int size) {
    int i;
    for (i = 0; i < size; i++) {
        if (i != 0 && i % 16 == 0)
            printf("\n");
        printf("%02X ", buf[i]);
    }
    printf("\n");
}

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi;
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);
    if (ret >= 0) {
		printf("payload_len=%d\n", ret);
        dump(data, ret);
    }

	fputc('\n', stdout);

	return id;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
    double elapsed;
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    printf("Call Back function checking\n");
	u_int32_t id = print_pkt(nfa);
	printf("entering callback\n");
    unsigned char* payload;

    int len = nfq_get_payload(nfa, &payload);
    if(len >= 0)
    {
        struct libnet_ipv4_hdr* ip_hdr = (struct libnet_ipv4_hdr*)(payload);
        if(ip_hdr->ip_p != 0x06)
        {
            printf("ip protocol is %02x\n", ip_hdr->ip_p);
            clock_gettime(CLOCK_MONOTONIC, &end);
            elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
            printf("[Debug]time: %.9fs\n", elapsed);
            return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
        }
        struct libnet_tcp_hdr* tcp_hdr = (struct libnet_tcp_hdr*)(payload + ip_hdr->ip_hl * 4);

        unsigned char* http_ptk = payload + (ip_hdr->ip_hl * 4) + (tcp_hdr->th_off * 4);

        char* host_start = strstr((char*)http_ptk, "Host: ");
        if (host_start != NULL) {
            host_start += 6;
            char* host_end = strstr(host_start, "\r\n");
            if (host_end != NULL) {
                int host_length = host_end - host_start;
                char host[256] = {0,};
                strncpy(host, host_start, host_length);
                host[host_length] = '\0';

                printf("Found Host: '%s'\n", host);

                printf("Checking map...\n");

                if (is_blocked(host)) {
                    printf("Blocking...\n");
                    clock_gettime(CLOCK_MONOTONIC, &end);
                    elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
                    printf("[Debug]time: %.9fs\n", elapsed);
                    return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
                } else {
                    printf("Not Blocked!\n");
                    clock_gettime(CLOCK_MONOTONIC, &end);
                    elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
                    printf("[Debug]time: %.9fs\n", elapsed);
                    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
                }
            }
        }
        clock_gettime(CLOCK_MONOTONIC, &end);
        elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
        printf("[Debug]time: %.9fs\n", elapsed);
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }
}

int main(int argc, char **argv)
{
    block = g_hash_table_new(g_str_hash, g_str_equal);
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
    char files_loc[512] = {0,};
    snprintf(files_loc, sizeof(files_loc), "./%s", argv[1]);
    load_blocked_urls(files_loc);
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}

