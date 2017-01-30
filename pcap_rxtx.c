#include"virtio.h"
#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/eventfd.h>

static bpf_u_int32 net;		/* Our IP */
pcap_t *pcap_init(char *iname)
{
	pcap_t *handle;			/* Session handle */
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	bpf_u_int32 mask;		/* Our netmask */

	/* Define the device */

	printf("vvdn debug :opening pcap on interface %s\n",iname);
	dev = iname;

	/* Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}
	/* Open the session in promiscuous mode */
	handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return;
	}

	return handle;
}

extern volatile struct vring_desc *rx_desc_base; 
extern volatile struct vring_used  *rx_used; 
extern volatile struct vring_avail *rx_avail;
extern volatile int rxirqfd;
extern int rx_desc_count;
extern volatile connected_to_guest;
extern int vhost_hlen;


uint64_t guestphyddr_to_vhostvadd(uint64_t gpaddr);

unsigned char mac_address[6] = {0xb8,0x2a,0x72,0xc4,0x26,0x45};
unsigned char broadcast_mac_address[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
void *pcap_rx_thread(void *arg)
{
	struct bpf_program fp;		/* The compiled filter */
	//char filter_exp[] = "ether dst 00:00:00:00:00:01 ";	/* The filter expression */
	//char filter_exp[] = "ether dst b8:2a:72:c4:26:45 or ether dst ff:ff:ff:ff:ff:ff  or  arp";	/* The filter expression */
	//char filter_exp[] = "ether dst b8:2a:72:c4:26:45 or  arp";	/* The filter expression */
	char filter_exp[] = "ether dst 00:00:00:00:00:01 or  arp";	/* The filter expression */
	//char filter_exp[] = "";	/* The filter expression */
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */
	pcap_t *handle;
	void  *tmp;
	uint16_t rx_desc_num = 0,rx_header_desc_num = 0,rx_avail_ring_no = 0,rx_used_ring_no = 0;
	unsigned char  *packet_addr;
	uint32_t packet_len;
	uint16_t avail_idx,used_idx;

	handle = (pcap_t *) arg;

	printf("starting rx thread with pcap handle : %p\n",handle);

	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return;
	}

	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return;
	}

	while(1) {
		/* Grab a packet */
		packet = pcap_next(handle, &header);
		packet_addr = (unsigned char *) packet;
		/* Print its length */


#if 1
		if(header.len > 0 && connected_to_guest) {

			//printf("received a packet with length of [%d]\n", header.len);

			if(packet ) {


			
				//printf("vhost rx packet at address : %p len : %d\n",(void *) packet,header.len);
				//printf("vhost rx packet len : %d\n",header.len);

				avail_idx = rx_avail->idx;
				used_idx = rx_used->idx;

				if((avail_idx - used_idx) == 0) {
					printf("Dropping packet\n");
					continue;
				}
				
				//printf("avail_idx : %d and used_idx : %d diff  : %d\n",avail_idx,used_idx,avail_idx-used_idx);


				rx_desc_num = rx_avail->ring[rx_avail_ring_no];
				rx_header_desc_num = rx_desc_num;
				tmp = (void *)guestphyddr_to_vhostvadd(rx_desc_base[rx_desc_num].addr);
				//printf("header desc no : %d\n",rx_desc_num);
				//printf("tmp( virtio header ): %p \n",tmp);
				memset(tmp,0,vhost_hlen);
				//printf("virtio header done\n");
				rx_desc_num = rx_desc_base[rx_desc_num].next;
				//printf("packet data desc no : %d\n",rx_desc_num);

				if(rx_desc_base[rx_desc_num].len < header.len) {
					printf("receive desc buff len : %d and packet len : %d ,so dropping packet\n"
					,rx_desc_base[rx_desc_num].len,header.len);
					continue;
				}
				//printf("receive desc buff len : %d and packet len : %d\n",rx_desc_base[rx_desc_num].len,header.len);

				tmp = (void *)guestphyddr_to_vhostvadd(rx_desc_base[rx_desc_num].addr);
				//printf("tmp ( packet data ): %p \n",tmp);
				packet_len = header.len;
				memcpy(tmp,packet_addr,packet_len);
				//printf("packet copied to VM memory\n");
				rx_avail_ring_no = (rx_avail_ring_no + 1)%rx_desc_count;
				wmb();

				//rx_used->ring[rx_used_ring_no].id = rx_desc_num;
				rx_used->ring[rx_used_ring_no].id = rx_header_desc_num;
				rx_used->ring[rx_used_ring_no].len = vhost_hlen + packet_len;
				//rx_desc_num = (rx_desc_num+2)%rx_desc_count;
				rx_used_ring_no = (rx_used_ring_no +1)%rx_desc_count;
				wmb();
				rx_used->idx++;
				wmb();
				eventfd_write(rxirqfd, (eventfd_t)1);
				wmb();
				//printf("packets received : %d\n",rx_used->idx);
			}
			else {
				//printf("packet address is NULL\n");
			}
		}
#endif
	}
	/* And close the session */
}

void pcap_tx(pcap_t *handle, void *packet,int size)
{
	pcap_inject(handle,packet,size);
}
