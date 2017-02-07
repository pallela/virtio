#include<stdio.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<string.h>
#include<sys/un.h>
#include<stdlib.h>
#include"virtio.h"
#include <sys/eventfd.h>
#include<sys/mman.h>
#include<sys/stat.h>
#include<pthread.h>
#include<signal.h>
#include"pcap_rxtx.h"
#include<semaphore.h>

#define SOCKPATH "/usr/local/var/run/openvswitch/vhost-user1"


pcap_t *handle;
uint64_t guestphyddr_to_vhostvadd(uint64_t gpaddr);
uint64_t qemuvaddr_to_vhostvadd(uint64_t qaddr);



void write_to_file(void *addr, uint64_t mapsize,char *fpath)
{
	FILE *fp = fopen(fpath,"w");
	fwrite(addr,1,mapsize,fp);
	fclose(fp);
}

void print_hex(unsigned char *buff, int len)
{
	int i;

	printf("\n");

	for(i=0;i<len;i++) {

		if(i%32 == 0){
			printf("\n");
		}

		printf("%02x ",buff[i]);
	}
	printf("\n\n");
}

#define RECV 0

//char sample_rx_buffer[100] = "This is sample rx data This is sample rx data This is sample rx data This is sample rx data This is ";
char sample_rx_buffer[] =  {
	0xff,0xff,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,
	0x00,0x01,0x08,0x06,0x00,0x01,0x08,0x00,0x06,0x04,
	0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x01,0xc0,0xa8,
	0x0a,0x0a,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0xa8,
	0x0a,0x14
};

volatile int kickfd = -1;
volatile int txirqfd = -1;
volatile int rxirqfd = -1;

struct address_translation translation_table[10];
int translation_table_count = -1;

volatile struct vring_desc *tx_desc_base;
int tx_desc_count = 0;
volatile struct vring_desc *rx_desc_base; 
int rx_desc_count = 0;
volatile struct vring_avail *tx_avail;
volatile struct vring_used  *tx_used; 
volatile struct vring_avail *rx_avail;
volatile struct vring_used  *rx_used; 

volatile int tx_vring_ready = 0, rx_vring_ready = 0;

volatile connected_to_guest = 0;
uint16_t tx_last_avail_idx;
uint16_t tx_last_used_idx;
int vhost_hlen = 0;

sem_t tx_start_wait_sem,rx_start_wait_sem;
sem_t tx_clean_wait_sem,rx_clean_wait_sem;


static unsigned char rx_packet_buff[10*1024];
static unsigned char tx_packet_buff[10*1024];


void * transmit_thread(void *args)
{
	uint64_t tx_kick_count;
	int i;
	uint16_t cur_avail_idx = 0,new_avail_descs = 0;;
	uint16_t cur_used_idx = 0,rx_desc_num = 0;
	uint16_t rx_ring_no = 0,temp;
	int packet_no = 0;
	unsigned char *packet_addr,*tmp;
	int packet_len;
	int desc_no,TXB = 0;
	struct virtio_net_hdr_mrg_rxbuf *packet_hdr;
	struct vring_desc temp_desc;
	int tx_buff_len = 0;
	int tx_cleanup_required = 0;


	printf("starting transmit thread \n");


	while(1) {

		if(connected_to_guest) {

			temp = tx_avail->idx;
			cur_avail_idx = tx_last_avail_idx;
			new_avail_descs = temp - tx_last_avail_idx ;
			rmb();// read correct values before proceeding
			tx_last_avail_idx = temp;

			//printf("cur_avail_idx : %d new_avail_descs : %d\n",cur_avail_idx,new_avail_descs);
			cur_avail_idx = cur_avail_idx % tx_desc_count;
			//printf("(remainder) cur_avail_idx : %d new_avail_descs : %d\n",cur_avail_idx,new_avail_descs);


			//printf("tx_avail->flags : %04x tx_avail->idx : %04x\n",tx_avail->flags,tx_avail->idx);

			//i = 0;
			while(new_avail_descs--){

				//printf("packet no : %d\n",packet_no);
				desc_no = tx_avail->ring[cur_avail_idx];
				//desc_no = (desc_no + 1)%tx_desc_count;
				packet_len = tx_desc_base[desc_no].len;
				TXB +=  packet_len;
				//printf("total sent bytes : %d\n",TXB);

				#if 1

				//printf("avail desc [%04d] : %04d\n",cur_avail_idx,tx_avail->ring[cur_avail_idx]);
				//desc_no = tx_avail->ring[cur_avail_idx];
				tx_buff_len = 0;

				while(1) {

					memcpy((void *)&temp_desc,(void *)&tx_desc_base[desc_no],sizeof(struct vring_desc));

					//if(tx_desc_base[desc_no].flags & VRING_DESC_F_NEXT) {
					if(temp_desc.flags & VRING_DESC_F_NEXT) {
						packet_addr = (unsigned char *) guestphyddr_to_vhostvadd(tx_desc_base[desc_no].addr);
						packet_len = tx_desc_base[desc_no].len;
						//printf("(next flag) desc no : %d len : %d\n",desc_no,packet_len);
						//print_hex(packet_addr,packet_len);
						//desc_no = (desc_no + 1)%tx_desc_count;
						desc_no = tx_desc_base[desc_no].next;
						memcpy(tx_packet_buff + tx_buff_len,packet_addr,packet_len);
						tx_buff_len += packet_len;
					}
					else {
						packet_addr = (unsigned char *) guestphyddr_to_vhostvadd(tx_desc_base[desc_no].addr);
						packet_len = tx_desc_base[desc_no].len;
						//printf("desc no : %d len : %d\n",desc_no,packet_len);
						rmb();
						packet_hdr = (struct virtio_net_hdr_mrg_rxbuf*) packet_addr;

						//printf("num buffers : %02x\n",packet_hdr->num_buffers);
						//printf("flags : %02x\n",packet_hdr->hdr.flags);
						//printf("gso_type : %02x\n",packet_hdr->hdr.gso_type);
						//printf("hdr_len : %02x\n",packet_hdr->hdr.hdr_len);
						//printf("gso_size : %02x\n",packet_hdr->hdr.gso_size);
						//printf("csum_start : %02x\n",packet_hdr->hdr.csum_start);
						//printf("csum_offset : %02x\n",packet_hdr->hdr.csum_offset);

						//print_hex(packet_addr,packet_len);
						//desc_no = tx_desc_base[desc_no].next;
						//printf("next desc no may be : %d and next desc data len : %d\n",
						//desc_no,tx_desc_base[desc_no].len);
						//pcap_tx(handle,packet_addr+vhost_hlen,packet_len-vhost_hlen);

						memcpy(tx_packet_buff + tx_buff_len,packet_addr,packet_len);
						tx_buff_len += packet_len;
						//print_hex(tx_packet_buff,tx_buff_len);
						pcap_tx(handle,tx_packet_buff+vhost_hlen,tx_buff_len-vhost_hlen);



						#if 0 /* loopback */
						printf("loopback packet_no : %d\n",packet_no);
						tmp = (unsigned char *)guestphyddr_to_vhostvadd(rx_desc_base[rx_desc_num].addr);
						memset(tmp,0,10);
						tmp = (unsigned char *)guestphyddr_to_vhostvadd(rx_desc_base[rx_desc_num+1].addr);
						memcpy(tmp,packet_addr,packet_len);
						rx_used->ring[rx_ring_no].id = rx_desc_num;
						rx_used->ring[rx_ring_no].len = 10 + packet_len;
						rx_desc_num = (rx_desc_num+2)%rx_desc_count;
						rx_ring_no = (rx_ring_no +1)%rx_desc_count;
						wmb();
						rx_used->idx++;
						wmb();
						eventfd_write(rxirqfd, (eventfd_t)1);
						wmb();
						printf("packets received : %d\n",rx_used->idx);
						#endif

						break;
					}
				}
				#endif

				packet_no++;	

				tx_used->ring[cur_used_idx].id = tx_avail->ring[cur_avail_idx];
				tx_used->ring[cur_used_idx].len = tx_desc_base[tx_avail->ring[cur_avail_idx]].len;
				wmb();
				tx_used->idx++;
				wmb();

				//eventfd_write(txirqfd, (eventfd_t)1);
				
				//printf("packets transmitted %d\n\n",tx_used->idx);

				cur_avail_idx = (cur_avail_idx + 1)%tx_desc_count;
				cur_used_idx  = (cur_used_idx + 1) %tx_desc_count;

			}
			//printf("tx_avail->idx : %d and tx_used->idx: %d\n",tx_avail->idx,tx_used->idx);


			//tx_used->idx = tx_avail->idx;
			wmb();
			eventfd_write(txirqfd, (eventfd_t)1);
			wmb();


			#if 0
			printf("rx_avail->idx : %d\n",rx_avail->idx);
			for(i=0;i < rx_avail->idx;i++) {
				printf("rx_avail->ring[%04d] = %04d\n",i,rx_avail->ring[i]);
		
			}
			#endif

			#if 0 /* able to show correctly in VM */
			if(rx_avail) {

				static int ft = 0;
				unsigned char  *tmp;

				if(ft == 0)
				{
					printf("rx first packet\n");

					tmp = (unsigned char *)guestphyddr_to_vhostvadd(rx_desc_base[0].addr);
					memset(tmp,0,10);
					tmp = (unsigned char *)guestphyddr_to_vhostvadd(rx_desc_base[1].addr);
					memcpy(tmp,sample_rx_buffer,sizeof(sample_rx_buffer));
					rx_used->ring[0].id = 0;
					rx_used->ring[0].len = 10 + sizeof(sample_rx_buffer);


					tmp = (unsigned char *)guestphyddr_to_vhostvadd(rx_desc_base[2].addr);
					memset(tmp,0,10);
					tmp = (unsigned char *)guestphyddr_to_vhostvadd(rx_desc_base[3].addr);
					memcpy(tmp,sample_rx_buffer,sizeof(sample_rx_buffer));
					rx_used->ring[1].id = 2;
					rx_used->ring[1].len = 10 + sizeof(sample_rx_buffer);

					tmp = (unsigned char *)guestphyddr_to_vhostvadd(rx_desc_base[4].addr);
					memset(tmp,0,10);
					tmp = (unsigned char *)guestphyddr_to_vhostvadd(rx_desc_base[5].addr);
					memcpy(tmp,sample_rx_buffer,sizeof(sample_rx_buffer));
					rx_used->ring[2].id = 4;
					rx_used->ring[2].len = 10 + sizeof(sample_rx_buffer);


					rx_used->idx = 3;

					wmb();

					eventfd_write(rxirqfd, (eventfd_t)1);
					wmb();
					ft = 1;
				}
			}
			#endif
		}
		//usleep(1000000);
		else {
			cur_used_idx = 0;
			cur_avail_idx = 0;
			if(tx_cleanup_required) {
				tx_cleanup_required = 0;
				printf("tx thread, cleanup done\n");
				sem_post(&tx_clean_wait_sem);
			}
			printf("tx thread, waiting for connection\n");
			sem_wait(&tx_start_wait_sem);
			tx_cleanup_required = 1;
			printf("tx thread, starting processing now\n");
		}
		usleep(1000);

	}


}

unsigned char memory_table[100*1024];
pthread_t tx_thread;
pthread_t rx_thread;


uint64_t guestphyddr_to_vhostvadd(uint64_t gpaddr)
{
	int i;
	uint64_t offset;
	uint64_t ret;
	for(i=0;i<translation_table_count;i++) {
		if(gpaddr >= translation_table[i].guestphyaddr && gpaddr <=  translation_table[i].guestphyaddr + translation_table[i].len){
			offset = (gpaddr - translation_table[i].guestphyaddr);
			//printf("found gpaddr : %llx in table entry : %d offset : %llx\n",
			//		(unsigned long long int)gpaddr,i,(unsigned long long int)offset);
			ret =  translation_table[i].vhostuservirtaddr + offset + translation_table[i].offset;
			//printf("translated address : %llx\n",(unsigned long long int) ret);
			return ret;
		}
	}

	return 0;
}


int guestphyddr_to_vhostvadd_list(uint64_t gpaddr, int len,struct sg_list *list, int max_list_len)
{
	int i;
	uint64_t offset;
	uint64_t vhostaddr;
	uint64_t phystartaddr,phyendaddr;
	uint64_t rem_len_in_block,len_used;

	list->num_elements = 0;

	while(len) {

		for(i=0;i<translation_table_count;i++) {
			phystartaddr = translation_table[i].guestphyaddr;
			phyendaddr = translation_table[i].guestphyaddr + translation_table[i].len;
			if(gpaddr >= phystartaddr && gpaddr <= phyendaddr){

				offset = (gpaddr - translation_table[i].guestphyaddr);

				vhostaddr =  translation_table[i].vhostuservirtaddr + offset + translation_table[i].offset;

				list->chunks[list->num_elements].addr = vhostaddr;
				rem_len_in_block = ((translation_table[i].vhostuservirtaddr + translation_table[i].len) - vhostaddr + 1);
				len_used =  len < rem_len_in_block ? len : rem_len_in_block;
				len = len - len_used;
				list->chunks[list->num_elements].len = len_used ;

				list->num_elements++;
				if(list->num_elements == max_list_len && len) {
					printf("remaining len to translate : %d\n",len);
					return -1;
				}
			}
		}
	}

	return 0;

}

uint64_t qemuvaddr_to_vhostvadd(uint64_t qaddr)
{
	int i;
	uint64_t offset;
	for(i=0;i<translation_table_count;i++) {
		if(qaddr >= translation_table[i].qemuvirtaddr && qaddr <=  translation_table[i].qemuvirtaddr + translation_table[i].len){
			offset = (qaddr - translation_table[i].qemuvirtaddr);
			printf("found qaddr : %llx in table entry : %d offset : %llx\n",
			(unsigned long long int)qaddr,i,(unsigned long long int)offset);
			return translation_table[i].vhostuservirtaddr + offset + translation_table[i].offset;
		}
	}

	return 0;
}

void print_desc(volatile struct vring_desc *tmp,int count)
{

	int i;
	void *packet_data;

	for(i=0;i<count;i++) {
		printf("desc[%04d] (%016llx) addr : %016llx len : %08x flags : %04x next : %04x\n",
				i,(unsigned long long int) &tmp[i],
				(unsigned long long int) tmp[i].addr,
				(unsigned int) tmp[i].len,
				(unsigned int) tmp[i].flags,
				(unsigned int) tmp[i].next);
			#if 1
			if(tmp[i].len) {
				packet_data = (void *) guestphyddr_to_vhostvadd(tmp[i].addr);
				printf("packet data (%d bytes) at address : %p\n",tmp[i].len,packet_data);
				print_hex(packet_data,tmp[i].len);
			}
			#endif
	}

}

#define PRINT_TX_DESC_AND_PACKETS 1
#if 1
void snapshot(int signum)
{

	int i;

	printf("address translation table : %d entries\n",translation_table_count);
	printf("GPA              ");
	printf("QVA              ");
	printf("VUVA              ");
	printf("LEN               ");
	printf("OFFSET            \n");
	for(i = 0 ;i < translation_table_count ;i ++) {
		char filename[20];
		printf("%016llx %016llx %016llx %016llx %016llx\n",
				(unsigned long long int) translation_table[i].guestphyaddr,
				(unsigned long long int) translation_table[i].qemuvirtaddr,
				(unsigned long long int) translation_table[i].vhostuservirtaddr,
				(unsigned long long int) translation_table[i].len,
				(unsigned long long int) translation_table[i].offset);
		//sprintf(filename,"part%d.dat",i);
		//write_to_file((void *)translation_table[i].vhostuservirtaddr,translation_table[i].len,filename);
	}

#if PRINT_TX_DESC_AND_PACKETS

	//printf("Transmit descriptors\n");
	//print_desc(tx_desc_base,tx_desc_count);
	printf("Receive Descriptors\n");
	print_desc(rx_desc_base,rx_desc_count);
#endif

	#if 0
	printf("tx_avail->flags : %04x  tx_avail->idx : %d\n",tx_avail->flags,tx_avail->idx);
	printf("tx_used->flags : %04x  tx_used->idx : %d\n",tx_used->flags,tx_used->idx);

	for(i = 0;i <= tx_avail->idx; i++) {
		printf("tx_avail->ring[%05d] = %05d\n",i,tx_avail->ring[i]);
	}
	#endif

	#if 0

	tx_used->flags = 0;
	tx_used->idx = 2;

	tx_used->ring[0].id = tx_avail->ring[0];
	tx_used->ring[0].len = tx_desc_base[tx_avail->ring[0]].len;
	eventfd_write(txirqfd, (eventfd_t)1);

	#endif

}
#endif


#if 1
void search_pattern(int signum)
{

	int i,j;
	int len;
	unsigned char *mem;
	char search_str[] = "xilinx virtio string to be searched";
	unsigned char modify = 0xAB;

	for(i = 0 ;i < translation_table_count ;i ++) {
		mem =  (unsigned char *) translation_table[i].vhostuservirtaddr;
		len =  translation_table[i].len;
		for(j=0;j<len-sizeof(search_str);j++) {
			if(memcmp(search_str,mem+j,sizeof(search_str)) == 0) {
				printf("found in part %d at offset : %x\n",i,j);
				memset(mem+j,modify,sizeof(search_str));
			}
		}
	}
}
#endif


main()
{
	int sockfd;
	int newsockfd;
	struct sockaddr_un local,remote;
	int len,t,i;
	unsigned char rxbuff[1024],txbuff[1024];
	int recv_bytes,ret;
	int fdbytes;
        struct vhost_user_msg *msg;
	struct vhost_vring_file file;
	struct vhost_memory *table = (struct vhost_memory *) memory_table;


	sem_init(&tx_start_wait_sem,0,0);
	sem_init(&rx_start_wait_sem,0,0);
	sem_init(&tx_clean_wait_sem,0,0);
	sem_init(&rx_clean_wait_sem,0,0);

	handle  = pcap_init("eth0");
	printf("pcap handle : %p\n",handle);

	#if 1
	if(pthread_create(&tx_thread,NULL,transmit_thread,NULL)){
		printf("transmit thread creation failed\n");
	}else {
		printf("transmit thread creation success\n");
	}
	#endif

	#if 1
	if(pthread_create(&rx_thread,NULL,pcap_rx_thread,handle)){
		printf("receive thread creation failed\n");
	}else {
		printf("receive thread creation success\n");
	}
	#endif

	signal(SIGUSR1,snapshot);
	signal(SIGUSR2,search_pattern);

	sockfd = socket(AF_UNIX,SOCK_STREAM,0);

	if(sockfd > 0)  {
		printf("sockfd : %d\n",sockfd);
	} else {
		perror("sockfd: ");
	}

	local.sun_family = AF_UNIX;
	strcpy(local.sun_path,SOCKPATH);
	unlink(local.sun_path);
	len = strlen(local.sun_path) + sizeof(local.sun_family);

	if(bind(sockfd,(struct sockaddr *)&local,len) == -1) {
		perror("bind : ");
		exit(1);
	}

	if(listen(sockfd,1) == -1) {
		perror("listen : ");
		exit(1);
	}

	printf("Waitng for a connection\n");

	t =  sizeof(remote);

	if((newsockfd = accept(sockfd,(struct sockaddr *)&remote,&t)) == -1) {
		perror("accept : ");
		exit(1);
	}

	printf("connected\n");


	while(1) {

		memset(rxbuff,0,1024);
		memset(txbuff,0,1024);

		#if RECV
		recv_bytes = recv(newsockfd,rxbuff,12,0);
		if(recv_bytes == 0) {
			perror("recv : ");
			printf("received 0 bytes exiting\n");
			close(newsockfd);
			close(sockfd);
			exit(1);
		}

		msg = (struct vhost_user_msg *) rxbuff;

		if(msg->size != 0) {
			recv_bytes += recv(newsockfd,rxbuff+12,msg->size,0);
		}


		printf("received total bytes : %d\n",recv_bytes);
		#else /*RECVFROM*/


		msg = (struct vhost_user_msg *) rxbuff;

		ret = read_vhost_message(newsockfd,msg);

		if(ret == 0) {
			int check;
			printf("sleep 5 due to ret = 0, vm might be shutdown\n");
			if(connected_to_guest && tx_avail && rx_avail && tx_vring_ready && rx_vring_ready) {
				connected_to_guest = 0;
				//sleep(5);
				printf("sockfd closed : waiting for rx thread and tx thread to cleanup\n");
				check = sem_wait(&tx_clean_wait_sem);
				printf("check  : %d\n",check);
				printf("sockfd closed : tx cleanup done for poweroff\n");
				check = sem_wait(&rx_clean_wait_sem);
				printf("check  : %d\n",check);
				printf("sockfd closed : rx cleanup done for poweroff\n");
				tx_last_avail_idx = 0;
				printf("sockfd closed : unmapping translation table\n");
				{
					int i;
					for(i=0;i<translation_table_count;i++ ) {
						munmap((void *)translation_table[i].vhostuservirtaddr,translation_table[i].len);
						close(translation_table[i].mapfd);
					}
					translation_table_count = -1;
				}
				tx_avail = NULL;
				tx_vring_ready = 0;
				rx_avail = NULL;
				rx_vring_ready = 0;	
				close(txirqfd); txirqfd = -1;
				close(rxirqfd); rxirqfd = -1;
				close(kickfd); kickfd = -1;
			}else {
				printf("already get_vring_base must have done cleanup\n");
			}
			close(newsockfd);
			printf("waiting for new connection\n");
			if((newsockfd = accept(sockfd,(struct sockaddr *)&remote,&t)) == -1) {
				perror("accept : ");
				exit(1);
			}

			printf("connected\n");


			continue;
		}
		else {
			printf("ret = %d\n",ret);
			print_hex(rxbuff,msg->size + 12);
		}
		#endif




		printf("msg.request : %d name : %s payload size : %d\n",msg->request,req_names[msg->request],msg->size);
		//print_hex(rxbuff,recv_bytes);
		print_hex(rxbuff,msg->size);

		switch(msg->request) {

			case VHOST_USER_GET_FEATURES:
				msg = (struct vhost_user_msg *) rxbuff;
				msg->payload.u64 = VHOST_SUPPORTED_FEATURES;
				msg->size = sizeof(msg->payload.u64);
				send_vhost_message(newsockfd,msg);
				printf("payload : %016llx\n",(unsigned long long int)msg->payload.u64);
				printf("sent bytes : %d\n",20);

				break;

			case VHOST_USER_SET_FEATURES:
				msg = (struct vhost_user_msg *) rxbuff;
				printf("payload is %016llx\n",(unsigned long long int)msg->payload.u64);
				printf("Mergeable RX buffers %s, virtio 1 %s\n",
						(msg->payload.u64 & (1 << VIRTIO_NET_F_MRG_RXBUF)) ? "on" : "off",
						(msg->payload.u64 & (1ULL << VIRTIO_F_VERSION_1)) ? "on" : "off");

				if (msg->payload.u64 &
						((1 << VIRTIO_NET_F_MRG_RXBUF) | (1ULL << VIRTIO_F_VERSION_1))) {
					vhost_hlen = sizeof(struct virtio_net_hdr_mrg_rxbuf);
				} else {
					vhost_hlen = sizeof(struct virtio_net_hdr);
				}

				printf("vhost_hlen is %d\n",vhost_hlen);


				break;


			case  VHOST_USER_GET_PROTOCOL_FEATURES:
				msg = (struct vhost_user_msg *) rxbuff;
				msg->payload.u64 = VHOST_USER_PROTOCOL_FEATURES;
				msg->size = sizeof(msg->payload.u64);
				send_vhost_message(newsockfd,msg);
				printf("sent payload : %016llx\n",(unsigned long long int)msg->payload.u64);
				printf("\n\nsent bytes : %d\n",20);
				printf("\n\n");

				break;
			case  VHOST_USER_SET_PROTOCOL_FEATURES:
				msg = (struct vhost_user_msg *) rxbuff;
				printf("protocol features : %016llx and we provided : %016llx\n",(unsigned long long int)msg->payload.u64,(unsigned long long int)VHOST_USER_PROTOCOL_FEATURES);	
				break;

			case VHOST_USER_GET_QUEUE_NUM:
				msg = (struct vhost_user_msg *) rxbuff;
				//msg->payload.u64 = 0x8000;
				msg->payload.u64 = 1;
				msg->size = sizeof(msg->payload.u64);
				send_vhost_message(newsockfd,msg);
				printf("sent payload : %016llx\n",(unsigned long long int)msg->payload.u64);
				printf("\n\nsent bytes : %d\n",20);
				printf("\n\n");
				break;

			case VHOST_USER_SET_VRING_CALL:
				msg = (struct vhost_user_msg *) rxbuff;
				printf("payload : %016llx\n",(unsigned long long int)msg->payload.u64);
				if (msg->payload.u64 & VHOST_USER_VRING_NOFD_MASK) {
					printf("some issue : fd = -1\n");
				}
				file.index = msg->payload.u64 & VHOST_USER_VRING_IDX_MASK;
				file.fd = msg->fds[0];
				printf("vring call idx:%d file:%d\n", file.index, file.fd);
				if(file.index == 1) {
					if(txirqfd > 0) {
						close(txirqfd);
					}
					txirqfd =  file.fd;
				}
				else if(file.index ==  0) {
					if(rxirqfd > 0) {
						close(rxirqfd);
					}
					rxirqfd =  file.fd;
				}


				break;

			case VHOST_USER_SET_VRING_ENABLE:
				msg = (struct vhost_user_msg *) rxbuff;
				printf("payload.state.index : %u\n",msg->payload.state.index);
				printf("payload.state.num   : %u\n",msg->payload.state.num);
				if(msg->payload.state.index == 0) {
					rx_vring_ready = 1;
					printf("rx vring is ready when rx_avail : %p and tx_avail : %p\n",rx_avail,tx_avail);
				}
				else if(msg->payload.state.index == 1) {
					tx_vring_ready = 1;
					printf("tx vring is ready when rx_avail : %p and tx_avail : %p\n",rx_avail,tx_avail);
				}
				if(tx_avail && rx_avail && tx_vring_ready && rx_vring_ready && !connected_to_guest) {
					connected_to_guest = 1;
					printf("Now connected to guest\n");
					sem_post(&tx_start_wait_sem);
					sem_post(&rx_start_wait_sem);
				}
				break;

			case VHOST_USER_SET_MEM_TABLE:
				msg = (struct vhost_user_msg *) rxbuff;
				printf("processing VHOST_USER_SET_MEM_TABLE , copying %u bytes\n",msg->size);
				memcpy(table,&(msg->payload.memory),msg->size);
				printf("nr_regions : %u\n",table->nregions);
				printf("padding    : %u\n",table->padding);


				for(i=0;i<table->nregions;i++) {
					printf("region[%04d]  gpaddr : %llx memory_size : %llx userspace_addr : %llx \
							mmap_offset : %llx fd[%d] : %d alignment : %llx\n",
							i,
							(unsigned long long int) table->regions[i].guest_phys_addr,
							(unsigned long long int) table->regions[i].memory_size,
							(unsigned long long int) table->regions[i].userspace_addr,
							(unsigned long long int) table->regions[i].mmap_offset,
							i,
							msg->fds[i],
							(unsigned long long int) get_blk_size(msg->fds[i])\
					      );





#if 1
					if(table->regions[i].memory_size) {
						void *addr;
						uint64_t mapsize,alignment,mapped_size;
						alignment = get_blk_size(msg->fds[i]);
						mapsize = RTE_ALIGN_CEIL(table->regions[i].memory_size +  table->regions[i].mmap_offset,alignment);
						printf("map size : %llx\n",(unsigned long long int) mapsize);
						addr = mmap(NULL,mapsize,PROT_READ | PROT_WRITE, MAP_SHARED,msg->fds[i],0);
						printf("mmap address : %p\n",addr);

						translation_table[i].guestphyaddr = table->regions[i].guest_phys_addr;
						translation_table[i].qemuvirtaddr = table->regions[i].userspace_addr;
						translation_table[i].vhostuservirtaddr = (uint64_t) addr;
						translation_table[i].len = mapsize;
						translation_table[i].offset = table->regions[i].mmap_offset;
						translation_table[i].mapfd = msg->fds[i];

						//write_to_file(addr,mapsize,"/tmp/image.dat");
					}
#endif
				}

				wmb(); // write barrier so that other cpus can access correct data immediately

				translation_table_count = i;
				printf("address translation table : %d entries\n",translation_table_count);
				printf("GPA              ");
				printf("QVA              ");
				printf("VUVA              ");
				printf("LEN               ");
				printf("OFFSET            \n");
				#if 1
				for(i = 0 ;i < translation_table_count ;i ++) {
					char filename[20];
					printf("%016llx %016llx %016llx %016llx %016llx\n",
					(unsigned long long int) translation_table[i].guestphyaddr,
					(unsigned long long int) translation_table[i].qemuvirtaddr,
					(unsigned long long int) translation_table[i].vhostuservirtaddr,
					(unsigned long long int) translation_table[i].len,
					(unsigned long long int) translation_table[i].offset);
					//sprintf(filename,"part%d.dat",i);
					//write_to_file((void *)translation_table[i].vhostuservirtaddr,translation_table[i].len,filename);
				}
				#endif

				{
					unsigned char *a,*b;
					int matched = 0;
					int not_matched = 0;
					a = (unsigned char *) translation_table[0].vhostuservirtaddr;
					a += translation_table[1].guestphyaddr;
					a += translation_table[1].offset;
					b = (unsigned char *) translation_table[1].vhostuservirtaddr;
					for(i=0;i<1000;i++) {
						if(a[i] == b[i]) {
							matched++;
						}
						else {
							not_matched++;
							break;
						}
					}
					printf("matched : %d and not_matched : %d\n",matched,not_matched);
				}	


				break;	

			case VHOST_USER_SET_VRING_NUM :
				{
				struct vhost_vring_state *tmp;
				tmp = (struct vhost_vring_state *) &(msg->payload.u64);
				printf("vvdn debug : state num : %d state index : %d\n",tmp->num,tmp->index);
				if(tmp->index == 1) {
					tx_desc_count = tmp->num;
				}
				else if(tmp->index == 0) {
					rx_desc_count = tmp->num;
				}
				}
				break;
			case VHOST_USER_SET_VRING_BASE :
				{
					struct vhost_vring_state *tmp;
					tmp = (struct vhost_vring_state *) &(msg->payload.u64);
					printf("vvdn debug : state num : %d state index : %d\n",tmp->num,tmp->index);
				}
				break;
			case VHOST_USER_SET_VRING_ADDR :
				{
					struct vhost_vring_addr *tmp;
					tmp = (struct vhost_vring_addr *) &msg->payload.u64;
					printf("vvdn debug : desc_user_addr : %llx\n",(unsigned long long int) tmp->desc_user_addr);
					printf("vvdn debug : used_user_addr : %llx\n",(unsigned long long int) tmp->used_user_addr);
					printf("vvdn debug : avail_user_addr : %llx\n",(unsigned long long int) tmp->avail_user_addr);

					if(tmp->index == 1) {
						tx_desc_base = (void *) qemuvaddr_to_vhostvadd(tmp->desc_user_addr);
						printf("tx desc base at addr : %p\n",tx_desc_base);
						if(tx_desc_count) {
							//print_desc(tx_desc_base,tx_desc_count);
						}
						tx_used = (void *) qemuvaddr_to_vhostvadd(tmp->used_user_addr);
						tx_avail = (void *) qemuvaddr_to_vhostvadd(tmp->avail_user_addr);
						printf("tx_used  at vhostvaddr : %p\n",tx_used);
						printf("tx_avail at vhostvaddr : %p\n",tx_avail);

					}
					else if(tmp->index == 0) {
						rx_desc_base = (void *) qemuvaddr_to_vhostvadd(tmp->desc_user_addr);
						printf("rx desc base at addr : %p\n",rx_desc_base);
							//print_desc(rx_desc_base,rx_desc_count);
						rx_used = (void *) qemuvaddr_to_vhostvadd(tmp->used_user_addr);
						rx_avail = (void *) qemuvaddr_to_vhostvadd(tmp->avail_user_addr);
						printf("rx_used  at vhostvaddr : %p\n",rx_used);
						printf("rx_avail at vhostvaddr : %p\n",rx_avail);
						rx_used->idx = 0;
					}

					#if 0
					if(tx_avail && rx_avail) {
						connected_to_guest = 1;
						printf("Now connected to guest\n");
					}
					#endif
				}
			
			break;

			case VHOST_USER_SET_VRING_KICK:
				printf("vvdn debug :  kick fd : %d index : %llx\n",msg->fds[0], (unsigned long long int)(msg->payload.u64 & VHOST_USER_VRING_IDX_MASK));
				if(kickfd) {
					close(kickfd);
				}
				kickfd = msg->fds[0];
			break;
			case  VHOST_USER_GET_VRING_BASE :
			//printf("exiting...");
			//exit(0);
			{
				msg = (struct vhost_user_msg *) rxbuff;
				struct vhost_vring_state *state;
				state = &msg->payload.state;
				printf("state->index : %d  state->num : %d ",state->index,state->num);
				if(state->index == 0) {
					connected_to_guest = 0;
					printf("get_vring_base : waiting for tx to cleanup\n");
					sem_wait(&rx_clean_wait_sem);
					printf("get_vring_base : tx cleanup done\n");
					state->num = rx_used->idx;
					rx_avail = NULL;
					rx_vring_ready = 0;
					//close(rxirqfd);
					//rxirqfd = -1;
				}
				else if( state->index == 1) {
					connected_to_guest = 0;
					printf("get_vring_base : waiting for rx to cleanup\n");
					sem_wait(&tx_clean_wait_sem);
					printf("get_vring_base : rx cleanup done\n");
					state->num = tx_used->idx;
					//close(txirqfd);
					//txirqfd = -1;
					tx_avail =  NULL;
					tx_vring_ready = 0;
					tx_last_avail_idx = 0;
				}
			#if 0
				if(txirqfd == -1 && rxirqfd == -1) {
					close(kickfd);
					kickfd = -1;
				}
				#endif
			}
			#if 1
			if(tx_avail == NULL && rx_avail == NULL && tx_vring_ready == 0 && rx_vring_ready == 0 ) {
				printf("get_vring_base : unmapping translation table\n");
				{
					int i;
					for(i=0;i<translation_table_count;i++ ) {
						munmap((void *)translation_table[i].vhostuservirtaddr,translation_table[i].len);
						close(translation_table[i].mapfd);
					}
					translation_table_count = -1;
				}
				close(txirqfd); txirqfd = -1;
				close(rxirqfd); rxirqfd = -1;
				close(kickfd); kickfd = -1;
			}
			#endif

			msg->size = sizeof(msg->payload.state);
			printf("msg->size : %d\n",msg->size);
			send_vhost_message(newsockfd,msg);

			break;

			default:
				printf("\ndefault\n");
		}

	}




	close(newsockfd);
	close(sockfd);
}
