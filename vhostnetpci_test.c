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

#define VHOST_USER_F_PROTOCOL_FEATURES  30

#define VHOST_SUPPORTS_MQ      (1ULL << VIRTIO_NET_F_MQ)
#define VHOST_F_LOG_ALL 26
/* Features supported by this lib. */

#if 0
#define VHOST_SUPPORTED_FEATURES ((1ULL << VIRTIO_NET_F_MRG_RXBUF) | \
                                (1ULL << VIRTIO_NET_F_CTRL_VQ) | \
                                (1ULL << VIRTIO_NET_F_CTRL_RX) | \
                                (1ULL << VIRTIO_NET_F_GUEST_ANNOUNCE) | \
                                (VHOST_SUPPORTS_MQ)            | \
                                (1ULL << VIRTIO_F_VERSION_1)   | \
                                (1ULL << VHOST_F_LOG_ALL)      | \
                                (1ULL << VHOST_USER_F_PROTOCOL_FEATURES) | \
                                (1ULL << VIRTIO_NET_F_HOST_TSO4) | \
                                (1ULL << VIRTIO_NET_F_HOST_TSO6) | \
                                (1ULL << VIRTIO_NET_F_CSUM)    | \
                                (1ULL << VIRTIO_NET_F_GUEST_CSUM) | \
                                (1ULL << VIRTIO_NET_F_GUEST_TSO4) | \
                                (1ULL << VIRTIO_NET_F_GUEST_TSO6))
#endif


/* Features supported by this lib. */
#define VHOST_SUPPORTED_FEATURES ((1ULL << VIRTIO_NET_F_MRG_RXBUF) | \
                                (1ULL << VIRTIO_NET_F_CTRL_VQ) | \
                                (1ULL << VIRTIO_NET_F_CTRL_RX) | \
                                (VHOST_SUPPORTS_MQ)            | \
				(1ULL << VIRTIO_F_VERSION_1)   | \
                                (1ULL << VHOST_F_LOG_ALL)      | \
                                (1ULL << VHOST_USER_F_PROTOCOL_FEATURES))



/*#define VHOST_SUPPORTED_FEATURES ((1ULL << VIRTIO_NET_F_MRG_RXBUF) | \
                                (1ULL << VIRTIO_NET_F_CTRL_VQ) | \
                                (1ULL << VIRTIO_NET_F_CTRL_RX) | \
                                (1ULL << VIRTIO_NET_F_GUEST_ANNOUNCE) | \
                                (1ULL << VIRTIO_F_VERSION_1)   | \
                                (1ULL << VHOST_F_LOG_ALL)      | \
                                (1ULL << VHOST_USER_F_PROTOCOL_FEATURES) | \
                                (1ULL << VIRTIO_NET_F_HOST_TSO4) | \
                                (1ULL << VIRTIO_NET_F_HOST_TSO6) | \
                                (1ULL << VIRTIO_NET_F_CSUM)    | \
                                (1ULL << VIRTIO_NET_F_GUEST_CSUM) | \
                                (1ULL << VIRTIO_NET_F_GUEST_TSO4) | \
                                (1ULL << VIRTIO_NET_F_GUEST_TSO6))
*/

#define VHOST_USER_PROTOCOL_F_MQ        0
#define VHOST_USER_PROTOCOL_F_LOG_SHMFD 1
#define VHOST_USER_PROTOCOL_F_RARP      2

/*
#define VHOST_USER_PROTOCOL_FEATURES    ((1ULL << VHOST_USER_PROTOCOL_F_MQ) | \
                                         (1ULL << VHOST_USER_PROTOCOL_F_LOG_SHMFD) |\
                                         (1ULL << VHOST_USER_PROTOCOL_F_RARP))
*/


#define VHOST_USER_PROTOCOL_FEATURES    (1ULL << VHOST_USER_PROTOCOL_F_MQ) 

#define SOCKPATH "/usr/local/var/run/openvswitch/vhost-user1"





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
	printf("\n");
}

#define RECV 0

volatile int kickfd = -1;
volatile int txirqfd = -1;
volatile int rxirqfd = -1;

struct address_translation translation_table[10];
int translation_table_count = -1;

void * transmit_thread(void *args)
{
	uint64_t tx_kick_count;

	printf("starting transmit thread \n");

	while(1) {
		printf("kickfd : %d txirqfd : %d rxirqfd : %d\n",kickfd,txirqfd,rxirqfd);
		sleep(1);
	}
}

unsigned char memory_table[100*1024];
pthread_t tx_thread;


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
		sprintf(filename,"part%d.dat",i);
		//write_to_file((void *)translation_table[i].vhostuservirtaddr,translation_table[i].len,filename);
	}
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

	#if 0
	if(!pthread_create(&tx_thread,NULL,transmit_thread,NULL)){
		printf("transmit thread creation failed\n");
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
			printf("sleep 5 due to ret = 0\n");
			sleep(5);
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
				if(file.index == 0) {
					if(txirqfd) {
						close(txirqfd);
					}
					txirqfd =  file.fd;
				}
				else if(file.index ==  1) {
					if(rxirqfd) {
						close(rxirqfd);
					}
					rxirqfd =  file.fd;
				}
				break;

			case VHOST_USER_SET_VRING_ENABLE:
				msg = (struct vhost_user_msg *) rxbuff;
				printf("payload.state.index : %u\n",msg->payload.state.index);
				printf("payload.state.num   : %u\n",msg->payload.state.num);
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

						//write_to_file(addr,mapsize,"/tmp/image.dat");
					}
#endif
				}
				translation_table_count = i;
				printf("address translation table : %d entries\n",translation_table_count);
				printf("GPA              ");
				printf("QVA              ");
				printf("VUVA              ");
				printf("LEN               ");
				printf("OFFSET            \n");
				#if 0
				for(i = 0 ;i < translation_table_count ;i ++) {
					char filename[20];
					printf("%016llx %016llx %016llx %016llx %016llx\n",
					(unsigned long long int) translation_table[i].guestphyaddr,
					(unsigned long long int) translation_table[i].qemuvirtaddr,
					(unsigned long long int) translation_table[i].vhostuservirtaddr,
					(unsigned long long int) translation_table[i].len,
					(unsigned long long int) translation_table[i].offset);
					sprintf(filename,"part%d.dat",i);
					write_to_file((void *)translation_table[i].vhostuservirtaddr,translation_table[i].len,filename);
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
				}
			
			break;

			case VHOST_USER_SET_VRING_KICK:
				printf("vvdn debug :  kick fd : %d index : %llx\n",msg->fds[0], (unsigned long long int)(msg->payload.u64 & VHOST_USER_VRING_IDX_MASK));
				if(kickfd) {
					close(kickfd);
				}
				kickfd = msg->fds[0];
			break;

			default:
				printf("\ndefault\n");
		}

	}




	close(newsockfd);
	close(sockfd);
}
