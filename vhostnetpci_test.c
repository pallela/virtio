#include<stdio.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<string.h>
#include<sys/un.h>
#include<stdlib.h>
#include"virtio.h"
#include <sys/eventfd.h>


#define VHOST_USER_VERSION    0x1

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

#define RECV 1

unsigned char memory_table[100*1024];

main()
{
	int sockfd;
	int newsockfd;
	struct sockaddr_un local,remote;
	int len,t,i;
	unsigned char rxbuff[1024],txbuff[1024];
	int recv_bytes;
	int fdbytes;
        struct vhost_user_msg *msg;
	struct vhost_vring_file file;
	struct vhost_memory *table = (struct vhost_memory *) memory_table;

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

		memset(rxbuff,0,100);

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

		read_vhost_message(newsockfd,msg);
		#endif




		printf("msg.request : %d name : %s payload size : %d\n",msg->request,req_names[msg->request],msg->size);
		print_hex(rxbuff,recv_bytes);

		switch(msg->request) {

			case VHOST_USER_GET_FEATURES:
				memcpy(txbuff,rxbuff,recv_bytes);
				msg = (struct vhost_user_msg *) txbuff;
				//msg->payload.u64 = (1ULL << 30);
				msg->payload.u64 = VHOST_SUPPORTED_FEATURES;
				msg->size = 8;
				msg->flags &= ~VHOST_USER_VERSION_MASK;
				msg->flags |= VHOST_USER_VERSION;
				msg->flags |= VHOST_USER_REPLY_MASK;
				send(newsockfd,txbuff,20,0);
				printf("payload : %016llx\n",(unsigned long long int)msg->payload.u64);
				printf("sent bytes : %d\n",20);
				//print_hex(txbuff,20);

				break;

			case VHOST_USER_SET_FEATURES:
			memcpy(txbuff,rxbuff,recv_bytes);
			msg = (struct vhost_user_msg *) txbuff;
			printf("payload is %016llx\n",(unsigned long long int)msg->payload.u64);
			printf("Mergeable RX buffers %s, virtio 1 %s\n",
					(msg->payload.u64 & (1 << VIRTIO_NET_F_MRG_RXBUF)) ? "on" : "off",
					(msg->payload.u64 & (1ULL << VIRTIO_F_VERSION_1)) ? "on" : "off");

			//eventfd_write(file.fd,(eventfd_t)1);
			break;
			

			case  VHOST_USER_GET_PROTOCOL_FEATURES:
			memcpy(txbuff,rxbuff,recv_bytes);
			msg = (struct vhost_user_msg *) txbuff;
			msg->payload.u64 = VHOST_USER_PROTOCOL_FEATURES;
			msg->size = 8;
			msg->flags &= ~VHOST_USER_VERSION_MASK;
			msg->flags |= VHOST_USER_VERSION;
			msg->flags |= VHOST_USER_REPLY_MASK;
			send(newsockfd,txbuff,20,0);
			printf("payload : %016llx\n",(unsigned long long int)msg->payload.u64);
			printf("\n\nsent bytes : %d\n",20);
			//print_hex(txbuff,20);
			printf("\n\n");

			break;
			case  VHOST_USER_SET_PROTOCOL_FEATURES:
			memcpy(txbuff,rxbuff,recv_bytes);
			msg = (struct vhost_user_msg *) txbuff;
			printf("protocol features : %016llx and we provided : %016llx\n",(unsigned long long int)msg->payload.u64,(unsigned long long int)VHOST_USER_PROTOCOL_FEATURES);	
			break;

			case VHOST_USER_GET_QUEUE_NUM:
			memcpy(txbuff,rxbuff,recv_bytes);
			msg = (struct vhost_user_msg *) txbuff;
			msg->payload.u64 = 0x8000;
			//msg->payload.u64 = 1;
			msg->size = 8;
			msg->flags &= ~VHOST_USER_VERSION_MASK;
			msg->flags |= VHOST_USER_VERSION;
			msg->flags |= VHOST_USER_REPLY_MASK;
			send(newsockfd,txbuff,20,0);
			printf("payload : %016llx\n",(unsigned long long int)msg->payload.u64);
			printf("\n\nsent bytes : %d\n",20);
			//print_hex(txbuff,20);
			printf("\n\n");
			break;

			case VHOST_USER_SET_VRING_CALL:
			memcpy(txbuff,rxbuff,recv_bytes);
			msg = (struct vhost_user_msg *) txbuff;
			fdbytes = recv(newsockfd,&msg->fds[0],4*8,0);
			printf("fds bytes : %d\n",fdbytes);
			print_hex((unsigned char *)&msg->fds[0],fdbytes);
			printf("payload : %016llx\n",(unsigned long long int)msg->payload.u64);
		  	if (msg->payload.u64 & VHOST_USER_VRING_NOFD_MASK) {
				printf("some issue : fd = -1\n");
			}
			file.index = msg->payload.u64 & VHOST_USER_VRING_IDX_MASK;
			file.fd = msg->fds[0];
			printf("vring call idx:%d file:%d\n", file.index, file.fd);
			//eventfd_write(file.fd,(eventfd_t)1);


			break;

			case VHOST_USER_SET_VRING_ENABLE:
			memcpy(txbuff,rxbuff,recv_bytes);
			msg = (struct vhost_user_msg *) txbuff;
			printf("payload.state.index : %u\n",msg->payload.state.index);
			printf("payload.state.num   : %u\n",msg->payload.state.num);
			break;
		
			case VHOST_USER_SET_MEM_TABLE:
			msg = (struct vhost_user_msg *) txbuff;
			memcpy(txbuff,rxbuff,recv_bytes);
			printf("processing VHOST_USER_SET_MEM_TABLE , copying %u bytes\n",msg->size);
			memcpy(table,&(msg->payload.memory),msg->size);
			printf("nr_regions : %u\n",table->nregions);
			printf("padding    : %u\n",table->padding);


			for(i=0;i<table->nregions;i++) {
				printf("region[%04d]  gpaddr : %llx memory_size : %llx userspace_addr : %llx mmap_offset : %llx\n",
				i,
				(unsigned long long int) table->regions[i].guest_phys_addr,
				(unsigned long long int) table->regions[i].memory_size,
				(unsigned long long int) table->regions[i].userspace_addr,
				(unsigned long long int) table->regions[i].mmap_offset\
					);
			}
			
			break;	


			default:
			printf("\ndefault\n");
		}

	}




	close(newsockfd);
	close(sockfd);
}
