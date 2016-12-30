#include<stdio.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<string.h>
#include<sys/un.h>
#include<stdlib.h>
#include"virtio.h"

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



#define VHOST_SUPPORTED_FEATURES ((1ULL << VIRTIO_NET_F_MRG_RXBUF) | \
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

#define VHOST_USER_PROTOCOL_F_MQ        0
#define VHOST_USER_PROTOCOL_F_LOG_SHMFD 1
#define VHOST_USER_PROTOCOL_F_RARP      2

#define VHOST_USER_PROTOCOL_FEATURES    ((1ULL << VHOST_USER_PROTOCOL_F_MQ) | \
                                         (1ULL << VHOST_USER_PROTOCOL_F_LOG_SHMFD) |\
                                         (1ULL << VHOST_USER_PROTOCOL_F_RARP))



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

main()
{
	int sockfd;
	int newsockfd;
	struct sockaddr_un local,remote;
	int len,t;
	unsigned char rxbuff[100],txbuff[100];
	int recv_bytes;
        struct vhost_user_msg *msg;


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

		recv_bytes = recv(newsockfd,rxbuff,12,0);

		msg = (struct vhost_user_msg *) rxbuff;

		if(msg->size != 0) {
			recv_bytes += recv(newsockfd,rxbuff+12,msg->size,0);
		}


		printf("received total bytes : %d\n",recv_bytes);

		print_hex(rxbuff,recv_bytes);


		printf("msg.request : %d name : %s payload size : %d\n",msg->request,req_names[msg->request],msg->size);

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
				printf("sent bytes : %d\n",20);
				print_hex(txbuff,20);

			break;

			case VHOST_USER_SET_FEATURES:
			memcpy(txbuff,rxbuff,recv_bytes);
			msg = (struct vhost_user_msg *) txbuff;
			printf("payload is %016x\n",msg->payload.u64);
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
			printf("\n\nsent bytes : %d\n",20);
			print_hex(txbuff,20);
			printf("\n\n");

			break;

			case VHOST_USER_GET_QUEUE_NUM:
			memcpy(txbuff,rxbuff,recv_bytes);
			msg = (struct vhost_user_msg *) txbuff;
			msg->payload.u64 = 0x8000;
			msg->size = 8;
			msg->flags &= ~VHOST_USER_VERSION_MASK;
			msg->flags |= VHOST_USER_VERSION;
			msg->flags |= VHOST_USER_REPLY_MASK;
			send(newsockfd,txbuff,20,0);
			printf("\n\nsent bytes : %d\n",20);
			print_hex(txbuff,20);
			printf("\n\n");
			break;

			case VHOST_USER_SET_VRING_CALL:
			memcpy(txbuff,rxbuff,recv_bytes);
			msg = (struct vhost_user_msg *) txbuff;
			printf("payload : %llx\n",msg->payload.u64);
			break;

			case VHOST_USER_SET_VRING_ENABLE:
			memcpy(txbuff,rxbuff,recv_bytes);
			msg = (struct vhost_user_msg *) txbuff;
			printf("payload.state.index : %u\n",msg->payload.state.index);
			printf("payload.state.num   : %u\n",msg->payload.state.num);
			break;
			


			default:
			printf("default\n");
		}

	}




	close(newsockfd);
	close(sockfd);
}
