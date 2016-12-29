#include<stdio.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<string.h>
#include<sys/un.h>
#include<stdlib.h>

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
	unsigned char buff[100];
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

	if(listen(sockfd,5) == -1) {
		perror("listen : ");
		exit(1);
	}

	//while(1) {
		printf("Waitng for a connection\n");

		t =  sizeof(remote);

		if((newsockfd = accept(sockfd,(struct sockaddr *)&remote,&t)) == -1) {
			perror("accept : ");
			exit(1);
		}

		printf("connected\n");
	//}



	close(newsockfd);
	close(sockfd);
}
