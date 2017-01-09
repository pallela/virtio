#include"virtio.h"
#include<sys/uio.h>
#include<sys/socket.h>
#include<stdio.h>
#include<string.h>
#include<sys/stat.h>

int send_fd_message(int sockfd, char *buf, int buflen, int *fds, int fd_num)
{

        struct iovec iov;
        struct msghdr msgh;
        size_t fdsize = fd_num * sizeof(int);
        char control[CMSG_SPACE(fdsize)];
        struct cmsghdr *cmsg;
        int ret;

        memset(&msgh, 0, sizeof(msgh));
        iov.iov_base = buf;
        iov.iov_len = buflen;

        msgh.msg_iov = &iov;
        msgh.msg_iovlen = 1;

        if (fds && fd_num > 0) {
                msgh.msg_control = control;
                msgh.msg_controllen = sizeof(control);
                cmsg = CMSG_FIRSTHDR(&msgh);
                cmsg->cmsg_len = CMSG_LEN(fdsize);
                cmsg->cmsg_level = SOL_SOCKET;
                cmsg->cmsg_type = SCM_RIGHTS;
                memcpy(CMSG_DATA(cmsg), fds, fdsize);
        } else {
                msgh.msg_control = NULL;
                msgh.msg_controllen = 0;
        }

        do {
                ret = sendmsg(sockfd, &msgh, 0);
        } while (ret < 0 && errno == EINTR);

        if (ret < 0) {
                printf("vvdn debug : sendmsg error\n");
                return ret;
        }

        return ret;
}


int send_vhost_message(int sockfd, struct vhost_user_msg *msg)
{
        int ret;

        if (!msg)
                return 0;

        msg->flags &= ~VHOST_USER_VERSION_MASK;
        msg->flags |= VHOST_USER_VERSION;
        msg->flags |= VHOST_USER_REPLY_MASK;

        ret = send_fd_message(sockfd, (char *)msg,
                VHOST_USER_HDR_SIZE + msg->size, NULL, 0);

        return ret;
}

/* return bytes# of read on success or negative val on failure. */
int read_fd_message(int sockfd, char *buf, int buflen, int *fds, int fd_num)
{
	struct iovec iov;
	struct msghdr msgh;
	size_t fdsize = fd_num * sizeof(int);
	char control[CMSG_SPACE(fdsize)];
	struct cmsghdr *cmsg;
	int ret;

	memset(&msgh, 0, sizeof(msgh));
	iov.iov_base = buf;
	iov.iov_len  = buflen;

	msgh.msg_iov = &iov;
	msgh.msg_iovlen = 1;
	msgh.msg_control = control;
	msgh.msg_controllen = sizeof(control);

	ret = recvmsg(sockfd, &msgh, 0);
	if (ret <= 0) {
		perror("recvmsg : ");
		printf("vvdn debug : recvmsg failed ret  %d\n",ret);
		return ret;
	}

	if (msgh.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) {
		printf("vvdn debug : truncted msg\n");
		return -1;
	}

	for (cmsg = CMSG_FIRSTHDR(&msgh); cmsg != NULL;
			cmsg = CMSG_NXTHDR(&msgh, cmsg)) {
		printf("vvdn debug :  func : %s line : %u\n",__func__,__LINE__);
		if ((cmsg->cmsg_level == SOL_SOCKET) &&
				(cmsg->cmsg_type == SCM_RIGHTS)) {
		printf("vvdn debug :  func : %s line : %u\n",__func__,__LINE__);
			memcpy(fds, CMSG_DATA(cmsg), fdsize);
			break;
		}
	}

	return ret;
}


int read_vhost_message(int sockfd, struct vhost_user_msg *msg)
{
	int ret;

	ret = read_fd_message(sockfd, (char *)msg, VHOST_USER_HDR_SIZE,
			msg->fds, VHOST_MEMORY_MAX_NREGIONS);
	if (ret <= 0)
		return ret;

	if (msg && msg->size) {
		if (msg->size > sizeof(msg->payload)) {
			printf("vvdn debug : invalid msg size: %d\n", msg->size);
			return -1;
		}
		ret = read(sockfd, &msg->payload, msg->size);
		if (ret <= 0)
			return ret;
		if (ret != (int)msg->size) {
			printf("vvdn debug : read control message failed\n");
			return -1;
		}
	}

	return ret;
}


uint64_t get_blk_size(int fd)
{
        struct stat stat;

        fstat(fd, &stat);
        return (uint64_t)stat.st_blksize;
}

