#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <sys/poll.h>

#define NETLINK_USER 31  // 必须与内核模块中的 NETLINK_USER 相同
int group = 5;
// Netlink 消息结构
struct msg_data {
    int type;
    int pid;
    char path[256];
    char process[256];
};

int main() {
    struct sockaddr_nl sa;
    int sock;
    struct nlmsghdr *nlh;
    struct msg_data msg;
    struct pollfd fds[1];  // 用来保存文件描述符和事件信息
    int ret;

    // 创建 Netlink 套接字
    sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_USER);
    if (sock < 0) {
        perror("Socket creation failed");
        return -1;
    }

    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
	sa.nl_groups = 1 <<(group-1);
	sa.nl_pid = 0;
    // 绑定套接字
    ret = bind(sock, (struct sockaddr*)&sa, sizeof(sa));
    if (ret < 0) {
        perror("Bind failed");
        close(sock);
        return -1;
    }

    // 设置 pollfd 结构体
    fds[0].fd = sock;
    fds[0].events = POLLIN;  // 设置为 "可读" 事件

    while (1) {
        // 使用 poll 等待套接字变为可读，设置等待时间为 3 秒
        ret = poll(fds, 1, 3000);  // 3 秒等待
        if (ret == -1) {
            perror("Poll failed");
            close(sock);
            return -1;
        }

        // 如果套接字可读
        if (fds[0].revents & POLLIN) {
            nlh = (struct nlmsghdr*)malloc(NLMSG_SPACE(sizeof(struct msg_data)));
            ret = recv(sock, nlh, NLMSG_SPACE(sizeof(struct msg_data)), 0);
            if (ret < 0) {
                perror("Recv failed");
                free(nlh);
                close(sock);
                return -1;
            }

            // 解析消息
            memcpy(&msg, NLMSG_DATA(nlh), sizeof(struct msg_data));

            // 打印消息内容
            printf("Received message:\n");
            printf("Type: %d\n", msg.type);
            printf("PID: %d\n", msg.pid);
            printf("Path: %s\n", msg.path);
            printf("Process: %s\n", msg.process);

            free(nlh);
        } else {
            printf("No data received in the last 3 seconds.\n");
        }
    }

    close(sock);
    return 0;
}

