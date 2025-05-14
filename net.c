#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <linux/string.h>

#define NETLINK_USER 31

#define ARRAY_SIZE 1024
#define MAX_STRING_LENGTH 1024
extern char **program_list;
extern char **file_list;
extern struct mutex my_mutex;
static struct sock *nl_sk = NULL;
int group = 5;
// Netlink 消息结构
struct msg_data {
    int type;
    int pid;
    char path[256];
    char process[256];
};

void send_netlink_msg(int type, int pid, const char *path, const char *process) {
    struct sk_buff *skb;
    struct nlmsghdr *nlh;
    struct msg_data msg;
    int msg_size;
    
    msg.type = type;  // 设置消息类型
    msg.pid = pid;  // 设置进程 ID
    strncpy(msg.path, path, sizeof(msg.path) - 1);  // 设置路径
    strncpy(msg.process, process, sizeof(msg.process) - 1);  // 设置进程名
    
    // 计算消息大小
    msg_size = sizeof(struct msg_data);
    
    // 创建一个空的 skb，准备发送
    skb = nlmsg_new(msg_size, GFP_KERNEL);
    if (!skb) {
        printk(KERN_INFO "Failed to allocate memory for netlink message\n");
        return;
    }

    // 填充消息头
    nlh = nlmsg_put(skb, 0, 0, NLMSG_DONE, msg_size, 0);
    NETLINK_CB(skb).dst_group = group;  // 发送到用户空间
    NETLINK_CB(skb).portid = 0;  // 发送到用户空间
    memcpy(nlmsg_data(nlh), &msg, msg_size);  // 拷贝消息数据到 skb
    
    // 发送消息
    //if (nlmsg_unicast(nl_sk, skb, 0) < 0) {
    if (netlink_broadcast(nl_sk, skb, 0,group, 0) < 0) {
        printk(KERN_INFO "Failed to send netlink message\n");
    } else {
        printk(KERN_INFO "Netlink message sent to user\n");
    }
}


static void nl_recv_msg(struct sk_buff *skb) {
	struct nlmsghdr *nlh;
	int pid;
	char *data;
	int len;


	nlh = (struct nlmsghdr *)skb->data;
	pid = nlh->nlmsg_pid; // 发送者的PID
	data = NLMSG_DATA(nlh);
	len = skb->len - NLMSG_SPACE(0);
	printk(KERN_INFO "len %d\n", len);


	// 获取消息中的type字段
	int *type = (int *)NLMSG_DATA(nlh);
	printk(KERN_INFO "Received type: %d\n", *type);

	mutex_lock(&my_mutex);    // 获取锁
	if (*type == 1)
	{
	//clear old file
	int foo = 0;
	for (foo = 0 ; foo < ARRAY_SIZE; foo++)
		*(file_list[foo]) = 0;

		data = (char*)(type + 1);
		len = len -4;
		int i =0;
		// 打印接收到的字符串数组
		while (len > 0) {
			printk(KERN_INFO "Received: %s\n", data);
			snprintf(file_list[i], MAX_STRING_LENGTH, "%s", data);
			i++;
			len -= strlen(data) + 1;
			data += strlen(data) + 1;

		}

	}


	if (*type == 2)
	{
		int foo;
	//clear old file
	for ( foo = 0 ; foo < ARRAY_SIZE; foo++)*(program_list[foo]) = 0;
		data = (char*)(type + 1);
		len = len -4;
		int i =0;
		// 打印接收到的字符串数组
		while (len > 0) {
			printk(KERN_INFO "Received: %s\n", data);
			snprintf(program_list[i], MAX_STRING_LENGTH, "%s", data);
			i++;
			len -= strlen(data) + 1;
			data += strlen(data) + 1;

		}

	}
	mutex_unlock(&my_mutex);    // 获取锁
}

 int  nl_init(void) {
    struct netlink_kernel_cfg cfg = {
        .input = nl_recv_msg,
    };

    nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);
    if (!nl_sk) {
        printk(KERN_ERR "Error creating netlink socket.\n");
        return -10;
    }
    printk(KERN_INFO "Netlink socket created.\n");
    return 0;
}

void  nl_exit(void) {
    netlink_kernel_release(nl_sk);
    printk(KERN_INFO "Netlink socket released.\n");
}


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Netlink example module");
