#include <cstdio>
#include <cstdlib>
#include <string.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <errno.h>
#include <unistd.h>
#include <fstream>
#include <iostream>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <rapidjson/document.h>
#include <rapidjson/istreamwrapper.h>
#include <set>
using namespace std;
#define NETLINK_USER 31
#define MAX_PAYLOAD 1024

void send_netlink_message(set<string> & info, int type) {
	struct sockaddr_nl src_addr, dest_addr;
	struct nlmsghdr *nlh = NULL;
	struct iovec iov;
	int sock_fd;
	char *buf = NULL;
	int total_len = sizeof(int); // 初始空间：为了存储一个type字段

	for (auto & tmp : info)
	{
		total_len += strlen(tmp.c_str()) + 1;
	}
	printf("send len %d\n", total_len);

	// 创建Netlink套接字
	if ((sock_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_USER)) == -1) {
		perror("Creating socket failed");
		exit(EXIT_FAILURE);
	}

	memset(&src_addr, 0, sizeof(src_addr));
	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = getpid(); // 自己的PID

	bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr));

	memset(&dest_addr, 0, sizeof(dest_addr));
	dest_addr.nl_family = AF_NETLINK;
	dest_addr.nl_pid = 0; // 内核模块的PID
	dest_addr.nl_groups = 0; // 未使用组

	// 分配缓冲区
	buf = (char *)calloc(NLMSG_SPACE(total_len), 1);
	printf("malloc %d\n", NLMSG_SPACE(total_len));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_len = NLMSG_SPACE(total_len);
	nlh->nlmsg_pid = getpid();
	nlh->nlmsg_flags = 0;

	// 将type字段添加到消息数据部分
	char *data = (char*)NLMSG_DATA(nlh);
	memcpy(data, &type, sizeof(int)); // 将type字段添加到消息开头
	data += sizeof(int); // 移动到下一个位置

	// 复制每个字符串到消息中

	for (auto &tmp : info)
	{

		strcpy(data, tmp.c_str()); // 复制字符串
		data += strlen(tmp.c_str()) + 1; // 移动到下一个位置

		cout << tmp.c_str() << endl;;
	}

	iov.iov_base = (void *)nlh;
	iov.iov_len = nlh->nlmsg_len;

	struct msghdr msg = {
		.msg_name = (void *)&dest_addr,
		.msg_namelen = sizeof(dest_addr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};

	// 发送消息
	if (sendmsg(sock_fd, &msg, 0) < 0) {
		perror("Sending message failed");
		exit(EXIT_FAILURE);
	}

	printf("Message sent\n");
	close(sock_fd);
	free(buf);
}

void send_netlink_message(char *messages[], int count, int type) {
	struct sockaddr_nl src_addr, dest_addr;
	struct nlmsghdr *nlh = NULL;
	struct iovec iov;
	int sock_fd;
	char *buf = NULL;
	int total_len = sizeof(int); // 初始空间：为了存储一个type字段

	// 计算总长度：所有字符串的总长度
	for (int i = 0; i < count; i++) {
		total_len += strlen(messages[i]) + 1; // 每个字符串和结束符
	}
	printf("send len %d\n", total_len);

	// 创建Netlink套接字
	if ((sock_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_USER)) == -1) {
		perror("Creating socket failed");
		exit(EXIT_FAILURE);
	}

	memset(&src_addr, 0, sizeof(src_addr));
	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = getpid(); // 自己的PID

	bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr));

	memset(&dest_addr, 0, sizeof(dest_addr));
	dest_addr.nl_family = AF_NETLINK;
	dest_addr.nl_pid = 0; // 内核模块的PID
	dest_addr.nl_groups = 0; // 未使用组

	// 分配缓冲区
	buf = (char *)malloc(NLMSG_SPACE(total_len));
	printf("malloc %d\n", NLMSG_SPACE(total_len));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_len = NLMSG_SPACE(total_len);
	nlh->nlmsg_pid = getpid();
	nlh->nlmsg_flags = 0;

	// 将type字段添加到消息数据部分
	char *data = (char*)NLMSG_DATA(nlh);
	memcpy(data, &type, sizeof(int)); // 将type字段添加到消息开头
	data += sizeof(int); // 移动到下一个位置

	// 复制每个字符串到消息中
	for (int i = 0; i < count; i++) {
		strcpy(data, messages[i]); // 复制字符串
		data += strlen(messages[i]) + 1; // 移动到下一个位置
	}

	iov.iov_base = (void *)nlh;
	iov.iov_len = nlh->nlmsg_len;

	struct msghdr msg = {
		.msg_name = (void *)&dest_addr,
		.msg_namelen = sizeof(dest_addr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};

	// 发送消息
	if (sendmsg(sock_fd, &msg, 0) < 0) {
		perror("Sending message failed");
		exit(EXIT_FAILURE);
	}

	printf("Message sent\n");
	close(sock_fd);
	free(buf);
}


#define MAX_PATHS 10
#define MAX_PATH_LEN 100


void parse_json(std::set<string> &file, std::set<string> &process)
{

	std::ifstream ifs("data.json");

	// 使用 rapidjson 的 IStreamWrapper 来读取文件内容
	rapidjson::IStreamWrapper isw(ifs);

	// 创建 rapidjson 的 Document 对象
	rapidjson::Document doc;

	// 解析 JSON 内容到 Document 对象中
	doc.ParseStream(isw);

	// 检查解析是否成功
	if (doc.HasParseError()) {
		std::cerr << "Error parsing JSON file!" << std::endl;
		return ;
	}
	// 访问数组
	if (doc.HasMember("files") && doc["files"].IsArray()) {
		const rapidjson::Value& names = doc["files"];

		// 遍历数组
		for (rapidjson::SizeType i = 0; i < names.Size(); i++) {
			std::cout << "files " << i + 1 << ": " << names[i].GetString() << std::endl;
			file.insert(names[i].GetString());

		}

		// 创建一个 char* 数组来存储 c_str() 地址
		char* message[file.size()];

		// 遍历 set 并将 c_str() 地址存储到数组中
		int index = 0;
		for (const auto& str : file) {
			message[index] = const_cast<char*>(str.c_str());  // 将 c_str() 的地址存储到 a 中
			index++;

		}

		send_netlink_message(message, file.size(), 1);
		//	send_netlink_message(file, 1);
	}

	if (doc.HasMember("white_process") && doc["white_process"].IsArray()) {
		const rapidjson::Value& names = doc["white_process"];

		// 遍历数组
		for (rapidjson::SizeType i = 0; i < names.Size(); i++) {
			std::cout << "white_process " << i + 1 << ": " << names[i].GetString() << std::endl;
			process.insert(names[i].GetString());
		}

		char* message[file.size()];

		// 遍历 set 并将 c_str() 地址存储到数组中
		int index = 0;
		for (const auto& str : process) {
			message[index] = const_cast<char*>(str.c_str());  // 将 c_str() 的地址存储到 a 中
			index++;

		}

			send_netlink_message(message, process.size(), 2);
	}

}

int main(int argc, char *argv[]) {

	set<string> file;
	set<string> p;
	parse_json(file, p);


	//   send_netlink_message(file, 3, type);
	////
	//    char *file[] = {"/tmp/a", "/tmp/b", "/tmp/c"};
	//    int type = 1; // 设置一个type值
	//    send_netlink_message(file, 3, type);
	//
	//
	//    char *process[] = {"/usr/bin/vim"};
	//    send_netlink_message(process, 1, 2);
	return 0;
}

