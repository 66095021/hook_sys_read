#ifndef __NET__HEL__
#define __NET__HEL__
int nl_init(void);
void nl_exit(void);
void send_netlink_msg(int type, int pid, char *process, char* file);
#endif
