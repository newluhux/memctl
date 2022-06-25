#define _GNU_SOURCE

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <unistd.h>

#define LINEMAX 512 // /proc/<pid>/maps 中行的最大长度
#define MAX_REGIONS 8192

struct map {
	// 在 /proc/<pid>/maps 中存储的项
	void *addr_start; // man 2 mmap
	void *addr_end; // man 2 mmap
	int prot; // man 2 mmap
	int flags; // man 2 mmap
	off_t offset; // man 2 mmap
	unsigned int dev_major; // man 3 major
	unsigned int dev_minor; // man 3 major
	ino_t inode; // man 2 stat
	char *pathname; // man 5 proc
};
typedef struct map map;

/*
使用calloc分配一个新的map结构的内存空间并初始化

如果成功返回指向新的map结构的指针
如果出错返回空指针
*/

map *map_init(void);

/*
将mapsline解析并存储到m中

mapsline	从/proc/pid/maps中读取的一行
m			存储解析结果

如果出错返回-1
*/

int map_parser(char *mapsline, map *m);

/*
将m结构中的指针所指向的内存释放，并释放m结构本身

如果出错返回-1
*/

int map_free(map *m);

/*
格式化打印m结构中内容并打印到output

如果出错返回-1
*/

int map_show(map *m,FILE *output);

struct process {
	// 存放操作一个进程需要的信息
	pid_t pid; // 进程号
	int regions; // 内存区域个数
	map *maps[MAX_REGIONS]; // 内存区域信息
	int (*read)(struct process *p,void *addr,void *buf,size_t count); // 内存读函数
	int (*write)(struct process *p,void *addr,void *buf,size_t count); // 内存写函数
	int procmemfd; // 如果使用 /proc/pid/mem 则使用此字段
};
typedef struct process process;


/*
使用calloc分配一个新的process结构需要的内存空间并初始化
如果成功返回指向新的process结构的指针
如果出错返回空指针
*/

process *process_init(void);

/*
根据pid加载进程信息到p结构

pid		进程pid
p		存储进程信息的结构

如果出错返回-1
*/

int process_open(pid_t pid,process *p);

/*
设置读写内存的方法

method	选择方法:

0	使用 process_vm_xx 方式
1	读写 /proc/pid/mem 方式

如果出错返回-1;
*/

#define DEFAULT_METHOD 1 // 默认使用的方式
int process_set_read(int method, process *p);
int process_set_write(int method, process *p);

/*
将p结构中的内容重置为0，指针指向的内存释放。

如果出错返回-1
*/

int process_clean(process *p);

/*
格式化打印p结构中的信息，并输出到output

如果出错返回-1
*/

int process_show(process *p,FILE *output);


// procmem backend 读写 /proc/pid/mem 方法
int procmem_read(process *p,void *addr,void *buf,size_t count);
int procmem_write(process *p,void *addr,void *buf,size_t count);

// procvm backend 调用 process_vm_xxx 方法
int procvm_read(process *p,void *addr,void *buf,size_t count);
int procvm_write(process *p,void *addr,void *buf,size_t count);

/*
读取目标进程的内存到buf

p		目标进程
addr	目标进程虚拟内存地址
buf		读取目标进程的内容存入此内存区域，必须大于等于count
count	从addr开始读取count个字节

如果出错返回-1
*/

int process_readm(process *p,void *addr,void *buf,size_t count);

/*
将buf中的内容写到目标进程的内存

p		目标进程
addr	目标进程的虚拟内存地址
buf		存放数据的内存区域
count	数据的长度

如果出错返回-1
*/

int process_writem(process *p,void *addr,void *buf,size_t count);

/*
将目标进程的内容读取并写入outfd

p		目标进程
addr	目标进程的虚拟内存地址
count	读取的字节数
outfd	写入的file descriptor

如果出错返回-1
*/

int process_dumpm(process *p,void *addr,size_t count,int outfd);

#define MAX_ARGC 20

struct cmd {
	int argc; // 参数个数
	char *argv[MAX_ARGC]; // 指向每个参数字符串的内存地址
};
typedef struct cmd cmd;

/*
使用calloc分配一个新的cmd结构的内存空间并初始化

如果成功返回指向新的cmd结构的指针
如果出错返回空指针
*/

cmd *cmd_init(void);

/*
将c结构中的指针所指向的内存释放，并释放c结构本身

如果出错返回-1
*/

int cmd_free(cmd *c);

/*
解析line，结果存放在c

line	一行命令，以\n结尾
c		存放解析的结果

如果出错返回-1
*/

int cmd_parser(char *line,cmd *c);

/*
执行c，作用在p，输入在in，输出在out

c	要执行的结构
p	作用在的进程
out	打印输出

如果出错返回-1
*/
int cmd_execute(cmd *c,process *p, FILE *out);

/*
从in循环读入然后解析然后执行结果输出到out

in	输入流
out	输出流

出错返回-1
*/
int cmd_loop(FILE *in,FILE *out);

// 命令对应执行的函数
struct cmd_call {
	char *argv0;
	int (*func)(FILE *out,cmd *c,process *p);
};
typedef struct cmd_call cmd_call;

int do_backend(FILE *out,cmd *c,process *p);
int do_close(FILE *out,cmd *c,process *p);
int do_dump(FILE *out,cmd *c,process *p);
int do_info(FILE *out,cmd *c,process *p);
int do_open(FILE *out,cmd *c,process *p);
int do_print(FILE *out,cmd *c,process *p);
int do_search(FILE *out,cmd *c,process *p);
int do_write(FILE *out,cmd *c,process *p);

// 命令对应函数列表
static cmd_call cmd_calls[] = {
	/*	argv0		function   */
	{	"backend",	do_backend	},
	{	"close",	do_close,	},
	{	"dump",		do_dump,	},
	{	"info",		do_info,	},
	{	"open",		do_open,	},
	{	"print",	do_print,	},
	{   "search",	do_search,	},
	{	"write",	do_write,	},
	{    NULL,		NULL,		},
};

map *map_init(void) {
	map *n = (map*)calloc(1,sizeof(*n));
	n->pathname = NULL;
	return n;
}

static int make_perms(char *perms,int *prot,int *flags) {
	if (strlen(perms) != 4 || prot == NULL || flags == NULL)
		return -1;
	*prot = PROT_NONE;
	*flags = 0;
	if (index(perms,'r') != NULL)
		*prot |= PROT_READ;
	if (index(perms,'w') != NULL)
		*prot |= PROT_WRITE;
	if (index(perms,'x') != NULL)
		*prot |= PROT_EXEC;
	if (index(perms,'p') != NULL)
		*flags = MAP_SHARED;
	if (index(perms,'s') != NULL)
		*flags = MAP_PRIVATE;
	return 1;
}

// 移除字符串开头和结尾的空白，移除后的结果使用char *指针返回
static char *strstripwhite(const char *s) {
	char *ns = strdup(s); // 新的字符串用作操作
	char *saveptr = ns;
	int len = strlen(ns);
	int i;

	for (i=len-1;isspace(ns[i]);i--) { // 移除结尾的空白
		ns[i] = '\0';
	}
	for (;isspace(*ns);ns++) // 移动指针到行首非空白字符上
		;
	ns = strdup(ns); // 拷贝新的字符串
	free(saveptr); // 释放旧的字符串
	return ns;
}

int map_parser(char *mapsline,map *m) {
	if (mapsline == NULL || m == NULL)
		return -1;
	char *linecopy = strdup(mapsline);
	m->addr_start = (void *)strtoull(strtok(linecopy,"-"), NULL, 16);
	m->addr_end = (void *)strtoull(strtok(NULL," "), NULL, 16);
	make_perms(strtok(NULL," "),&m->prot,&m->flags);
	m->offset = strtoull(strtok(NULL," "), NULL, 16);
	m->dev_major = atoi(strtok(NULL, ":"));
	m->dev_minor = atoi(strtok(NULL, " "));
	m->inode = atol(strtok(NULL, " "));

	char *pathname;
	pathname = strtok(NULL, "\n");
	if (pathname == NULL)
		m->pathname = NULL;
	else
		m->pathname = strstripwhite(pathname);
	return 1;
}

int map_free(map *m) {
	if (m->pathname != NULL) {
		free(m->pathname);
	}
	free(m);
	return 1;
}

static void show_perms(int prot,int flags) {
	printf("perms: ");
	if (prot == PROT_READ)
		printf("PROT_READ ");
	else if (prot == PROT_WRITE)
		printf("PROT_WRITE ");
	else if (prot == PROT_EXEC)
		printf("PROT_EXEC ");
	else if (prot == (PROT_READ | PROT_WRITE))
		printf("PROT_READ|PROT_WRITE ");
	else if (prot == (PROT_READ | PROT_EXEC))
		printf("PROT_READ|PROT_EXEC ");
	else if (prot == (PROT_READ | PROT_WRITE | PROT_EXEC))
		printf("PROT_READ|PROT_WRITE|PROT_EXEC ");
	if (flags == MAP_SHARED)
		printf("MAP_SHARED ");
	else if (flags == MAP_PRIVATE)
		printf("MAP_PRIVATE ");
	putchar('\n');
	return;
}

int map_show(map *m,FILE *output) {
	if (m == NULL || output == NULL)
		return -1;
	fprintf(output,"virtual memory address range: %lx %lx\n",
			(unsigned long)m->addr_start,
			(unsigned long)m->addr_end);
	show_perms(m->prot,m->flags);
	fprintf(output,"offset: %lx\n",m->offset);
	fprintf(output,"dev: %d:%d\n",m->dev_major,m->dev_minor);
	fprintf(output,"inode: %ld\n",m->inode);
	fprintf(output,"pathname: ");
	if (m->pathname != NULL)
		fprintf(output,"%s",m->pathname);
	putc('\n',output);
	return 1;
}

process *process_init(void) {
	process *p = (process *)calloc(1,sizeof(*p));
	p->pid = 0;
	p->regions = 0;
	p->procmemfd = -1;
	return p;
}

int process_open(pid_t pid,process *p) {
	char fn[PATH_MAX];
	snprintf(fn,PATH_MAX,"/proc/%d/maps",pid);
	FILE *mapsfp = fopen(fn,"r");
	if (mapsfp == NULL)
		return -1;

	p->pid = pid;

	char line[LINEMAX];
	while (fgets(line,LINEMAX,mapsfp) != NULL) {
		if (p->regions == MAX_REGIONS)
			break;
		p->maps[p->regions] = map_init();
		map_parser(line,p->maps[p->regions]);
		++(p->regions);
	}
	fclose(mapsfp);

	if (process_set_read(DEFAULT_METHOD,p) == -1)
		return -1;
	if (process_set_write(DEFAULT_METHOD,p) == -1)
		return -1;
	return p->regions;
}

int process_set_read(int method, process *p) {
	if (p == NULL)
		return -1;
	if (method == 0) {
		p->read = procvm_read;
	} else if (method == 1) {
		p->read = procmem_read;
	} else {
		p->read = NULL;
		return -1;
	}
	return 1;
}
int process_set_write(int method, process *p) {
	if (p == NULL)
		return -1;
	if (method == 0) {
		p->write = procvm_write;
	} else if (method == 1) {
		p->write = procmem_write;
	} else {
		p->write = NULL;
		return -1;
	}
	return 1;	
}

int process_clean(process *p) {
	if (p == NULL)
		return -1;
	int i;
	for (i=0;i<(p->regions);i++) {
		map_free(p->maps[i]);
	}
	p->pid = 0;
	p->regions = 0;
	return p->regions;
}

int process_show(process *p,FILE *output) {
	if (p == NULL)
		return -1;
	int i;
	fprintf(output,"PID: %d\n",p->pid);
	fprintf(output,"memory regions: %d\n",p->regions);
	for (i=0;i<p->regions;i++) {
		map_show(p->maps[i],output);
		putchar('\n');
	}
	return 1;
}

int process_readm(process *p,void *addr,void *buf,size_t count) {
	return (p->read(p,addr,buf,count));
}

int procvm_read(process *p,void *addr,void *buf,size_t count) {
	if (p == NULL || addr == NULL)
		return -1;
	if (count == 0)
		return 0;
	if (buf == NULL)
		return -1;

	struct iovec localiobuf[1];
	struct iovec remoteiobuf[1];
	localiobuf[0].iov_base = buf;
	localiobuf[0].iov_len = count;
	remoteiobuf[0].iov_base = addr;
	remoteiobuf[0].iov_len = count;

	ssize_t nread = process_vm_readv(p->pid,localiobuf,1,remoteiobuf,1,0);
	if (nread != count)
		return -1;

	return 1;
}

int procmem_read(process *p,void *addr,void *buf,size_t count) {
	if (p == NULL || addr == NULL || buf == NULL)
		return -1;
	if (count == 0)
		return 0;
	if (p->pid <= 0)
		return -1;

	if (p->procmemfd < 0) {
		char path[PATH_MAX];
		snprintf(path,PATH_MAX,"/proc/%d/mem",p->pid);
		p->procmemfd = open(path,O_RDWR);
		if (p->procmemfd == -1)
			return -1;
	}

	if (pread(p->procmemfd,buf,count,(off_t)addr) != count)
		return -1;

	return 1;
}

int process_writem(process *p,void *addr,void *buf,size_t count) {
	return (p->write(p,addr,buf,count));
}

int procvm_write(process *p,void *addr,void *buf,size_t count) {
	if (p == NULL || addr == NULL)
		return -1;
	if (count == 0)
		return 0;
	if (buf == NULL)
		return -1;

	struct iovec localiobuf[1];
	struct iovec remoteiobuf[1];
	localiobuf[0].iov_base = buf;
	localiobuf[0].iov_len = count;
	remoteiobuf[0].iov_base = addr;
	remoteiobuf[0].iov_len = count;

	ssize_t nwrite = process_vm_writev(p->pid,localiobuf,1,remoteiobuf,1,0);
	if (nwrite != count)
		return -1;

	return 1;
}

int procmem_write(process *p,void *addr,void *buf,size_t count) {
	if (p == NULL || addr == NULL || buf == NULL)
		return -1;
	if (count == 0)
		return 0;
	if (p->pid <= 0)
		return -1;

	if (p->procmemfd < 0) {
		char path[PATH_MAX];
		snprintf(path,PATH_MAX,"/proc/%d/mem",p->pid);
		p->procmemfd = open(path,O_RDWR);
		if (p->procmemfd == -1)
			return -1;
	}

	if (pwrite(p->procmemfd,buf,count,(off_t)addr) != count)
		return -1;
	
	return 1;
}

int process_dumpm(process *p,void *addr,size_t count,int outfd) {
	if (p == NULL || addr == NULL || outfd == -1)
		return -1;
	if (count == 0)
		return 0;

	unsigned char buf[count];
	if (process_readm(p,addr,(void *)buf,count) == -1)
		return -1;
write:
	if (write(outfd,buf,count) != count)
		if (errno == EINTR)
			goto write;
	return 1;
}

cmd *cmd_init(void) {
	cmd *c = (cmd *)calloc(1,sizeof(*c));
	if (c == NULL)
		return NULL;
	c->argc = 0;
	int i;
	for (i=0;i<MAX_ARGC;i++) {
		c->argv[i] = NULL;
	}
	return c;
}

int cmd_free(cmd *c) {
	int i;
	for (i=0;i<c->argc;i++) {
		free(c->argv[i]);
	}
	free(c);
	return 1;
}

int cmd_parser(char *line,cmd *c) {
	if (line == NULL || c == NULL)
		return -1;
	char *token = NULL;

	token = strtok(line," "); // 获取argv0
	if (token != NULL) {
		c->argv[c->argc] = strstripwhite(token);
		c->argc++;
	}
	while ((token = strtok(NULL," \n")) != NULL) {
		c->argv[c->argc] = strstripwhite(token);
		c->argc++;
	}
	return 1;
}

int cmd_execute(cmd *c,process *p,FILE *out) {
	if (c == NULL)
		return -1;
	if (c->argc <= 0)
		return -1;
	int ret = -1;

	char *argv0 = c->argv[0];

	int i;
	for (i=0;cmd_calls[i].argv0 != NULL;i++) {
		if (strcmp(argv0,cmd_calls[i].argv0) == 0) {
			ret = cmd_calls[i].func(out,c,p);
		}
	}
	return ret;
}

int cmd_loop(FILE *in,FILE *out) {
	if (in == NULL || out == NULL)
		return -1;
	process *proc = process_init();
	if (proc == NULL)
		return -1;
	char line[LINEMAX];
	cmd *command = NULL;
	int ret;

	while (fgets(line,LINEMAX,in) != NULL) {
		command = cmd_init();
		if (command == NULL)
			return -1;
		cmd_parser(line,command);
		if (command->argc < 1)
			continue;
		if (strcmp(command->argv[0],"exit") == 0) {
			process_clean(proc);
			break;
		}
		ret = cmd_execute(command, proc,out);
		if (ret == -1) {
			fprintf(out,"?");
			if (errno) {
				fprintf(out,strerror(errno));
				errno = 0;
			}
			fprintf(out,"\n");
		}
		cmd_free(command);
	}
	free(proc);
	return 1;
}

int do_backend(FILE *out,cmd *c,process *p) {
	if (out == NULL || c == NULL || p == NULL)
		return -1;
	if (c->argc < 2)
		return -1;
	if (p->pid <= 0)
		return -1;

	int method = 0;
	if (strcmp(c->argv[1],"procmem") == 0)
		method = 1;
	else if (strcmp(c->argv[1],"procvm") == 0)
		method = 0;
	else
		return -1;

	int retr = process_set_read(method,p);
	int retw = process_set_write(method,p);
	if (retr == -1 || retw == -1)
		return -1;

	return 1;
}

int do_close(FILE *out,cmd *c,process *p) {
	if (out == NULL || c == NULL || p == NULL)
		return -1;
	if (c->argc < 1)
		return -1;
	if (p->pid <= 0)
		return -1;

	return (process_clean(p));
}

int do_dump(FILE *out,cmd *c,process *p) {
	if (out == NULL || c == NULL || p == NULL)
		return -1;
	if (c->argc < 4)
		return -1;
	if (p->pid <= 0)
		return -1;

	void *addr = (void *)strtoull(c->argv[1],NULL,16);
	size_t len = (size_t)strtoull(c->argv[2],NULL,16);
	char path[PATH_MAX];

	snprintf(path,PATH_MAX,"%s_%d_%lx-%lx.mem",
			c->argv[3],p->pid,
			(unsigned long)addr,(unsigned long)addr + len);

	int fd = open(path,O_WRONLY|O_CREAT|O_TRUNC,S_IWUSR|S_IRUSR);
	if (fd == -1)
		return -1;
	int ret = process_dumpm(p,addr,len,fd);
	close(fd);
	return ret;
}

int do_info(FILE *out,cmd *c,process *p) {
	if (out == NULL || c == NULL || p == NULL)
		return -1;
	if (c->argc < 1)
		return -1;

	return (process_show(p,out));
}

int do_open(FILE *out,cmd *c,process *p) {
	if (out == NULL || c == NULL || p == NULL)
		return -1;
	if (c->argc < 2)
		return -1;
	if (p->pid > 0)
		return -1;

	pid_t pid = atoi(c->argv[1]);

	return (process_open(pid,p));
}

int do_print(FILE *out,cmd *c,process *p) {
	if (out == NULL || c == NULL || p == NULL)
		return -1;
	if (c->argc < 3)
		return -1;
	if (p->pid <= 0)
		return -1;
	
	void *addr = (void *)strtoull(c->argv[1],NULL,16);
	size_t len = strtoull(c->argv[2],NULL,16);

	uint8_t *buf = calloc(1,len);
	if (process_readm(p,addr,(void *)buf,len) == -1)
		goto Err;

	int i;
	for (i=0;i<len;i++) {
		fprintf(out,"%x",
				*(buf+i));
	}
	free(buf);
	return 1;

Err:
	if (buf != NULL)
		free(buf);
	return -1;
}

char char2hex_table [16][2] = {
{ '0', 0},  { '1', 1},  { '2', 2},  { '3', 3}, 
{ '4', 4},  { '5', 5},  { '6', 6},  { '7', 7}, 
{ '8', 8},  { '9', 9},  { 'A', 10}, { 'B', 11},
{ 'C', 12}, { 'D', 13}, { 'E', 14}, { 'F', 15}
};

int strhex2data(char *str,void *data,size_t n) {
	size_t i;
	int j;
	uint8_t *saveptr = (uint8_t *)data;
	for (i=0;i<n;i++) {
		for (j=0;j<16;j++) {
			if (str[i] == char2hex_table[j][0]) {
				saveptr[i] = char2hex_table[j][1];
			}
		}
	}
	return i;
}

int do_write(FILE *out,cmd *c,process *p) {
	if (out == NULL || c == NULL || p == NULL)
		return -1;
	if (c->argc < 3)
		return -1;
	if (p->pid <= 0)
		return -1;

	void *addr = (void *)strtoull(c->argv[1],NULL,16);
	size_t len = strlen(c->argv[2]);
	uint8_t *data = calloc(1,len);
	char *hexstr = c->argv[2];

	strhex2data(hexstr,(void *)data,len);
	int ret = process_writem(p,addr,data,len);
	free(data);
	
	return ret;
}

int do_search(FILE *out,cmd *c,process *p) {
	return 1;
}

int main(int argc, char *argv[]) {
	FILE *in = stdin;
	FILE *out = stdout;

	if (cmd_loop(in,out) == -1) {
		fprintf(stderr,"IO Error\n");
		exit(EXIT_FAILURE);
	}

	exit(EXIT_SUCCESS);
}
