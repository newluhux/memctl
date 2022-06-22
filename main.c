#define _GNU_SOURCE

#include <ctype.h>
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

map *map_init(void);
int map_parser(char *mapsline, map *m);
int map_free(map *m);
int map_show(map *m);

struct process {
	pid_t pid;
	int regions;
	map *maps[MAX_REGIONS];
};
typedef struct process process;

process *process_init(void);
int process_open(pid_t pid,process *p);
int process_close(process *p);
void process_show(process *p);
size_t process_mem_read(pid_t pid,void *addr,size_t len,void *buf);
size_t process_mem_write(pid_t pid,void *addr,size_t len,void *buf);
size_t process_mem_read_map(pid_t pid,map *map, void *buf);
size_t process_mem_write_map(pid_t pid,map *map, void *buf);
size_t process_mem_save_map(pid_t pid,map *map,int outfd);
int process_mem_save_map_all(process *p,char *fnprefix);

map *map_init(void) {
	map *n = (map*)calloc(1,sizeof(*n));
	n->pathname = NULL;
	return n;
}

int make_perms(char *perms,int *prot,int *flags) {
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
char *strstripwhite(const char *s) {
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

void show_perms(int prot,int flags) {
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



int map_show(map *m) {
	if (m == NULL)
		return -1;
	printf("virtual memory address range: %lx-%lx\n",
			(unsigned long)m->addr_start,
			(unsigned long)m->addr_end);
	show_perms(m->prot,m->flags);
	printf("offset: %lx\n",m->offset);
	printf("dev: %d:%d\n",m->dev_major,m->dev_minor);
	printf("inode: %ld\n",m->inode);
	printf("pathname: ");
	if (m->pathname != NULL)
		printf("%s",m->pathname);
	putchar('\n');
	return 1;
}

process *process_init(void) {
	process *p = (process *)calloc(1,sizeof(*p));
	p->pid = 0;
	p->regions = 0;
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
	return p->regions;
}

int process_close(process *p) {
	if (p == NULL)
		return -1;
	int i;
	for (i=0;i<(p->regions);i++) {
		map_free(p->maps[i]);
	}
	p->regions = 0;
	free(p);
	return p->regions;
}

void process_show(process *p) {
	if (p == NULL)
		return;
	int i;
	for (i=0;i<p->regions;i++) {
		map_show(p->maps[i]);
		putchar('\n');
	}
	return;
}

// pid 目标进程的pid
// addr 目标进程的内存地址
// len 要读入的长度
// buf 读入内存存放的缓存区，大小必须和大于等于 len
size_t process_mem_read(pid_t pid,void *addr, size_t len, void *buf) {
	if (addr == NULL || len <= 0 || buf == NULL )
		return -1;
	struct iovec localiobuf[1];
	struct iovec remoteiobuf[1];
	localiobuf[0].iov_base = buf;
	localiobuf[0].iov_len = len;
	remoteiobuf[0].iov_base = addr;
	remoteiobuf[0].iov_len = len;
	ssize_t nread;
	nread = process_vm_readv(pid,localiobuf,1,remoteiobuf,1,0); // 核心就这么一行代码
	if (nread != (ssize_t)len)
		return -1;
	return len;
}

// pid 目标进程的pid
// addr 目标进程的内存地址
// len 要写入的长度
// buf 准备写入内存存放的缓存区，大小必须大于等于len
size_t process_mem_write(pid_t pid,void *addr, size_t len, void *buf) {
	if (addr == NULL || len <= 0 || buf == NULL )
		return -1;
	struct iovec localiobuf[1];
	struct iovec remoteiobuf[1];
	localiobuf[0].iov_base = buf;
	localiobuf[0].iov_len = len;
	remoteiobuf[0].iov_base = addr;
	remoteiobuf[0].iov_len = len;
	ssize_t nwrite;
	nwrite = process_vm_writev(pid,localiobuf,1,remoteiobuf,1,0); // 核心就这么一行代码
	if (nwrite != (ssize_t)len)
		return -1;
	return len;	
}

size_t process_mem_read_map(pid_t pid,map *map,void *buf) {
	if (map == NULL || buf == NULL)
		return -1;
	size_t length = map->addr_end - map->addr_start;
	if (length <= 0)
		return -1;
	if (process_mem_read(pid,map->addr_start,length,buf) != length)
		return -1;
	return length;
}

size_t process_mem_write_map(pid_t pid,map *map,void *buf) {
	if (map == NULL || buf == NULL)
		return -1;
	size_t length = map->addr_end - map->addr_start;
	if (length <= 0)
		return -1;
	if (process_mem_write(pid,map->addr_start,length,buf) != length)
		return -1;
	return length;
}

size_t process_mem_save_map(pid_t pid,map *map,int outfd) {
	if (map == NULL || outfd < 0)
		return -1;
	int pagesize = sysconf(_SC_PAGE_SIZE);
	unsigned char buf[pagesize];

	void *addr_cur;
	for (addr_cur=map->addr_start;addr_cur < map->addr_end;addr_cur+=pagesize) {
		if (process_mem_read(pid,addr_cur,pagesize,buf)
		                     != (size_t)pagesize)
			return -1;
		if (write(outfd,buf,pagesize) != pagesize)
			return -1;
	}
	return (size_t)(addr_cur - map->addr_start);
}

int process_mem_save_map_all(process *p,char *fnprefix) {
	if (p == NULL || fnprefix == NULL)
		return -1;
	char output[PATH_MAX];
	int outfd = -1;
	int i;
	int count = 0;

	for (i=0;i<p->regions;i++) {
		if (p->maps[i]->pathname != NULL)
			if (strcmp(p->maps[i]->pathname, "[vvar]") == 0)
				continue;
		snprintf(output,PATH_MAX,"%s_%d_%lx-%lx.mem",
				fnprefix,p->pid,
				(unsigned long)p->maps[i]->addr_start,
				(unsigned long)p->maps[i]->addr_end);
		outfd = open(output,O_WRONLY|O_CREAT|O_TRUNC,S_IRUSR|S_IWUSR);
		if (outfd == -1)
			return -1;
		if (process_mem_save_map(p->pid,p->maps[i],outfd) == -1) {
			close(outfd);
			return -1;
		}
		count++;
	}
	return count;
}

// 如果pattern在s的头部，则返回1，
int matchstrhead(char *s,char *pattern) {
	int ret = 0;
	if (strstr(s,pattern) == s)
		return 1;
	else
		return 0;
}

process *proc = NULL;

void do_exit(void) {
	if (proc != NULL)
		process_close(proc);
	exit(EXIT_SUCCESS);
}

int do_open(char *cmd,process *p) {
	if (cmd == NULL || p == NULL)
		return -1;
	if (p->pid > 0) { // 已经被使用
		return -1;
	}

	pid_t pid = 0;
	sscanf(cmd,"open %d",&pid);
	if (pid == 0)
		return -1;
		
	return (process_open(pid,p));
}

int do_dumpall(char *cmd,process *p) {
	if (cmd == NULL || p == NULL)
		return -1;
	cmd += strlen("dumpall");
	cmd = strstripwhite(cmd);
	char prefix[PATH_MAX];
	strncpy(prefix,cmd,PATH_MAX);
	free(cmd);
	return (process_mem_save_map_all(p,prefix));
}

int commands(FILE *input) {
	if (input == NULL)
		return 0;

	int ret = 0;
	char line[LINEMAX]; // 输入行
	char *temp; // 临时存放字符串指针

	proc = process_init();

	while (fgets(line,LINEMAX,input) != NULL) {
		// 删除头部和尾部的空白
		temp = strstripwhite(line);
		strcpy(line,temp);
		free(temp);
		
		if (matchstrhead(line,"#")) { // 忽略注释
			continue;
		} else if (matchstrhead(line,"quit")) {
			do_exit();
		} else if (matchstrhead(line,"exit")) {
			do_exit();
		} else if (matchstrhead(line,"open")) {
			ret = do_open(line,proc);
		} else if (matchstrhead(line,"close")) {
			ret = process_close(proc);
			proc = NULL;
		} else if (matchstrhead(line,"info")) {
			process_show(proc);
		} else if (matchstrhead(line,"dumpall")) {
			ret = do_dumpall(line,proc);
		} else { // 如果命令非法
			printf("?\n");
		}
		if (ret == -1) { // 如果函数调用出错
			printf("?\n");
			ret = 0;
		}
	}
	return 1;
}

int main(int argc, char *argv[]) {
	FILE *in = stdin;

	if (commands(in) == -1) {
		fprintf(stderr,"Can't read input stream\n");
		exit(EXIT_FAILURE);
	}

	exit(EXIT_SUCCESS);
}
