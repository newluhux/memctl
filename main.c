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
int map_show(map *m,FILE *output);

struct process {
	pid_t pid;
	int regions;
	map *maps[MAX_REGIONS];
};
typedef struct process process;

process *process_init(void);
int process_open(pid_t pid,process *p);
int process_close(process *p);
int process_show(process *p,FILE *output);
size_t process_mem_read(pid_t pid,void *addr,size_t len,void *buf);
size_t process_mem_write(pid_t pid,void *addr,size_t len,void *buf);
size_t process_mem_read_map(pid_t pid,map *map, void *buf);
size_t process_mem_write_map(pid_t pid,map *map, void *buf);
size_t process_mem_save_map(pid_t pid,map *map,int outfd);
int process_mem_save_map_all(process *p,char *fnprefix);

#define MAX_ARGC 20

struct cmd {
	int argc;
	char *argv[MAX_ARGC];
};
typedef struct cmd cmd;

cmd *cmd_init(void);
int cmd_free(cmd *c);
int cmd_parser(char *line,cmd *c);
int cmd_execute(cmd *c,process *p,FILE *in, FILE *out);
int cmd_loop(FILE *in,FILE *out);

void do_exit(void);
int do_open(process *p,pid_t pid);
int do_close(process **p);
int do_info(process *p,FILE *out);
int do_dumpall(process *p,char *prefix);

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



int map_show(map *m,FILE *output) {
	if (m == NULL || output == NULL)
		return -1;
	fprintf(output,"virtual memory address range: %lx-%lx\n",
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

int process_show(process *p,FILE *output) {
	if (p == NULL)
		return -1;
	int i;
	for (i=0;i<p->regions;i++) {
		map_show(p->maps[i],output);
		putchar('\n');
	}
	return 1;
}

int is_addr_in_map(void *addr,map *m) {
	if (m == NULL || addr == NULL)
		return -1;
	if (addr >= m->addr_start &&
		addr <= m->addr_end) {
		return 1;
	}
	return -1;
}

int is_addr_in_process(void *addr,process *p) {
	int i;
	for (i=0;i<p->regions;i++) {
		if (is_addr_in_map(addr,p->maps[i]) == 1) {
			return 1;
		}
	}
	return -1;
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

	token = strtok(line," "); // 获取命令
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

int cmd_execute(cmd *c,process *p,FILE *in,FILE *out) {
	if (c == NULL)
		return -1;
	if (c->argc <= 0)
		return -1;
	int ret = 0;

	char *argv0 = c->argv[0];
	if ((strcmp(argv0,"exit") == 0) || (strcmp(argv0,"quit") == 0)) {
		do_exit();
	} else if (strcmp(argv0,"open") == 0) {
		if (c->argc < 2)
			ret = -1;
		else
			ret = do_open(p,atoi(c->argv[1]));
	} else if (strcmp(argv0,"close") == 0) {
		ret = do_close(&p);
	} else if (strcmp(argv0,"info") == 0) {
		ret = do_info(p,out);
	} else if (strcmp(argv0,"dumpall") == 0) {
		if (c->argc < 2)
			ret = -1;
		else
			ret = do_dumpall(p,c->argv[1]);
	} else {
		fprintf(out,"?\n");
	}
	if (ret < 0) {
		fprintf(out,"?\n");
	}
}

int cmd_loop(FILE *in,FILE *out) {
	if (in == NULL || out == NULL)
		return -1;
	process *proc = process_init();
	if (proc == NULL)
		return -1;
	char line[LINEMAX];
	cmd *command = NULL;

	while (fgets(line,LINEMAX,in) != NULL) {
		command = cmd_init();
		if (command == NULL)
			return -1;
		cmd_parser(line,command);
		cmd_execute(command, proc,in,out);
		cmd_free(command);
	}
	do_close(&proc);
	return 1;
}


void do_exit(void) {
	exit(EXIT_SUCCESS);
}

int do_open(process *p,pid_t pid) {
	if (p == NULL)
		return -1;
	if (p->pid > 0 || // p 已被使用
		pid <= 0)
		return -1;
		
	return (process_open(pid,p));
}

int do_close(process **p) {
	if (p == NULL)
		return -1;
	process_close(*p);
	*p = NULL;
	return 1;
}

int do_info(process *p,FILE *out) {
	if (p == NULL)
		return -1;
	return (process_show(p,out));
}

int do_dumpall(process *p,char *prefix) {
	if (p == NULL)
		return -1;
	if (prefix == NULL)
		prefix = "";
	return (process_mem_save_map_all(p,prefix));
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
