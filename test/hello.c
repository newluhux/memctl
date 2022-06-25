#include <stdio.h>
#include <unistd.h>
#include <string.h>

#define STR "hello";

int main(void) {
	char *data = strdup("hello"); // 拷贝到 heap
loop:
	printf("%s %ld\n",data,getpid());
	fflush(stdout);
	sleep(1);
	goto loop;
}
