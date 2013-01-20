#include <stdio.h>
#include <stdlib.h>

static void start(void) __attribute__ ((constructor));
static void stop(void) __attribute__ ((destructor));

int main(void)
{
        printf("main == %p\n", main);
        printf("start == %p\n", start);
        printf("stop == %p\n", stop);

	return 0;
}

void start(void)
{
        printf("hello world!\n");
}

void stop(void)
{
        printf("goodbye world!\n");
}
