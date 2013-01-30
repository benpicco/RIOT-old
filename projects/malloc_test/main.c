#include <stdio.h>
#include <malloc.h>
#include <vtimer.h>

struct node {
	struct node* next;
	void* ptr;
};

void fill(char* ptr, int size) {
	int step = size / 25;
	for (int i = 0; i < size; ++i, ++ptr) {
		if ( i % step == 0)
			printf(".");
		*ptr = 'x';
	}
	printf("\n");
}

int main(void)
{
	int chunk = 1024;
	int total = 0;
	struct node head;
	struct node* tail = &head;
	void* ptr;

	while (1) {
		printf("malloc(%d) - %d byte allocated\n", chunk, total);
		ptr = malloc(chunk);
		if (ptr) {
			fill(ptr, chunk);
			total += chunk;

			tail->ptr = ptr;
			if (tail->next = malloc(sizeof(struct node))) {
				tail = tail->next;
				tail->next = 0;
				tail->ptr  = 0;
			}
		}
		if (!ptr || !tail) {
			printf("Failed!\n");

			if (head.ptr) {
				printf("free(%p) - %d left\n", head.ptr, total -= chunk);
				free(head.ptr);
			}
			tail = head.next;

			while (tail) {
				if (tail->ptr) {
					printf("free(%p) - %d left\n", tail->ptr, total -= chunk);
					free(tail->ptr);
				}
				struct node* next = tail->next;
				printf("free node at %p, next node: %p\n", tail, next);
				free(tail);
				tail = next;
			}

			tail = &head;
			vtimer_usleep(1000000);
		}
		vtimer_usleep(100000);
	}
}
