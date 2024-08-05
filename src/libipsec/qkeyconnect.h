#ifndef QKEYCONNECT_H_
#define QKEYCONNECT_H_

#include <library.h>
#include <utils/debug.h>

#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h> // For malloc, free
#include <pthread.h>

#define socket_path "/tmp/my_socket" // 定义本地套接字路径
#define MAX_DYNAMIC_SPI_COUNT 100	 // 设定最大的套接字数量

typedef struct Queue Queue;

typedef struct keyparameter
{
	int range;
	char qkey[64 + 1];
} keyparameter;

typedef struct KeyqueueNode
{
	keyparameter keypara;
	struct KeyqueueNode *next;
} KeyqueueNode;

struct Queue
{
	KeyqueueNode *front;
	KeyqueueNode *rear;
	pthread_mutex_t lock; // 添加锁以保证线程安全
	int count;
};

void init_queue(Queue *queue);

void enqueue(Queue *queue, keyparameter data);

keyparameter dequeue(Queue *queue);

int is_empty(const Queue *queue);


typedef struct
{
	int socket_fd;
	uint32_t spi;
	bool key_type;
	int key_lenth;
	char raw_ekey[64 + 1], raw_dkey[64 + 1], old_dkey[64 + 1]; // 记录原始量子密钥
	Queue *encQueue, *decQueue;								   // 加密密钥队列和解密密钥队列
	int ekey_rw, dkey_lw, dkey_rw;							   // 加密右窗口，解密左窗口，解密右窗口
	pthread_mutex_t mutex;									   // 互斥锁变量
} SpiSocketPair;

extern SpiSocketPair *socket_pairs[MAX_DYNAMIC_SPI_COUNT];
extern int total_sockets;

bool ipsec_sa_register(uint32_t spi, bool inbound);

bool ipsec_sa_destroy(uint32_t spi);

bool getqsk(uint32_t spi, uint32_t next_seqno, bool key_type, chunk_t *qk, size_t keysize);

#endif // QKEYCONNECT_H_