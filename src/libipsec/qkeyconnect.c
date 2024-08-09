/*
 * @Author: xmgao dearlanxing@mail.ustc.edu.cn
 * @Date: 2024-07-17 19:07:59
 * @LastEditors: xmgao dearlanxing@mail.ustc.edu.cn
 * @LastEditTime: 2024-08-09 17:37:04
 * @FilePath: \c\strongswan-5.9.14\src\libipsec\qkeyconnect.c
 * @Description: 
 * 
 * Copyright (c) 2024 by ${git_name_email}, All Rights Reserved. 
 */
#include "qkeyconnect.h"
#include "sha256hmac.h"
#define EVP_MAX_MD_SIZE 64          //HMAC封装

SpiSocketPair *socket_pairs[MAX_DYNAMIC_SPI_COUNT] = {NULL};
int total_sockets = 0;

// 初始化队列
void init_queue(Queue *queue)
{
    queue->front = NULL;
    queue->rear = NULL;
    pthread_mutex_init(&queue->lock, NULL); // 初始化锁
    queue->count = 0;
}

// 入队
void enqueue(Queue *queue, keyparameter data)
{
    KeyqueueNode *new_node = (KeyqueueNode *)malloc(sizeof(KeyqueueNode));
    if (!new_node)
    {
        perror("Memory allocation error");
    }
    new_node->keypara = data;
    new_node->next = NULL;
    if (queue->rear)
    {
        queue->rear->next = new_node;
    }
    else
    {
        queue->front = new_node;
    }
    queue->rear = new_node;
    pthread_mutex_lock(&queue->lock); // 加锁
    queue->count += 1;
    pthread_mutex_unlock(&queue->lock); // 解锁
}

// 出队
keyparameter dequeue(Queue *queue)
{
    if (is_empty(queue))
    {
        perror("Queue underflow");
        return;
    }
    KeyqueueNode *temp = queue->front;
    keyparameter data = temp->keypara;
    queue->front = temp->next;
    if (!queue->front)
    {
        queue->rear = NULL;
    }
    free(temp);
    pthread_mutex_lock(&queue->lock); // 加锁
    queue->count -= 1;
    pthread_mutex_unlock(&queue->lock); // 解锁
    return data;
}

// 检查队列是否为空
int is_empty(const Queue *queue)
{
    return (queue->front == NULL);
}

// 销毁队列
void destroy_queue(Queue *queue)
{
    free(queue);
    pthread_mutex_destroy(&queue->lock); // 销毁锁
}

// 注册新的child SA(ipsec sa)
bool ipsec_sa_register(uint32_t spi, bool inbound)
{
    int ret;
    char buf[128], rbuf[128];
    int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        perror("socket creation failed");
        return false;
    }
    struct sockaddr_un server_addr;
    memset(&server_addr, 0, sizeof(struct sockaddr_un));
    server_addr.sun_family = AF_UNIX;
    strncpy(server_addr.sun_path, socket_path, sizeof(server_addr.sun_path) - 1);

    int connect_status = connect(sockfd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr_un));
    if (connect_status < 0)
    {
        perror("connect failed");
        return false;
    }
    sprintf(buf, "childsaregister %u %d\n", spi, inbound);
    ret = send(sockfd, buf, strlen(buf), 0);
    if (ret < 0)
    {
        perror("SpiRegisterRequest send error!\n");
        return false;
    }
    return true;
}

// 删除child SA(ipsec sa)
bool ipsec_sa_destroy(uint32_t spi)
{
    int ret;
    char buf[128];
    int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        perror("socket creation failed");
        return false;
    }
    struct sockaddr_un server_addr;
    memset(&server_addr, 0, sizeof(struct sockaddr_un));
    server_addr.sun_family = AF_UNIX;
    strncpy(server_addr.sun_path, socket_path, sizeof(server_addr.sun_path) - 1);

    int connect_status = connect(sockfd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr_un));
    if (connect_status < 0)
    {
        perror("connect failed");
        return false;
    }
    sprintf(buf, "childsadestroy %u\n", spi);
    ret = send(sockfd, buf, strlen(buf), 0);
    if (ret < 0)
    {
        perror("childsadestroyRequest send error!\n");
        return false;
    }
    return true;
}

void *thread_enckey_preaccess(void *args)
{
    SpiSocketPair *spipair = (SpiSocketPair *)args;
    int next_seqno = 1;
    while (1) // 大概10ms获取一次密钥，每次更换用时1ms
    {
        if (spipair->encQueue->count < 10)
        {
            char buf[128], rbuf[128];
            sprintf(buf, "getsk %u %d %u 0\n", spipair->spi, spipair->key_lenth, next_seqno);
            int ret = send(spipair->socket_fd, buf, strlen(buf), 0);
            if (ret < 0)
            {
                perror("getsk send error!\n");
                return false;
            }
            ret = read(spipair->socket_fd, rbuf, sizeof(rbuf));
            if (ret < 0)
            {
                perror("getsk read error!\n");
                return false;
            }
            keyparameter keypara;
            int range = 0;
            memcpy(&range, rbuf, sizeof(int));
            next_seqno += range;
            keypara.range = range;
            memcpy(keypara.qkey, rbuf + sizeof(int), spipair->key_lenth);
            enqueue(spipair->encQueue, keypara);
        }
        else
        {
            usleep(1000);
        }
    }
    destroy_queue(spipair->encQueue);
}

void *thread_deckey_preaccess(void *args)
{
    SpiSocketPair *spipair = (SpiSocketPair *)args;
    int next_seqno = 1;
    while (1)
    {
        if (spipair->decQueue->count < 10)
        {
            char buf[128], rbuf[128];
            sprintf(buf, "getsk %u %d %u 1\n", spipair->spi, spipair->key_lenth, next_seqno);
            int ret = send(spipair->socket_fd, buf, strlen(buf), 0);
            if (ret < 0)
            {
                perror("getsk send error!\n");
                return false;
            }
            ret = read(spipair->socket_fd, rbuf, sizeof(rbuf));
            if (ret < 0)
            {
                perror("getsk read error!\n");
                return false;
            }
            keyparameter keypara;
            int range = 0;
            memcpy(&range, rbuf, sizeof(int));
            next_seqno += range;
            keypara.range = range;
            memcpy(keypara.qkey, rbuf + sizeof(int), spipair->key_lenth);
            enqueue(spipair->decQueue, keypara);
        }
        else
        {
            usleep(1000);
        }
    }
    destroy_queue(spipair->decQueue);
}

// 为每个SPI,key_type对返回不同的SOCKET
SpiSocketPair *findspipair(uint32_t spi)
{

    // 检查是否已经存在特定SPI
    for (int i = 0; i < total_sockets; ++i)
    {
        if (socket_pairs[i]->spi == spi)
        {
            return socket_pairs[i];
        }
    }
    {
        // 动态分配内存，并存储新的SPI参数
        socket_pairs[total_sockets] = (SpiSocketPair *)malloc(sizeof(SpiSocketPair));
        if (socket_pairs[total_sockets] == NULL)
        {
            perror("Failed to allocate memory");
            return false;
        }

        // 创建新的套接字
        int new_socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (new_socket_fd == -1)
        {
            perror("Failed to create socket");
            return false;
        }
        //
        struct sockaddr_un serv_addr;
        memset(&serv_addr, 0, sizeof(serv_addr));
        serv_addr.sun_family = AF_UNIX;
        strncpy(serv_addr.sun_path, socket_path, sizeof(serv_addr.sun_path) - 1);

        int connect_result = connect(new_socket_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
        if (connect_result == -1)
        {
            perror("getqotpk connect error!\n");
            return false;
        }

        // 存储新创建的套接字
        socket_pairs[total_sockets]->socket_fd = new_socket_fd;
        socket_pairs[total_sockets]->spi = spi;
        socket_pairs[total_sockets]->dkey_lw = 0;
        socket_pairs[total_sockets]->dkey_rw = 0;
        socket_pairs[total_sockets]->ekey_rw = 0;
        socket_pairs[total_sockets]->encQueue = (Queue *)malloc(sizeof(Queue));
        init_queue(socket_pairs[total_sockets]->encQueue); // 初始化加密密钥缓存队列
        socket_pairs[total_sockets]->decQueue = (Queue *)malloc(sizeof(Queue));
        init_queue(socket_pairs[total_sockets]->decQueue);               // 初始化解密密钥缓存队列
        pthread_mutex_init(&(socket_pairs[total_sockets]->mutex), NULL); // 初始化互斥锁
        ++total_sockets;
        return socket_pairs[total_sockets - 1];
    }
}


// /** 密钥预存取
//  * @description: 获取量子密钥,通过spi和序列号获取对应的密钥
//  * @param {uint32_t} spi spi
//  * @param {uint32_t} next_seqno 序列号
//  * @param {bool} key_type TRUE表示解密，FALSE表示加密
//  * @param {chunk_t} *qk 量子密钥存储
//  * @param {size_t} keysize 密钥长度
//  * @return {*} TRUE if 获取成功
//  */
// bool getqsk(uint32_t spi, uint32_t next_seqno, bool key_type, chunk_t *qk, size_t keysize)
// {
//     int ret = 0;
//     SpiSocketPair *spipair;
//     spipair = findspipair(spi);
//     if (spipair == NULL)
//     {
//         return false;
//     }
//     pthread_mutex_lock(&spipair->mutex);
//     if (key_type == 0)
//     {
//         if (next_seqno > spipair->ekey_rw)
//         { // 向km请求密钥和密钥派生参数
//             if (spipair->socket_fd == -1)
//             {
//                 // 处理建立连接失败的情况
//                 perror("establish_connection error!\n");
//                 return false;
//             }
//             // 如果是第一个数据包，启动密钥预取线程
//             if (next_seqno == 1)
//             {
//                 spipair->key_lenth = keysize;
//                 pthread_t thread_enckey;
//                 // 创建子线程
//                 if (pthread_create(&thread_enckey, NULL, thread_enckey_preaccess, (void *)spipair) != 0)
//                 {
//                     perror("pthread_create");
//                     return false;
//                 }
//                 // 线程分离
//                 if (pthread_detach(thread_enckey) != 0)
//                 {
//                     perror("pthread_detach");
//                     return false;
//                 }
//             }
//             while (is_empty(spipair->encQueue))
//             { // 先判断队列是否为空，如果是空，说明参数还未到达队列，进行一定时间的等待
//                 usleep(1000);
//             }
//             keyparameter keypara = dequeue(spipair->encQueue); // 正确的密钥参数由一个队列管理
//             memcpy(spipair->raw_ekey, keypara.qkey, keysize);
//             spipair->ekey_rw += keypara.range;
//         }
//         pthread_mutex_unlock(&spipair->mutex);
//         memcpy(qk->ptr, spipair->raw_ekey, keysize);
//         return true;
//     }
//     else
//     {
//     loop1:
//         if (next_seqno > spipair->dkey_rw)
//         { // 向km请求密钥和密钥派生参数
//             if (spipair->socket_fd == -1)
//             {
//                 // 处理建立连接失败的情况
//                 perror("establish_connection error!\n");
//                 return false;
//             }
//             // 如果是第一个数据包，启动密钥预取线程
//             if (next_seqno == 1)
//             {
//                 spipair->key_lenth = keysize;
//                 pthread_t thread_deckey;
//                 // 创建子线程
//                 if (pthread_create(&thread_deckey, NULL, thread_deckey_preaccess, (void *)spipair) != 0)
//                 {
//                     perror("pthread_create");
//                     return false;
//                 }
//                 // 线程分离
//                 if (pthread_detach(thread_deckey) != 0)
//                 {
//                     perror("pthread_detach");
//                     return false;
//                 }
//             }
//             while (is_empty(spipair->decQueue))
//             { // 先判断队列是否为空，如果是空，说明参数还未到达队列，进行一定时间的等待
//                 usleep(1000);
//             }
//             keyparameter keypara = dequeue(spipair->decQueue); // 正确的密钥参数由一个队列管理
//             memcpy(spipair->old_dkey, spipair->raw_dkey, keysize);
//             memcpy(spipair->raw_dkey, keypara.qkey, keysize);
//             spipair->dkey_lw = spipair->dkey_rw;
//             spipair->dkey_rw += keypara.range;
//             goto loop1;
//         }
//         pthread_mutex_unlock(&spipair->mutex);
//         if (next_seqno > spipair->dkey_lw)
//         {
//             memcpy(qk->ptr, spipair->raw_dkey, keysize);
//             return true;
//         }
//         else
//         {
//             memcpy(qk->ptr, spipair->old_dkey, keysize);
//             return true;
//         }
//     }
// }

/** 非密钥预存取
 * @description: 获取量子密钥,通过spi和序列号获取对应的密钥
 * @param {uint32_t} spi spi
 * @param {uint32_t} next_seqno 序列号
 * @param {bool} key_type TRUE表示解密，FALSE表示加密
 * @param {chunk_t} *qk 量子密钥存储
 * @param {size_t} keysize 密钥长度
 * @return {*} TRUE if 获取成功
 */
bool getqsk(uint32_t spi, uint32_t next_seqno, bool key_type, chunk_t *qk, size_t keysize)
{
	int ret = 0;
	SpiSocketPair *spipair;
	char buf[128], rbuf[128];
	spipair = findspipair(spi);
	if (spipair == NULL)
	{
		return false;
	}
	pthread_mutex_lock(&spipair->mutex);
	if (key_type == 0)
	{
		if (next_seqno > spipair->ekey_rw)
		{
			if (spipair->socket_fd == -1)
			{
				perror("establish_connection error!\n");
				return false;
			}
			sprintf(buf, "getsk %u %d %u %d\n", spi, keysize, next_seqno, key_type);

			ret = send(spipair->socket_fd, buf, strlen(buf), 0);
			if (ret < 0)
			{
				perror("getsk send error!\n");
				return false;
			}
			ret = read(spipair->socket_fd, rbuf, sizeof(rbuf));
			if (ret < 0)
			{
				perror("getsk read error!\n");
				return false;
			}
			int range = 0;
			memcpy(&range, rbuf, sizeof(int));
			memcpy(spipair->raw_ekey, rbuf + sizeof(int), keysize);
			spipair->ekey_rw += range;
		}
		pthread_mutex_unlock(&spipair->mutex);
		memcpy(qk->ptr, spipair->raw_ekey, keysize);
		return true;
	}
	else
	{
	loop1:
		if (next_seqno > spipair->dkey_rw)
		{
			if (spipair->socket_fd == -1)
			{
				perror("establish_connection error!\n");
				return false;
			}
			sprintf(buf, "getsk %u %d %u %d\n", spi, keysize, next_seqno, key_type);
			ret = send(spipair->socket_fd, buf, strlen(buf), 0);
			if (ret < 0)
			{
				perror("getsk send error!\n");
				return false;
			}
			ret = read(spipair->socket_fd, rbuf, sizeof(rbuf));
			if (ret < 0)
			{
				perror("getsk read error!\n");
				return false;
			}
			memcpy(spipair->old_dkey, spipair->raw_dkey, keysize);
			int range = 0;
			memcpy(&range, rbuf, sizeof(int));
			memcpy(spipair->raw_dkey, rbuf + sizeof(int), keysize);
			spipair->dkey_lw = spipair->dkey_rw;
			spipair->dkey_rw += range;
			goto loop1;
		}
		pthread_mutex_unlock(&spipair->mutex);
		if (next_seqno > spipair->dkey_lw)
		{
			memcpy(qk->ptr, spipair->raw_dkey, keysize);
			return true;
		}
		else
		{
			memcpy(qk->ptr, spipair->old_dkey, keysize);
			return true;
		}
		// derive_key(rawkey, ret, next_seqno, keysize);
	}
}

// hkdf
static void compute_hmac_ex(unsigned char *dest, const uint8_t *key, uint32_t klen, const uint8_t *msg, uint32_t mlen)
{
	uint8_t md[SHA256_DIGESTLEN] = {0};
	HMAC_SHA256_CTX hmac;
	hmac_sha256_init(&hmac, key, klen);
	hmac_sha256_update(&hmac, msg, mlen);
	hmac_sha256_final(&hmac, md);
	memcpy(dest, md, SHA256_DIGESTLEN);
}

static void HKDF(const unsigned char *salt, int salt_len,
		  const unsigned char *ikm, int ikm_len,
		  const unsigned char *info, int info_len,
		  unsigned char *okm, int okm_len)
{
	unsigned char prk[EVP_MAX_MD_SIZE];
	compute_hmac_ex(prk, (const uint8_t *)salt, salt_len, (const uint8_t *)ikm, ikm_len);
	unsigned char prev[EVP_MAX_MD_SIZE];
	memset(prev, 0x00, EVP_MAX_MD_SIZE);

	int iter = (okm_len + 31) / 32;

	for (int i = 0; i < iter; i++)
	{
		unsigned char hmac_input[EVP_MAX_MD_SIZE];
		if (i == 0)
		{
			memcpy(hmac_input, info, info_len);
			hmac_input[info_len] = 0x01;
		}
		else
		{
			memcpy(hmac_input, prev, 32);
			memcpy(hmac_input + 32, info, info_len);
			hmac_input[32 + info_len] = i + 1;
		}

		unsigned char hmac_out[EVP_MAX_MD_SIZE];
		compute_hmac_ex(hmac_out, (const uint8_t *)prk, 32, (const uint8_t *)hmac_input, info_len + 32 * (i == 0 ? 0 : 1) + 1);

		memcpy(prev, hmac_out, 32);
		memcpy(okm + i * 32, hmac_out,
			   (i == iter - 1) ? okm_len - i * 32 : 32);
	}
}

/**
 * @description: 派生量子密钥,通过spi和原始密钥派生
 * @param {unsigned char*} key 原始密钥
 * @param {int} next_seqno 序列号
 * @param {int} keysize 密钥长度
 * @return {*} TRUE if 获取成功
 */
static void derive_key(unsigned char *key, int rawkeysize, int next_seqno, int keysize)
{
	unsigned char salt[32] = {0};
	unsigned char info[32];
	unsigned char okm[keysize];
	sprintf(info, "%d", next_seqno);
	HKDF(salt, sizeof(salt) - 1, key, rawkeysize, info, strlen(info), okm, sizeof(okm));
	memcpy(key, okm, keysize);
}


/**
 *获取量子OTP密钥
 *
 * 通过spi和序列号获取对应的密钥
 *
 *
 *
 * @param spi			spi
 * @param next_seqno	序列号
 * @param key_type		TRUE表示解密，FALSE表示加密
 * @param qk			量子密钥存储
 * @param keysize		密钥长度
 * @return				TRUE if 获取成功
 */
bool getqotpk(uint32_t spi, uint32_t next_seqno, bool key_type, chunk_t *qk, size_t keysize)
{
	int ret = 0;
	SpiSocketPair *spipair;
	char buf[128], rbuf[128];
	spipair = findspipair(spi);
	if (spipair == NULL)
	{
		return false;
	}
    char rawkey[keysize + 1];
	if (spipair->socket_fd == -1)
	{
		// 处理建立连接失败的情况
		perror("establish_connection error!\n");
		return false;
	}
	sprintf(buf, "getotpk %u %u %d\n", spi, next_seqno, key_type);
	ret = send(spipair->socket_fd, buf, strlen(buf), 0);
	if (ret < 0)
	{
		perror("getotpk send error!\n");
		return false;
	}
	ret = read(spipair->socket_fd, rbuf, sizeof(rbuf));
	if (ret < 0)
	{
		perror("getqotpk read error!\n");
		return false;
	}
	memcpy(rawkey, rbuf, ret);
	derive_key(rawkey, ret, next_seqno, keysize);
	memcpy(qk->ptr, rawkey, keysize);

	return true;
}