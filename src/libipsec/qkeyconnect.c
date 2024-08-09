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
#define EVP_MAX_MD_SIZE 64          //HMAC��װ

SpiSocketPair *socket_pairs[MAX_DYNAMIC_SPI_COUNT] = {NULL};
int total_sockets = 0;

// ��ʼ������
void init_queue(Queue *queue)
{
    queue->front = NULL;
    queue->rear = NULL;
    pthread_mutex_init(&queue->lock, NULL); // ��ʼ����
    queue->count = 0;
}

// ���
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
    pthread_mutex_lock(&queue->lock); // ����
    queue->count += 1;
    pthread_mutex_unlock(&queue->lock); // ����
}

// ����
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
    pthread_mutex_lock(&queue->lock); // ����
    queue->count -= 1;
    pthread_mutex_unlock(&queue->lock); // ����
    return data;
}

// �������Ƿ�Ϊ��
int is_empty(const Queue *queue)
{
    return (queue->front == NULL);
}

// ���ٶ���
void destroy_queue(Queue *queue)
{
    free(queue);
    pthread_mutex_destroy(&queue->lock); // ������
}

// ע���µ�child SA(ipsec sa)
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

// ɾ��child SA(ipsec sa)
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
    while (1) // ���10ms��ȡһ����Կ��ÿ�θ�����ʱ1ms
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

// Ϊÿ��SPI,key_type�Է��ز�ͬ��SOCKET
SpiSocketPair *findspipair(uint32_t spi)
{

    // ����Ƿ��Ѿ������ض�SPI
    for (int i = 0; i < total_sockets; ++i)
    {
        if (socket_pairs[i]->spi == spi)
        {
            return socket_pairs[i];
        }
    }
    {
        // ��̬�����ڴ棬���洢�µ�SPI����
        socket_pairs[total_sockets] = (SpiSocketPair *)malloc(sizeof(SpiSocketPair));
        if (socket_pairs[total_sockets] == NULL)
        {
            perror("Failed to allocate memory");
            return false;
        }

        // �����µ��׽���
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

        // �洢�´������׽���
        socket_pairs[total_sockets]->socket_fd = new_socket_fd;
        socket_pairs[total_sockets]->spi = spi;
        socket_pairs[total_sockets]->dkey_lw = 0;
        socket_pairs[total_sockets]->dkey_rw = 0;
        socket_pairs[total_sockets]->ekey_rw = 0;
        socket_pairs[total_sockets]->encQueue = (Queue *)malloc(sizeof(Queue));
        init_queue(socket_pairs[total_sockets]->encQueue); // ��ʼ��������Կ�������
        socket_pairs[total_sockets]->decQueue = (Queue *)malloc(sizeof(Queue));
        init_queue(socket_pairs[total_sockets]->decQueue);               // ��ʼ��������Կ�������
        pthread_mutex_init(&(socket_pairs[total_sockets]->mutex), NULL); // ��ʼ��������
        ++total_sockets;
        return socket_pairs[total_sockets - 1];
    }
}


// /** ��ԿԤ��ȡ
//  * @description: ��ȡ������Կ,ͨ��spi�����кŻ�ȡ��Ӧ����Կ
//  * @param {uint32_t} spi spi
//  * @param {uint32_t} next_seqno ���к�
//  * @param {bool} key_type TRUE��ʾ���ܣ�FALSE��ʾ����
//  * @param {chunk_t} *qk ������Կ�洢
//  * @param {size_t} keysize ��Կ����
//  * @return {*} TRUE if ��ȡ�ɹ�
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
//         { // ��km������Կ����Կ��������
//             if (spipair->socket_fd == -1)
//             {
//                 // ����������ʧ�ܵ����
//                 perror("establish_connection error!\n");
//                 return false;
//             }
//             // ����ǵ�һ�����ݰ���������ԿԤȡ�߳�
//             if (next_seqno == 1)
//             {
//                 spipair->key_lenth = keysize;
//                 pthread_t thread_enckey;
//                 // �������߳�
//                 if (pthread_create(&thread_enckey, NULL, thread_enckey_preaccess, (void *)spipair) != 0)
//                 {
//                     perror("pthread_create");
//                     return false;
//                 }
//                 // �̷߳���
//                 if (pthread_detach(thread_enckey) != 0)
//                 {
//                     perror("pthread_detach");
//                     return false;
//                 }
//             }
//             while (is_empty(spipair->encQueue))
//             { // ���ж϶����Ƿ�Ϊ�գ�����ǿգ�˵��������δ������У�����һ��ʱ��ĵȴ�
//                 usleep(1000);
//             }
//             keyparameter keypara = dequeue(spipair->encQueue); // ��ȷ����Կ������һ�����й���
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
//         { // ��km������Կ����Կ��������
//             if (spipair->socket_fd == -1)
//             {
//                 // ����������ʧ�ܵ����
//                 perror("establish_connection error!\n");
//                 return false;
//             }
//             // ����ǵ�һ�����ݰ���������ԿԤȡ�߳�
//             if (next_seqno == 1)
//             {
//                 spipair->key_lenth = keysize;
//                 pthread_t thread_deckey;
//                 // �������߳�
//                 if (pthread_create(&thread_deckey, NULL, thread_deckey_preaccess, (void *)spipair) != 0)
//                 {
//                     perror("pthread_create");
//                     return false;
//                 }
//                 // �̷߳���
//                 if (pthread_detach(thread_deckey) != 0)
//                 {
//                     perror("pthread_detach");
//                     return false;
//                 }
//             }
//             while (is_empty(spipair->decQueue))
//             { // ���ж϶����Ƿ�Ϊ�գ�����ǿգ�˵��������δ������У�����һ��ʱ��ĵȴ�
//                 usleep(1000);
//             }
//             keyparameter keypara = dequeue(spipair->decQueue); // ��ȷ����Կ������һ�����й���
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

/** ����ԿԤ��ȡ
 * @description: ��ȡ������Կ,ͨ��spi�����кŻ�ȡ��Ӧ����Կ
 * @param {uint32_t} spi spi
 * @param {uint32_t} next_seqno ���к�
 * @param {bool} key_type TRUE��ʾ���ܣ�FALSE��ʾ����
 * @param {chunk_t} *qk ������Կ�洢
 * @param {size_t} keysize ��Կ����
 * @return {*} TRUE if ��ȡ�ɹ�
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
 * @description: ����������Կ,ͨ��spi��ԭʼ��Կ����
 * @param {unsigned char*} key ԭʼ��Կ
 * @param {int} next_seqno ���к�
 * @param {int} keysize ��Կ����
 * @return {*} TRUE if ��ȡ�ɹ�
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
 *��ȡ����OTP��Կ
 *
 * ͨ��spi�����кŻ�ȡ��Ӧ����Կ
 *
 *
 *
 * @param spi			spi
 * @param next_seqno	���к�
 * @param key_type		TRUE��ʾ���ܣ�FALSE��ʾ����
 * @param qk			������Կ�洢
 * @param keysize		��Կ����
 * @return				TRUE if ��ȡ�ɹ�
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
		// ����������ʧ�ܵ����
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