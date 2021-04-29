// Client side implementation of UDP client-server model
#pragma comment(lib, "Ws2_32.lib")
#pragma warning(disable:4996) 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "Ws2tcpip.h"
#include <sys/types.h>
#include "winsock2.h"
#include <stdbool.h>
#include <ctype.h>

#define T_A 1 			/*Ipv4 address*/
#define T_NS 2 			/*Nameserver*/
#define T_CNAME 5 		/*canonical name*/
#define T_SOA 6 		/*start of authority zone */
#define T_PTR 12 		/*domain name pointer */
#define T_MX 15 		/*Mail server*/
#define PORT 53
#define MAXLINE 1024


struct DNS_HEADER
{
    unsigned short id; // identification number

    unsigned char rd : 1; // recursion desired
    unsigned char tc : 1; // truncated message
    unsigned char aa : 1; // authoritive answer
    unsigned char opcode : 4; // purpose of message
    unsigned char qr : 1; // query/response flag

    unsigned char rcode : 4; // response code
    unsigned char z : 3; // its z! reserved
    unsigned char ra : 1; // recursion available

    unsigned short qdcount; // number of question entries
    unsigned short ancount; // number of answer entries
    unsigned short nscount; // number of authority entries
    unsigned short arcount; // number of resource entrie
};

struct QUESTION {
    unsigned short qtype;
    unsigned short qclass;
};


#pragma pack(push, 1)
struct R_DATA {
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
};
#pragma pack(pop)


struct RES_RECORD {
    unsigned char* name;
    struct R_DATA* resource;
    unsigned char* rdata;
};

typedef struct {
    unsigned char* name;
    struct QUESTION* ques;
} QUERY;


struct sockaddr_in servaddr;
int sockfd, counter_id = 0;

void removeDotsFromName(unsigned char* dns, unsigned char* host)
{
    int lock = 0, i;
    int initLen = strlen(host);
    *(host + initLen) = '.';
    *(host + initLen + 1) = '\0';
    for (i = 0; i < strlen((char*)host); i++)
    {
        if (host[i] == '.')
        {
            *dns++ = i - lock;		/*replace the dot with the number of characters after it before the next dot*/
            for (; lock < i; lock++)
                *dns++ = host[lock];
            lock++;
        }
    }
    *dns++ = '\0';
}
u_char* ReadName(unsigned char* ptrInQuery, unsigned char* queryfer, int* count)
{
    unsigned char* name;
    unsigned int p = 0, jumped = 0, offset;
    int i, j;

    *count = 1;
    name = (unsigned char*)malloc(256);		/*maximum allowed length is 256*/

    name[0] = '\0';

    while (*ptrInQuery != 0)
    {
        if (*ptrInQuery >= 192)
        {
            offset = (*ptrInQuery) * 256 + *(ptrInQuery + 1) - 49152;
            ptrInQuery = queryfer + offset - 1;
            jumped = 1;
        }
        else
            name[p++] = *ptrInQuery;
        ptrInQuery = ptrInQuery + 1;
        if (jumped == 0)
            *count = *count + 1;
    }

    name[p] = '\0';
    if (jumped == 1)
        *count = *count + 1;

    for (i = 0; i < (int)strlen((const char*)name); i++)
    {
        p = name[i];
        for (j = 0; j < (int)p; j++)
        {
            name[i] = name[i + 1];
            i = i + 1;
        }
        name[i] = '.';
    }
    name[i - 1] = '\0';
    return name;
}
bool dnsQuerySend(unsigned char* hostname) {
    /// <summary>
    /// 
    /// </summary>
    /// <param name="hostname"></param>
    /// <returns></returns>
    /// 
    unsigned char query[65536], * qname, * ptrInQuery;
    DWORD timeout = 2 * 1000;
    struct DNS_HEADER* dns = NULL;
    struct QUESTION* qinfo = NULL;

    // sockfd is a Golbal variable
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));	/*set timeout on this socket*/

    dns = (struct DNS_HEADER*)&query;			/*DNS HEADER*/
    dns->id = (unsigned short)htons(counter_id++);
    dns->qr = 0;
    dns->opcode = 0; 				/*standard query*/
    dns->aa = 0;
    dns->tc = 0;
    dns->rd = 0; 					/*recursion desired*/
    dns->ra = 0;
    dns->z = 0;
    dns->rcode = 0;
    dns->qdcount = htons(1);
    dns->ancount = 0;
    dns->nscount = 0;
    dns->arcount = 0;
    qname = (unsigned char*)&query[sizeof(struct DNS_HEADER)];					     /*DNS QUESTION NAME.ANY JUNK VALUE WILL DO*/
    
    removeDotsFromName(qname, hostname);
    qinfo = (struct QUESTION*)&query[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)]; /*DNS QUESTION TYPE AND CLASS*/

    qinfo->qtype = htons(1);
    qinfo->qclass = htons(1);
    int len_of_packet = sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1) + sizeof(struct QUESTION);
    //printf("\nSending Packet to %s\n", argv[1]);
    if (sendto(sockfd, (char*)query, len_of_packet, 0, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
        printf("sendto() has failed.\n");
        return FALSE;
    }
    else {
        return TRUE;
    }
}

struct hostent* dnsQueryRecieve() {
    struct hostent hoststruct;
    unsigned char query[65536], * qname, * ptrInQuery;
    struct sockaddr_in a;
    int i, j, stop, s;
    DWORD timeout = 2 * 1000;
    struct DNS_HEADER* dns = NULL;
    struct QUESTION* qinfo = NULL;
    struct RES_RECORD answersRecords[50], authRecords[50], additionalRecords[50];

    // sockfd is a Golbal variable
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));	/*set timeout on this socket*/

    int len_of_serveradd = sizeof(servaddr);
    if (recvfrom(sockfd, (char*)query, 65536, 0, (struct sockaddr*)&servaddr, (socklen_t*)&len_of_serveradd) < 0)
    {
        perror("recvfrom failed");
        //return; 
    }
    dns = (struct DNS_HEADER*)query;// MIGHT NEED &query
    if (dns->rcode == 0) {
        qname = (unsigned char*)&query[sizeof(struct DNS_HEADER)];
        ptrInQuery = &query[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1) + sizeof(struct QUESTION)];	/*THE RESPONSE*/
        stop = 0;

        for (i = 0; i < ntohs(dns->ancount); i++)
        {
            answersRecords[i].name = ReadName(ptrInQuery, query, &stop);
            ptrInQuery = ptrInQuery + stop;

            answersRecords[i].resource = (struct R_DATA*)(ptrInQuery);
            ptrInQuery = ptrInQuery + sizeof(struct R_DATA);

            if (ntohs(answersRecords[i].resource->type) == 1) 	/*read address*/
            {
                answersRecords[i].rdata = (unsigned char*)malloc(ntohs(answersRecords[i].resource->data_len));

                for (j = 0; j < ntohs(answersRecords[i].resource->data_len); j++)
                    answersRecords[i].rdata[j] = ptrInQuery[j];

                answersRecords[i].rdata[ntohs(answersRecords[i].resource->data_len)] = '\0';
                long* p;
                p = (long*)answersRecords[i].rdata;
                a.sin_addr.s_addr = (*p);
                char* finalAdress = inet_ntoa(a.sin_addr);
                hoststruct.h_name = finalAdress;
                printf("%s\n", finalAdress);
                return &hoststruct;

                ptrInQuery = ptrInQuery + ntohs(answersRecords[i].resource->data_len);
            }
            else						/*read name*/
            {
                answersRecords[i].rdata = ReadName(ptrInQuery, query, &stop);
                ptrInQuery = ptrInQuery + stop;
            }
        }

        //read authRecordsorities
        for (i = 0; i < ntohs(dns->nscount); i++)
        {
            authRecords[i].name = ReadName(ptrInQuery, query, &stop);
            ptrInQuery += stop;

            authRecords[i].resource = (struct R_DATA*)(ptrInQuery);
            ptrInQuery += sizeof(struct R_DATA);

            if (ntohs(authRecords[i].resource->type) == 1)		/*read address*/
            {
                authRecords[i].rdata = (unsigned char*)malloc(ntohs(authRecords[i].resource->data_len));
                for (j = 0; j < ntohs(authRecords[i].resource->data_len); j++)
                    authRecords[i].rdata[j] = ptrInQuery[j];

                authRecords[i].rdata[ntohs(authRecords[i].resource->data_len)] = '\0';
                long* p;
                p = (long*)authRecords[i].rdata;
                a.sin_addr.s_addr = (*p);
                char* finalAdress = inet_ntoa(a.sin_addr);
                hoststruct.h_name = finalAdress;
                printf("%s\n", finalAdress);
                return &hoststruct;
                ptrInQuery += ntohs(authRecords[i].resource->data_len);
            }
            else						/*read name*/
            {
                authRecords[i].rdata = ReadName(ptrInQuery, query, &stop);
                ptrInQuery += stop;
            }

        }

        //read additional
        for (i = 0; i < ntohs(dns->arcount); i++)
        {
            additionalRecords[i].name = ReadName(ptrInQuery, query, &stop);
            ptrInQuery += stop;

            additionalRecords[i].resource = (struct R_DATA*)(ptrInQuery);
            ptrInQuery += sizeof(struct R_DATA);

            if (ntohs(additionalRecords[i].resource->type) == 1)				/*read address*/
            {
                additionalRecords[i].rdata = (unsigned char*)malloc(ntohs(additionalRecords[i].resource->data_len));
                for (j = 0; j < ntohs(additionalRecords[i].resource->data_len); j++)
                    additionalRecords[i].rdata[j] = ptrInQuery[j];

                additionalRecords[i].rdata[ntohs(additionalRecords[i].resource->data_len)] = '\0';
                long* p;
                p = (long*)additionalRecords[i].rdata;
                a.sin_addr.s_addr = (*p);
                char *finalAdress = inet_ntoa(a.sin_addr);
                hoststruct.h_name = finalAdress;
                printf("%s\n", finalAdress);
                return &hoststruct;
                ptrInQuery += ntohs(additionalRecords[i].resource->data_len);
            }
            else								/*read name*/
            {
                additionalRecords[i].rdata = ReadName(ptrInQuery, query, &stop);
                ptrInQuery += stop;
            }
        }
    }
        else {
            printf("ERROR: NONEXISTENT\n");
        }
}

static struct hostent* findAddress(unsigned char *hostname) {
    struct hostent* result;
    bool sendResult;
    sendResult = dnsQuerySend(hostname);
    if (sendResult) {
        result = dnsQueryRecieve();
        return result;
    } 
    else {
        perror("dnsQuerySend function has failed to send the packet");
    }
}

bool isValidHostname(char *ptr) {
    /*
      Could be replaced easly with regular expression, but this isnt working well in c.
      isValidHostname : char *ptr  which is a pointer to string (message) , that contains an hostname
      output - Boolean True/False that determine if the string is a valid HostName pattern 
      validation Rules:
            - Each element of the hostname must be from 1 to 63 characters long
            - the total length of the hostname must not exceed 255 characters
            - cannot start with '.'/'-/ , a contains only chars and digits and hypen (-).
            - If the input name ends with a trailing dot, the trailing dot is
              removed, and the remaining name is looked up with no further processing.
    */

    // checking if the first charcter is invalid
    if (isalpha(*(ptr)) == 0 && isdigit(*(ptr)) == 0) {
        return FALSE;
    }
    //printf("%c is alpha\n", *(ptr));

    int i;
    int generalCounter = 1;
    int currentCounter = 1;

    for (i = 1; i < strlen(ptr); i++) {
        generalCounter++;
        // check for alphabets
        if (isalpha(*(ptr + i)) != 0 || isdigit(*(ptr + i)) != 0 || *(ptr + i) == '-') {
            //printf("%c is alpha\n", *(ptr + i));
            currentCounter++;
        }
        // check for dots
        else if (*(ptr + i) == '.') {
            if (currentCounter == 0) {
                while (*(ptr + i) != '\0') {
                    if (*(ptr + i) != '.') {
                        return FALSE;
                    }
                    i++;
                }
                if (generalCounter < 256) {
                    return TRUE;
                }
                else {
                    return FALSE;
                }
            }
            else {
                currentCounter = 0;
            }
        }
    }
    if (generalCounter < 256) {
        return TRUE;
    }
    else {
        return FALSE;
    }
}


int main(int argc, char* argv[]) {
    struct hostent* result;
    //Checking if the user didnt put an valid input size
    if (argc < 2) {
        fprintf(stderr, "ERROR, no port provided\n");
        exit(0);
    }

    // initialize windows networking
    WSADATA wsaData;
    int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != NO_ERROR)
        printf("Error at WSAStartup()\n");
  

    // Creating socket file descriptor
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }
    memset(&servaddr, 0, sizeof(servaddr));

    // Filling server information
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(53);
    //InetPton(AF_INET, (PCWSTR)argv[1], &servaddr.sin_addr.s_addr);
    servaddr.sin_addr.s_addr = inet_addr((char *)argv[1]);
    char message[256];
    printf("nsclient> ");
    scanf_s("%s", message, (unsigned)_countof(message));
    while (strcmp(message, "quit") != 0) {
        bool valid = isValidHostname(message);
        if (valid == TRUE) {
            result = findAddress(message);
            memset(&message, '\0', strlen(message));
        }
        else {
            printf("ERROR : BAD NAME\n");
            memset(&message, '\0', strlen(message));
        }
        printf("nsclient> ");
        scanf_s("%s", message, (unsigned)_countof(message));
        //checking if message is valid
    }
    exit(0);
}

