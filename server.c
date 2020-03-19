#include<stdio.h> //For standard things
#include<stdlib.h>    //malloc
#include<string.h>    //memset
#include<netinet/ip_icmp.h>   //Provides declarations for icmp header
#include<netinet/udp.h>   //Provides declarations for udp header
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ip header
#include<sys/socket.h>
#include<arpa/inet.h>
 #include <unistd.h>
#include<string.h>

void ProcessPacket(unsigned char* , int);
void print_ip_header(unsigned char* , int);
void print_tcp_packet(unsigned char* , int);
void print_udp_packet(unsigned char * , int);
void PrintData (unsigned char* , int);
 
int sock_raw;
FILE *logfile;
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j;
struct sockaddr_in source,dest;
 

int socket_create()
{
    int tcp_socket=socket(PF_INET,SOCK_RAW,IPPROTO_TCP);
    if(tcp_socket<0)
    {
        perror("Error in TCP creating socket......");
        exit(-1);
        return(-1);
    }
    else
    {
        printf("Raw TCP Socket created...%d.......\n",tcp_socket);
        return(tcp_socket);
    }
    
}

int check_packet(unsigned char* Buffer,char *ip)
{
    struct iphdr *iph = (struct iphdr *)Buffer; 
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
    char *str;
    int len=strlen(ip);
    str=calloc(len+1,sizeof(char));
    
    inet_ntop(AF_INET, &(source.sin_addr), str, INET_ADDRSTRLEN);
    printf("%s %s\n",ip,str);
    if(strcmp(str,ip)==0)
    {
        return(1);
    }else{
        return(0);
    }
}


int main(int argc,char *argv[])
{
    int saddr_size , data_size;
    struct sockaddr saddr;
    struct in_addr in;
    if(argc<3)
    {
        perror("argc error :");
        exit(-1);
    }
    char *ip;
    int len=strlen(argv[1]);
    ip=calloc(len+1,sizeof(char));
    strcpy(ip,argv[1]);
    int port=atoi(argv[2]);
    unsigned char *buffer = (unsigned char *)malloc(65536); //Its Big!
    logfile=fopen("log.txt","w");
    if(logfile==NULL) printf("Unable to create file.");
    printf("Starting...\n");
    //Create a raw socket that shall sniff
    sock_raw = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);
    if(sock_raw < 0)
    {
        printf("Socket Error\n");
        return 1;
    }
    while(1)
    {
        saddr_size = sizeof saddr;
        //Receive a packet
        data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , &saddr_size);
        if(data_size <0 )
        {
            printf("Recvfrom error , failed to get packets\n");
            return 1;
        }
        //Now process the packet
        if(check_packet(buffer,ip)){
        ProcessPacket(buffer , data_size);
        }
    }
    close(sock_raw);
    printf("Finished");
    return 0;
}
 
void ProcessPacket(unsigned char* buffer, int size)
{
    //Get the IP Header part of this packet
    struct iphdr *iph = (struct iphdr*)buffer;
    ++total;
    switch (iph->protocol) //Check the Protocol and do accordingly...
    {
        case 6:  //TCP Protocol
            ++tcp;
            print_tcp_packet(buffer , size);
            break;
         
        case 17: //UDP Protocol
            ++udp;
            print_udp_packet(buffer , size);
            break;
         
        default: //Some Other Protocol like ARP etc.
            ++others;
            break;
    }
    printf("TCP : %d   UDP : %d   Others : %d   Total : %d\r",tcp,udp,others,total);
}
