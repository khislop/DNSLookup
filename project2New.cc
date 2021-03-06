// DNS Query Syststem
// Kelton Hislop

#include "includes.h"
#define NSERVER 9316


#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<string.h>
#include<arpa/inet.h>
#include<string.h>
#include<arpa/inet.h>
#include<stdio.h>
#define MAXLINE 1024


// Struct for DNS header. flags are in reverse order per byte for endian conversion. 
struct DNS_HEADER
{
    unsigned short id; // identification number
 
    unsigned char rd :1; // recursion desired
    unsigned char tc :1; // truncated message
    unsigned char aa :1; // authoritive answer
    unsigned char opcode :4; // purpose of message
    unsigned char qr :1; // query/response flag
 
    unsigned char rcode :4; // response code
    unsigned char cd :1; // checking disabled
    unsigned char ad :1; // authenticated data
    unsigned char z :1; // its z! reserved
    unsigned char ra :1; // recursion available
 
    unsigned short q_count; // number of question entries
    unsigned short ans_count; // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count; // number of resource entries
};

//Constant sized fields of query structure
struct QUESTION
{
    unsigned short qtype;
    unsigned short qclass;
};

//Pointers to resource record contents
struct RES_RECORD
{
    unsigned char *name;
    struct R_DATA *resource;
    unsigned char *rdata;
};

//Constant sized fields of the resource record structure
#pragma pack(push, 1)
struct R_DATA
{
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
};
#pragma pack(pop)
 
// This function was borowed from http://www.binarytides.com/dns-query-code-in-c-with-winsock/
void ChangetoDnsNameFormat(unsigned char* dns,unsigned char* host) 
{
    int lock = 0 , i;
    strcat((char*)host,".");
     
    for(i = 0 ; i < strlen((char*)host) ; i++) 
    {
        if(host[i]=='.') 
        {
            *dns++ = i-lock;
            for(;lock<i;lock++) 
            {
                *dns++=host[lock];
            }
            lock++; //or lock=i+1;
        }
    }
    *dns++='\0';
}

u_char* ReadName(unsigned char* reader,unsigned char* buffer,int* count)
{
    unsigned char *name;
    unsigned int p=0,jumped=0,offset;
    int i , j;
 
    *count = 1;
    name = (unsigned char*)malloc(256);
 
    name[0]='\0';
 
    //read the names in 3www6google3com format
    while(*reader!=0)
    {
        if(*reader>=192)
        {
            offset = (*reader)*256 + *(reader+1) - 49152; //49152 = 11000000 00000000 ;)
            reader = buffer + offset - 1;
            jumped = 1; //we have jumped to another location so counting wont go up!
        }
        else
        {
            name[p++]=*reader;
        }
 
        reader = reader+1;
 
        if(jumped==0)
        {
            *count = *count + 1; //if we havent jumped to another location then we can count up
        }
    }
 
    name[p]='\0'; //string complete
    if(jumped==1)
    {
        *count = *count + 1; //number of steps we actually moved forward in the packet
    }
 
    //now convert 3www6google3com0 to www.google.com
    for(i=0;i<(int)strlen((const char*)name);i++) 
    {
        p=name[i];
        for(j=0;j<(int)p;j++) 
        {
            name[i]=name[i+1];
            i=i+1;
        }
        name[i]='.';
    }
    name[i-1]='\0'; //remove the last dot
    return name;
}

void queryServer(){
    int test;

    int sockfd;	// Socketfd
    int n;	
    socklen_t len;
    char sendline[1024],recvline[1024]; // Buffers for sending and receiving
    struct sockaddr_in servaddr;  //Server addresshort
    strcpy(sendline,"");  //Put an empty tring into sendline
    printf("\n Enter the message : ");  //prompt user for mesage
    scanf("%s",sendline);  //Receive user input
    sockfd=socket(AF_INET,SOCK_DGRAM,0);  //Initialize the socketfd
    bzero(&servaddr,sizeof(servaddr));  //Zero the server address
    servaddr.sin_family=AF_INET;  //Specify and internet address
    //servaddr.sin_addr.s_addr=inet_addr("127.0.0.1");  //Set the address
    //servaddr.sin_port=htons(5035);  //Set the port
    servaddr.sin_addr.s_addr=inet_addr("138.67.1.2");  //Set the address
    servaddr.sin_port=htons(53);  //Set the port
    connect(sockfd,(struct sockaddr*)&servaddr,sizeof(servaddr));  //Connect to the server
    len=sizeof(servaddr);  //get size of server address
    test = sendto(sockfd,sendline,MAXLINE,0,(struct sockaddr*)&servaddr,len);  //Send sendline through socket
    printf("Send Result: %i\n", test);
    n=recvfrom(sockfd,recvline,MAXLINE,0,NULL,NULL);  //receive a response
    recvline[n]=0;  //set the end of the received data
    printf("Return Result: %i\n", n);
    printf("\n Server's Echo : %s\n\n",recvline);  //print received data
    
    

}

void queryServerQuestion(unsigned char *host)
{
    unsigned char buf[65536],*qname,*reader;
    int i , j , stop , s, n;
    int bufsize = 65536;
 
    struct sockaddr_in a;
 
    struct RES_RECORD answers[20],auth[20],addit[20]; //the replies from the DNS server
    struct sockaddr_in dest;
 
    struct DNS_HEADER *header = NULL;
    struct QUESTION *question = NULL;
 
    printf("Resolving %s" , host);
 
      s=socket(AF_INET,SOCK_DGRAM,0);  //Initialize the socketfd
    bzero(&dest,sizeof(dest));  //Zero the server address
    dest.sin_family=AF_INET;  //Specify and internet address
    //dest.sin_addr.s_addr=inet_addr("127.0.0.1");  //localhost
    //dest.sin_port=htons(5035);  //Set the port
    dest.sin_addr.s_addr=inet_addr("138.67.1.2");  //Mines
    //dest.sin_addr.s_addr=inet_addr("198.41.0.4");  //root a
    dest.sin_port=htons(53);  //Set the port
    //connect(s,(struct sockaddr*)&dest,sizeof(dest));  //Connect to the server
    
    
    //Set the DNS structure to standard queries
    header = (struct DNS_HEADER *)&buf;
 
    header->id = (unsigned short) htons(getpid());
    header->qr = 0; //This is a query
    header->opcode = 0; //This is a standard query
    header->aa = 0; //Not Authoritative
    header->tc = 0; //This message is not truncated
    header->rd = 1; //Recursion Desired
    header->ra = 0; //Recursion not available
    header->z = 0;
    header->ad = 0;
    header->cd = 0;
    header->rcode = 0;
    header->q_count = htons(1); //we have only 1 question
    header->ans_count = 0;
    header->auth_count = 0;
    header->add_count = 0;
    
    
    
    //point past the header
    qname = &buf[12];
 
    ChangetoDnsNameFormat(qname , host);
    question = (struct QUESTION*)&buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)]; //fill it
    
    question->qtype = htons(1); 
    question->qclass = htons(1); 
    
    printf("\nSending Packet...");
    if( sendto(s,(char*)buf,sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION),0,(struct sockaddr*)&dest,sizeof(dest)) < 0)
    {
        perror("sendto failed\n");
    }
    printf("Done\n");
    

    n=recvfrom(s,buf,bufsize,0,NULL,NULL);  //receive a response
    buf[n] = 0;  //set the end of the received data
    printf("Return Result: %i\n", n);
    if(n < 1){
        printf("No response from this server.");
        return;
    }
    printf("\n Server's Echo : %s\n\n",buf);  //print received data
    
    
    ///////////////////////////////////////////////////////////////////////////
    header = (struct DNS_HEADER*) buf;
    
    reader = &buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION)];
    
    if(ntohs(header->ans_count) < 1){
        printf("No available answer from this server.\n\n");
        return;
    }
    
 
    printf("\nThe response contains : ");
    printf("\n %d Questions.",ntohs(header->q_count));
    printf("\n %d Answers.",ntohs(header->ans_count));
    printf("\n %d Authoritative Servers.",ntohs(header->auth_count));
    printf("\n %d Additional records.\n\n",ntohs(header->add_count));
 
    //Start reading answers
    stop=0;
 
    for(i=0;i<ntohs(header->ans_count);i++)
    {
        answers[i].name=ReadName(reader,buf,&stop);
        reader = reader + stop;
 
        answers[i].resource = (struct R_DATA*)(reader);
        reader = reader + sizeof(struct R_DATA);
 
        if(ntohs(answers[i].resource->type) == 1) //if its an ipv4 address
        {
            answers[i].rdata = (unsigned char*)malloc(ntohs(answers[i].resource->data_len));
 
            for(j=0 ; j<ntohs(answers[i].resource->data_len) ; j++)
            {
                answers[i].rdata[j]=reader[j];
            }
 
            answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';
 
            reader = reader + ntohs(answers[i].resource->data_len);
        }
        else
        {
            answers[i].rdata = ReadName(reader,buf,&stop);
            reader = reader + stop;
        }
    }
 
    //read authorities
    for(i=0;i<ntohs(header->auth_count);i++)
    {
        auth[i].name=ReadName(reader,buf,&stop);
        reader+=stop;
 
        auth[i].resource=(struct R_DATA*)(reader);
        reader+=sizeof(struct R_DATA);
 
        auth[i].rdata=ReadName(reader,buf,&stop);
        reader+=stop;
    }
 
    //read additional
    for(i=0;i<ntohs(header->add_count);i++)
    {typedef struct
{
    unsigned char *name;
    struct QUESTION *ques;
} QUERY;
        addit[i].name=ReadName(reader,buf,&stop);
        reader+=stop;
 
        addit[i].resource=(struct R_DATA*)(reader);
        reader+=sizeof(struct R_DATA);
 
        if(ntohs(addit[i].resource->type)==1)
        {
            addit[i].rdata = (unsigned char*)malloc(ntohs(addit[i].resource->data_len));
            for(j=0;j<ntohs(addit[i].resource->data_len);j++)
            addit[i].rdata[j]=reader[j];
 
            addit[i].rdata[ntohs(addit[i].resource->data_len)]='\0';
            reader+=ntohs(addit[i].resource->data_len);
        }
        else
        {
            addit[i].rdata=ReadName(reader,buf,&stop);
            reader+=stop;
        }
    }
 
    //print answers
    printf("\nAnswer Records : %d \n" , ntohs(header->ans_count) );
    for(i=0 ; i < ntohs(header->ans_count) ; i++)
    {
        printf("Name : %s ",answers[i].name);
 
        if( ntohs(answers[i].resource->type) == 1) //IPv4 address
        {
            long *p;
            p=(long*)answers[i].rdata;
            a.sin_addr.s_addr=(*p); //working without ntohl
            printf("has IPv4 address : %s",inet_ntoa(a.sin_addr));
        }
         
        if(ntohs(answers[i].resource->type)==5) 
        {
            //Canonical name for an alias
            printf("has alias name : %s",answers[i].rdata);
        }
 
        printf("\n");
    }
 
    //print authorities
    printf("\nAuthoritive Records : %d \n" , ntohs(header->auth_count) );
    for( i=0 ; i < ntohs(header->auth_count) ; i++)
    {
         
        printf("Name : %s ",auth[i].name);
        if(ntohs(auth[i].resource->type)==2)
        {
            printf("has nameserver : %s",auth[i].rdata);
        }
        printf("\n");
    }
 
    //print additional resource records
    printf("\nAdditional Records : %d \n" , ntohs(header->add_count) );
    for(i=0; i < ntohs(header->add_count) ; i++)
    {
        printf("Name : %s ",addit[i].name);
        if(ntohs(addit[i].resource->type)==1)
        {
            long *p;
            p=(long*)addit[i].rdata;
            a.sin_addr.s_addr=(*p);
            printf("has IPv4 address : %s",inet_ntoa(a.sin_addr));
        }
        printf("\n");
    }
    return;
}

// ***************************************************************************
// * Main
// ***************************************************************************
/*int main(int argc, char **argv) {

    unsigned char address[50];
    //address = (char*)malloc(sizeof("test"));
    //address = (unsigned char)malloc(50);
    strcpy(address, "www.mines.edu");

    queryServerQuestion(address);

    return 0;
    
}*/

int main( int argc , char *argv[])
{
    unsigned char hostname[100];
 
     
    //Get the hostname from the terminal
    printf("Enter Hostname to Lookup : ");
    scanf("%s" , hostname);
     
    //Now get the ip of this hostname , A record
    queryServerQuestion(hostname);
 
    return 0;
}


