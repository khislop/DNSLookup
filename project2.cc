// DNS Query Syststem
// Kelton Hislop

#include "includes.h"
#define MAXLINE 1024

int debug = 0;




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
            lock++;
        }
    }
    *dns++='\0';
}

void parseArg(char *arg){
    if (arg[1] == 'd'){
        debug = 1;
    }
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

u_char* ReadName(unsigned char* reader,unsigned char* buffer,int* count){
    unsigned char *name;
    unsigned int p=0,jumped=0,offset;
    int i , j;
 
    *count = 1;
    name = (unsigned char*)malloc(256);
 
    name[0]='\0';
 

    while(*reader!=0)
    {
        if(*reader>=192)
        {
            offset = (*reader)*256 + *(reader+1) - 49152; 
            reader = buffer + offset - 1;
            jumped = 1; 
        }
        else
        {
            name[p++]=*reader;
        }
 
        reader = reader+1;
 
        if(jumped==0)
        {
            *count = *count + 1;
        }
    }
 
    name[p]='\0'; 
    if(jumped==1)
    {
        *count = *count + 1; 
    }
 
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
    name[i-1]='\0'; 
    return name;
}



u_char* queryServerQuestion(unsigned char *host, char *nameserver)
{
    int bufsize = 65536;
    unsigned char buf[bufsize],*qname,*reader,authbuf[bufsize];
    int i , j , stop , s, n;
    int noans = 0;
 
    struct sockaddr_in a;
 
    struct RES_RECORD answers[20],auth[20],addit[20]; //the replies from the DNS server
    struct sockaddr_in dest;
 
    struct DNS_HEADER *header = NULL;
    struct QUESTION *question = NULL;
    
    //printf("NS Adress: %s\n\n", nameserver);
    //strcpy(nameserver, "138.67.1.2");
    //printf("NS Adress: %s\n\n", nameserver);
 
    s=socket(AF_INET,SOCK_DGRAM,0);  //Initialize the socketfd
    bzero(&dest,sizeof(dest));  //Zero the server address
    dest.sin_family=AF_INET;  //Specify and internet address
    //dest.sin_addr.s_addr=inet_addr("127.0.0.1");  //localhost
    //dest.sin_port=htons(5035);  //Set the port
    //dest.sin_addr.s_addr=inet_addr("138.67.1.2");  //Mines
    dest.sin_addr.s_addr=inet_addr(nameserver);  //Set the address
    //dest.sin_addr.s_addr=inet_addr("198.41.0.4");  //root a
    dest.sin_port=htons(53);  //Set the port
    
    
    
    //Set the DNS structure to standard queries
    header = (struct DNS_HEADER *)&buf;
 
    header->id = (unsigned short) htons(getpid());
    header->qr = 0; 
    header->opcode = 0; 
    header->aa = 0; 
    header->tc = 0; 
    header->rd = 0; 
    header->ra = 0; 
    header->z = 0;
    header->ad = 0;
    header->cd = 0;
    header->rcode = 0;
    header->q_count = htons(1);
    header->ans_count = 0;
    header->auth_count = 0;
    header->add_count = 0;
    
    
    
    //point past the header
    qname = &buf[12];
 
    ChangetoDnsNameFormat(qname , host);
    question = (struct QUESTION*)&buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)];
    
    question->qtype = htons(1); 
    question->qclass = htons(1); 
    
    if( sendto(s,(char*)buf,sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION),0,(struct sockaddr*)&dest,sizeof(dest)) < 0)
    {
        perror("Sending failed");
        return host;
    }
    

    n=recvfrom(s,buf,bufsize,0,NULL,NULL);  //receive a response
    buf[n] = 0;  
    //printf("Return Result: %i\n", n);
    if(n < 1){
        printf("No response from this server.");
        return host;
    }
    //printf("\n Server's Echo : %s\n\n",buf);  //print received data
    
    
    ///////////////////////////////////////////////////////////////////////////
    header = (struct DNS_HEADER*) buf;
    
    reader = &buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION)];
    
 
    //Read answers
    stop=0;
 
    for(i=0;i<ntohs(header->ans_count);i++)
    {
        answers[i].name=ReadName(reader,buf,&stop);
        reader = reader + stop;
 
        answers[i].resource = (struct R_DATA*)(reader);
        reader = reader + sizeof(struct R_DATA);
 
        if(ntohs(answers[i].resource->type) == 1)
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
    
    //Read authorities
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
    {
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
 
        }else
        {
            addit[i].rdata=ReadName(reader,buf,&stop);
            reader+=stop;
        }
    }
 
    // Print the output to console
    if(ntohs(header->ans_count) > 0){

        for(i=0 ; i < ntohs(header->ans_count) ; i++)
        {
            
     
            if( ntohs(answers[i].resource->type) == 1)
            {
                long *p;
                p=(long*)answers[i].rdata;
                a.sin_addr.s_addr=(*p);
                if(header->aa){
                    printf("Authoritative answer: ");
                }else{
                    printf("Non-authoritative answer: ");
                }
                printf("%s\n\n", inet_ntoa(a.sin_addr));
            }
        }
        return host;
        
    }else if(ntohs(header->add_count) > 0 && !noans){
        //printf("\nNeed recursion.\n\n");
        
        long *p;
        p=(long*)addit[0].rdata;
        a.sin_addr.s_addr=(*p);
        
        if(debug){
            printf("No answer, checking with %s\n\n", inet_ntoa(a.sin_addr));
        }
        
        queryServerQuestion(host, inet_ntoa(a.sin_addr));
        
        
    }else{
        printf("No available answer from this server.\n\n");
        return host;
    }

 


//root - 198.41.0.4
//mines - 138.67.1.2

    return host;
}

// ***************************************************************************
// * Main
// ***************************************************************************

int main( int argc , char *argv[])
{
    unsigned char hostname[1024];
    bzero(hostname, 1024);
    
    //Check for enough arguments
    if(argc < 3){
        printf("ERROR: Must give two arguments for address and nameserver.\n");
        return 1;
    }
    
    if(argc > 3){
        parseArg(argv[3]);
    }
    
    
    //printf("Argument: %s\n", argv[1]);
    //printf("Argument size: %lu\n", strlen(argv[1]));
    memcpy(hostname, argv[1], strlen(argv[1]));
    //printf("Argument copy: %s\n", hostname);

    queryServerQuestion(hostname, argv[2]);
 
    return 0;
}


