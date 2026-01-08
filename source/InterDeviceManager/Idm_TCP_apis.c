/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2022 Sky
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <net/if.h>
#include <sys/ioctl.h>
#include "Idm_TCP_apis.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#ifdef ENABLE_HW_CERT_USAGE
#include "rdkconfig.h"
#endif
#include "Idm_data.h"
#include "secure_wrapper.h"
#define MAX_TCP_CLIENTS 30
#define SSL_CERTIFICATE "/tmp/idm_xpki_cert"
#define SSL_KEY         "/tmp/idm_xpki_key"

extern char g_sslCert[SSL_FILE_LEN];
extern char g_sslKey[SSL_FILE_LEN];
extern char g_sslCA[SSL_FILE_LEN];
extern char g_sslCaDir[SSL_FILE_LEN];
#ifdef ENABLE_HW_CERT_USAGE
extern char g_sslSeCert[128];
extern char g_sslPassCodeFile[128];
extern char g_sslSeCA[128];
#endif
bool ssl_lib_init = false;
bool TCP_server_started = false;
bool connect_reset = false;
pthread_mutex_t connect_reset_mutex = PTHREAD_MUTEX_INITIALIZER;
typedef int (*callback_recv)( connection_info_t* conn_info, void *payload);

typedef struct tcp_server_threadargs
{
    callback_recv cb;
    int port;
    char interface[INTF_SIZE];
} TcpServerThreadArgs;

SSL_CTX* init_ctx(void)
{
    SSL_CTX *ctx = NULL;
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(SSLv23_method());
    //SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
    //SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
    return ctx;
}

int load_certificate(SSL_CTX* ctx)
{
#ifdef ENABLE_HW_CERT_USAGE
    EVP_PKEY *pkey = NULL;
    X509 *x509 = NULL;
    uint8_t *pass_phrase = NULL;
    uint32_t pass_size;
    uint32_t len = 0;

    CcspTraceInfo(("(%s:%d) Getting passcode for file %s\n", __FUNCTION__, __LINE__,g_sslPassCodeFile));

    if(rdkconfig_get(&pass_phrase, &pass_size, g_sslPassCodeFile) == RDKCONFIG_FAIL)
    {
        CcspTraceError(("(%s:%d) Error in getting passcode\n", __FUNCTION__, __LINE__));
    }
    else
    {
        len = strcspn(pass_phrase, "\n");
        pass_phrase[len] = '\0';
        CcspTraceInfo(("(%s:%d) Passcode decoded successfully \n", __FUNCTION__, __LINE__));
    }

    if(load_se_cert(g_sslSeCert, pass_phrase, &pkey, &x509))
    {
        if(pass_phrase != NULL)
        {
            CcspTraceInfo(("(%s:%d) Freeing passphrase buffer \n", __FUNCTION__, __LINE__));
            rdkconfig_free(&pass_phrase, pass_size);
        }

        CcspTraceInfo(("(%s:%d) Using SE cert \n", __FUNCTION__, __LINE__));

        if(SSL_CTX_use_certificate(ctx,x509) != 1) 
        {
            CcspTraceError(("(%s:%d) Error in loading certificate\n", __FUNCTION__, __LINE__));
            EVP_PKEY_free(pkey);
            X509_free(x509);
            return -1;
        }

        if(SSL_CTX_use_PrivateKey(ctx, pkey) != 1) 
        {
            CcspTraceError(("(%s:%d) Error in loading private key\n", __FUNCTION__, __LINE__));
            EVP_PKEY_free(pkey);
            X509_free(x509);
            return -1;
        }
    }
    else
    {
        CcspTraceInfo(("(%s:%d)Error in loading SE cert \n", __FUNCTION__, __LINE__));

        if(pass_phrase != NULL)
        {
            CcspTraceInfo(("(%s:%d) Freeing passphrase buffer \n", __FUNCTION__, __LINE__));
            rdkconfig_free(&pass_phrase, pass_size);
        }

        if ( SSL_CTX_use_certificate_file(ctx, g_sslCert, SSL_FILETYPE_PEM) <= 0 )
        {
            CcspTraceError(("(%s:%d) Error in loading certificate\n", __FUNCTION__, __LINE__));
            return -1;
        }

        CcspTraceInfo(("(%s:%d) Using generic SSL Certificate \n", __FUNCTION__, __LINE__));

        if ( SSL_CTX_use_PrivateKey_file(ctx, g_sslKey, SSL_FILETYPE_PEM) <= 0 )
        {
            CcspTraceError(("(%s:%d) Error in loading private key file\n", __FUNCTION__, __LINE__));
            return -1;
        }

    }
#else
    if ( SSL_CTX_use_certificate_file(ctx, g_sslCert, SSL_FILETYPE_PEM) <= 0 )
    {
        CcspTraceError(("(%s:%d) Error in loading generic certificate\n", __FUNCTION__, __LINE__));
        return -1;
    }

    if ( SSL_CTX_use_PrivateKey_file(ctx, g_sslKey, SSL_FILETYPE_PEM) <= 0 )
    {
        CcspTraceError(("(%s:%d) Error in loading private key file\n", __FUNCTION__, __LINE__));
        return -1;
    }

#endif

    if ( !SSL_CTX_check_private_key(ctx) )
    {
        CcspTraceError(("(%s:%d) Error in verifying privat key with certificate file\n", __FUNCTION__, __LINE__));
    }

    CcspTraceInfo(("(%s:%d)Certificate & private key loaded successfully\n", __FUNCTION__, __LINE__));

    return 0;
}

// This function will check if mac_address and ip_address of client is matching
// with discovered list
int verify_client(char *interface, char *ip_address, unsigned int *sock_index)
{
    char mac_address[MAC_ADDR_SIZE] = { 0 };

    if(!ip_address || !interface || !sock_index)
    {
        return -1;
    }

    if(getARPMac(interface, ip_address, mac_address) == -1)
    {
        return -1;
    }

    if(strlen(mac_address) == 0)
    {
        CcspTraceInfo(("%s %d Failed to get ARP MAC address\n", __FUNCTION__, __LINE__));
        return -1;
    }

    PIDM_DML_INFO pidmDmlInfo = IdmMgr_GetConfigData_locked();

    if( pidmDmlInfo == NULL )
    {
        return  -1;
    }

    IDM_REMOTE_DEVICE_LINK_INFO *remoteDevice = pidmDmlInfo->stRemoteInfo.pstDeviceLink;

    while(remoteDevice!=NULL)
    {
        // check if both mac_address and ip_address matches with discovered list
        if(strncasecmp(remoteDevice->stRemoteDeviceInfo.ARPMac, mac_address ,MAC_ADDR_SIZE) == 0)
        {
            CcspTraceInfo(("%s %d Client mac address matches with discovered devices list\n", __FUNCTION__, __LINE__));
            if(strncmp(remoteDevice->stRemoteDeviceInfo.IPv4, ip_address, strlen(remoteDevice->stRemoteDeviceInfo.IPv4) ) == 0)
            {
                CcspTraceInfo(("%s %d Client IP address matches with discovered devices list\n",__FUNCTION__, __LINE__));
                /*xupnp discovery callback will update stRemoteDeviceInfo.Index whenever a new client(MAC) is discovered
                 stRemoteDeviceInfo.Index will be 2 for the first discovered device */
                *sock_index = remoteDevice->stRemoteDeviceInfo.Index - 2;
                IdmMgrDml_GetConfigData_release(pidmDmlInfo);
                return 1;
            }
            //ip does not matching.
            break;
        }
        remoteDevice=remoteDevice->next;
    }

    IdmMgrDml_GetConfigData_release(pidmDmlInfo);

    return 0;
}

void *tcp_server_thread(void *arg)
{
    struct sockaddr_in servaddr;
    int master_sock_fd = -1;
    int rc = 0, sd = 0, i;
    fd_set rset;
    int max_fd = 0;
    int c_fd = 0;
    int client_socket[MAX_TCP_CLIENTS];
    int optval = 1;
    payload_t buffer;
    SSL_CTX *ctx = NULL;
    SSL *ssl[MAX_TCP_CLIENTS] = {NULL};
    int fd = -1;
    struct ifreq ifr;
    char interface[INTF_SIZE];
    TcpServerThreadArgs *ta = arg;
    int port_no = ta->port;
    struct sockaddr_in client;
    int addrlen = sizeof(client);
    unsigned int counter = 0;
    int verify_status = 0;
    unsigned int sock_index = 0;

    callback_recv rcv_cb = ta->cb;
    strncpy_s(interface, sizeof(interface), ta->interface, INTF_SIZE);

    if (( fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        CcspTraceInfo(("%s %d Socket creation failed : %s", __FUNCTION__, __LINE__, strerror(errno)));
        return NULL;
    }

    memset(&ifr, 0x00, sizeof(ifr));
    strncpy(ifr.ifr_name, ta->interface, sizeof(ifr.ifr_name) - 1 );
    ifr.ifr_addr.sa_family = AF_INET;
    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0)
    {
        CcspTraceInfo(("%s %d Failed to get ip %s \n", __FUNCTION__, __LINE__, strerror(errno)));
        close(fd);
        return NULL;
    }
    close(fd);

    CcspTraceInfo(("%s %d -TCP server thread started\n", __FUNCTION__, __LINE__));
    pthread_detach(pthread_self());

    //initialise all client_socket[] to 0 so not checked
    for (i = 0; i < MAX_TCP_CLIENTS; i++)
    {
        client_socket[i] = 0;
    }

    master_sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(master_sock_fd < 0)
    {
        CcspTraceInfo(("\nIDM Server socket open failed\n"));
        rc = EINVAL;
        return NULL;
    }

    if( setsockopt(master_sock_fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval , sizeof(int)) )
    {
        CcspTraceError(("server socket SO_REUSEADDR flag set failed : %s", strerror(errno)));
        close(master_sock_fd);
        return NULL;
    }

#ifndef IDM_DEBUG
    if (!ssl_lib_init) {
        ssl_lib_init = true;
        SSL_library_init();
    }
    if ((ctx = init_ctx()) == NULL) {
        CcspTraceError(("(%s:%d) SSL ctx creation failed!!\n", __FUNCTION__, __LINE__));
        return NULL;
    }
    if (load_certificate(ctx) == -1) {
        CcspTraceError(("(%s:%d) Can't use certificate now!!\n", __FUNCTION__, __LINE__));
        SSL_CTX_free(ctx);
        close(master_sock_fd);
        return NULL;
    }
#endif
    servaddr.sin_family = AF_INET;
    // listen on configured interface IP address only
    servaddr.sin_addr.s_addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
    servaddr.sin_port = htons(port_no);

    rc = bind(master_sock_fd, (struct sockaddr *)&servaddr, sizeof(servaddr));

    if(rc < 0)
    {
        CcspTraceInfo(("\nIDM Server socket bind failed\n"));
#ifndef IDM_DEBUG
        SSL_CTX_free(ctx);
#endif
        close(master_sock_fd);
        return NULL;
    }

    rc = listen(master_sock_fd, MAX_TCP_CLIENTS);

    if(rc < 0)
    {
        CcspTraceInfo(("\nIDM server socket listen failed\n"));
#ifndef IDM_DEBUG
        SSL_CTX_free(ctx);
#endif
        close(master_sock_fd);
        return NULL;
    }
    while(TRUE)
    {
        FD_ZERO(&rset);
        FD_SET(master_sock_fd, &rset);
        max_fd = master_sock_fd;
        //add child sockets to set
        for ( i = 0 ; i < MAX_TCP_CLIENTS ; i++)
        {
            //socket descriptor
            sd = client_socket[i];

            //if valid socket descriptor then add to read list
            if(sd > 0)
                FD_SET( sd , &rset);

            //highest file descriptor number, need it for the select function
            if(sd > max_fd)
                max_fd = sd;
        }

        select( max_fd + 1 , &rset , NULL , NULL , NULL);
        if(FD_ISSET(master_sock_fd, &rset))
        {
            memset((void*)&client, 0, sizeof(client));
            c_fd = accept(master_sock_fd, (struct sockaddr *)&client, &addrlen);
            if(c_fd < 0){
                perror("idm : AF_INET accept failed");
            }
            
            CcspTraceInfo(("%s %d client IP address %s \n", __FUNCTION__, __LINE__, inet_ntoa(client.sin_addr)));
            // Check whether client is present in upnp discovered list
            counter = 0;
            while(1)
            {
                verify_status = verify_client(interface, inet_ntoa(client.sin_addr), &sock_index);
                // exit if it returns errors(-1) or if it returns 1(found the client)
                if(verify_status == 1 || verify_status == -1)
                {
                    break;
                }
                counter++;
                if(counter >= 60)
                {
                    break;
                }
                CcspTraceInfo(("%s %d Waiting to be discoverd by discovery protocol... \n", __FUNCTION__, __LINE__));
                sleep(1);
            };

            if(verify_status != 1)
            {
                CcspTraceInfo(("Failed to find client details. Rejecting client connection\n"));
                close(c_fd);
                continue;
            }

            CcspTraceInfo(("%s %d client mac and ip addresses matched sucessfully\n", __FUNCTION__, __LINE__));
            CcspTraceInfo(("New Client Connected Successfully with socket id  = %d\n", c_fd));
            // instead of searching for vacant position, use the array index derived from Index kept in node
            if(sock_index < MAX_TCP_CLIENTS)
            {
                CcspTraceInfo(("%s %d Using sock_index:%d for sock_id:%d\n", __FUNCTION__, __LINE__, sock_index, c_fd));
                // if previous socket id is there, just close it
                if(client_socket[sock_index] > 0)
                {
                    CcspTraceInfo(("%s %d Closing existing socket ID : %d\n", __FUNCTION__, __LINE__, client_socket[sock_index]));
                    close(client_socket[sock_index]);
                }
                client_socket[sock_index] = c_fd;
                c_fd = 0;
            }
            //No space left to hold the new connection, if you want increase MAX_CLIENTS
            else
            {
                //close(c_fd);
                CcspTraceInfo(("\nNo space left = %d\n", c_fd));
            }
#ifndef IDM_DEBUG
            if(sock_index < MAX_TCP_CLIENTS)
            {
                // if ssl was allocated previously for the same client, deallocate it
                if(ssl[sock_index])
                {
                    SSL_free(ssl[sock_index]);
                }
                ssl[sock_index] = SSL_new(ctx);
                if (ssl[sock_index] != NULL)
                {
                    SSL_set_fd(ssl[sock_index], client_socket[sock_index]);
                    if (SSL_accept(ssl[sock_index]) <= 0)
                    {
                        CcspTraceError(("(%s:%d)SSL handshake failed\n", __FUNCTION__, __LINE__));
                    }
                }
                else
                {
                    CcspTraceError(("(%s:%d) SSL session creation failed for client (%d)\n", __FUNCTION__, __LINE__, c_fd));
                }
            }
#endif
        } 
        //else its some IO operation on some other socket
        for (i = 0; i < MAX_TCP_CLIENTS; i++)
        {
            sd = client_socket[i];
            if (FD_ISSET(sd , &rset))
            {
                int ret;
                //Check if it was for closing , and also read the
                //incoming message
                memset((void *)&buffer, 0, sizeof(payload_t));
#ifndef IDM_DEBUG
                ret = SSL_read(ssl[i], (void *)&buffer, sizeof(payload_t));
                usleep(150000);
#else
                ret = read( sd , (void *)&buffer, sizeof(payload_t));
#endif

                if (ret <= 0)
                {
                    if (ret == 0)
                    {
                        //Somebody disconnected
                        //Close the socket and mark as 0 in list for reuse
                        CcspTraceInfo(("(%s:%d) Client socket(%d) closed\n", __FUNCTION__, __LINE__, sd));
#ifndef IDM_DEBUG
                        SSL_free(ssl[i]);
                        ssl[i] = NULL;
#endif
                        close(sd);
                        client_socket[i] = 0;
                    } else {
                        CcspTraceError(("(%s:%d) SSL Read failed\n", __FUNCTION__, __LINE__));
                    }
                }
                //Echo back the message that came in
                else
                {
                    connection_info_t client_info;
                    client_info.conn = sd;
#ifndef IDM_DEBUG
                    client_info.enc.ssl = ssl[i];
#endif
                    rcv_cb(&client_info, (void *)&buffer);
                }
            }
        }
    }
    pthread_exit(NULL);
}

int open_remote_connection(connection_config_t* connectionConf, int (*connection_cb)(device_info_t* Device, connection_info_t* conn_info, uint encryption_status), int (*rcv_message_cb)( connection_info_t* conn_info, void *payload))
{
    CcspTraceInfo(("%s %d -  \n", __FUNCTION__, __LINE__));
    struct sockaddr_in servaddr;
    int client_sockfd;
    bool enc_status = false;

    TcpServerThreadArgs ta ;

    memset (&ta,'\0',sizeof(TcpServerThreadArgs));
    strncpy_s(ta.interface, sizeof(ta.interface), connectionConf->interface, INTF_SIZE);
    ta.port = connectionConf->port;
    ta.cb = rcv_message_cb;

    /* start tcp server */
    if(!TCP_server_started)
    {
        pthread_t                server_thread;
        int                      iErrorCode     = 0;

        iErrorCode = pthread_create( &server_thread, NULL, &tcp_server_thread, &ta);
        if( 0 != iErrorCode )
        {
            CcspTraceInfo(("%s %d - Failed to start tcp_server_thread Thread EC:%d\n", __FUNCTION__, __LINE__, iErrorCode ));
            return -1;
        }
        else
        {
            TCP_server_started = true;
            CcspTraceInfo(("%s %d - IDM tcp_server_thread Started Successfully\n", __FUNCTION__, __LINE__ ));
        }
    }

    client_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (client_sockfd == -1)
    {
        CcspTraceInfo(("IDM Client socket creation failed...\n"));
        return -1;
    }

    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(connectionConf->device->ipv4_addr);
    servaddr.sin_port = htons(connectionConf->port);

    CcspTraceInfo(("waiting to connect to the IDM server..\n"));
    connect_reset = false;

    while (1)
    {
        pthread_mutex_lock(&connect_reset_mutex);
	if (connect_reset == true)
        {
            CcspTraceInfo(("Connect stopped since discovery is restarted"));
            pthread_mutex_unlock(&connect_reset_mutex);
	    close(client_sockfd);
            return -1; //This discovery is omitted due to discovery restart
        }
        pthread_mutex_unlock(&connect_reset_mutex);

        // Wait indefinitely untill other end idm server accepts the connection
        if (connect(client_sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) != 0)
        {
            sleep(1);
        }
        else {
            CcspTraceInfo(("IDM Client connected to the IDM server.. %d\n",client_sockfd));
            break;
        }
    }

    //TODO: check for dynamic allocation
    connection_info_t conn_info;
    conn_info.conn = client_sockfd;
#ifndef IDM_DEBUG
    conn_info.enc.ctx = NULL;
    conn_info.enc.ssl = NULL;

    // Client encryption
    conn_info.enc.ssl = NULL;
    if (!ssl_lib_init) {
        ssl_lib_init = true;
        SSL_library_init();
    }
    if ((conn_info.enc.ctx = init_ctx()) == NULL) {
        CcspTraceError(("(%s:%d) SSL ctx creation failed!!\n", __FUNCTION__, __LINE__));
        return -1;
    }
    if ((conn_info.enc.ssl = SSL_new(conn_info.enc.ctx)) == NULL) {
        CcspTraceError(("(%s:%d) SSL session creation failed!!\n", __FUNCTION__, __LINE__));
        return -1;
    }
    SSL_set_fd(conn_info.enc.ssl, client_sockfd);
    if (SSL_connect(conn_info.enc.ssl) > 0) {
        CcspTraceInfo(("Encryption status is set to true"));
        enc_status = true;
    }
    else
    {
        CcspTraceInfo(("Encryption status is set to false"));
    }
#else
    CcspTraceError(("(%s:%d) Refactor Disabled. Continue Connection without encryption\n", __FUNCTION__, __LINE__));
    enc_status = true;
#endif
    connection_cb(connectionConf->device, &conn_info, enc_status);
    return 0;
}

char* getFile_to_remote(connection_info_t* conn_info,void *payload)
{
    CcspTraceDebug(("Inside %s:%d\n",__FUNCTION__,__LINE__));
    FILE* fptr;
    payload_t *Data;
    char* buffer;
    int bytes = 0;
    uint32_t length;

#ifndef IDM_DEBUG
    if(conn_info->enc.ssl == NULL){
        CcspTraceError(("(%s:%d) SSL CTX is NULL, Data send failed\n", __FUNCTION__, __LINE__));
        return FT_ERROR;
    }
#endif
    Data = (payload_t*)payload;
    fptr = fopen(Data->param_name,"rb");
    CcspTraceInfo(("Inside %s:%d file name=%s\n",__FUNCTION__,__LINE__,Data->param_name));
    if(!fptr)
    {
        CcspTraceError(("%s:%d file not present\n",__FUNCTION__,__LINE__));
        strncpy_s(Data->param_value,sizeof(Data->param_value),FT_INVALID_FILE_NAME,strlen(FT_INVALID_FILE_NAME));
#ifndef IDM_DEBUG
        if ((bytes = SSL_write(conn_info->enc.ssl, Data, sizeof(payload_t))) > 0)
        {
            CcspTraceError(("%s:%d invalid file name information is sent to peer device\n",__FUNCTION__,__LINE__));
        }
#else
        if(send(conn_info->conn, Data, sizeof(payload_t), 0)<0){
            CcspTraceError(("%s %d - send failed : %s\n",  __FUNCTION__, __LINE__, strerror(errno)));
            return FT_ERROR;
        }
#endif
        return FT_INVALID_SRC_PATH;
    }
    fseek (fptr, 0, SEEK_END);
    length = ftell (fptr);
    CcspTraceDebug(("length of the file=%zu\n",length));
    fseek (fptr, 0, SEEK_SET);
    PIDM_DML_INFO pidmDmlInfo = IdmMgr_GetConfigData_locked();
    if(pidmDmlInfo == NULL)
    {
        CcspTraceError(("(%s:%d) idmDmlInfo is null\n",__FUNCTION__, __LINE__));
	fclose(fptr);
        return FT_ERROR;
    }
    if(length > (pidmDmlInfo->stRemoteInfo.max_file_size))
    {
        fclose(fptr);
        strncpy_s(Data->param_value,sizeof(Data->param_value),FT_FILE_SIZE_EXCEED,strlen(FT_FILE_SIZE_EXCEED));
#ifndef IDM_DEBUG
        if ((bytes = SSL_write(conn_info->enc.ssl, Data, sizeof(payload_t))) > 0)
        {
            CcspTraceError(("%s:%d file size is more than the configured value and information is sent to peer device\n",__FUNCTION__,__LINE__));
        }
#else
        if(send(conn_info->conn, Data, sizeof(payload_t), 0)<0){
            CcspTraceError(("%s %d - send failed : %s\n",  __FUNCTION__, __LINE__, strerror(errno)));
            IdmMgrDml_GetConfigData_release(pidmDmlInfo);
            return FT_ERROR;
        }
#endif
        IdmMgrDml_GetConfigData_release(pidmDmlInfo);
        return FT_INVALID_FILE_SIZE;
    }
    IdmMgrDml_GetConfigData_release(pidmDmlInfo);
    buffer = (char*)malloc (256);
    if(buffer)
    {
        memset(buffer,0,256);
        sprintf(buffer,"%zu",length);
        strncpy_s(Data->param_value,sizeof(Data->param_value),buffer,strlen(buffer));
#ifndef IDM_DEBUG
        if(conn_info->enc.ssl == NULL){
            CcspTraceError(("(%s:%d) SSL CTX is NULL, Data send failed\n", __FUNCTION__, __LINE__));
            free(buffer);
            fclose(fptr);
            return FT_ERROR;
        }
        if ((bytes = SSL_write(conn_info->enc.ssl, Data, sizeof(payload_t))) > 0)
        {
            free(buffer);
            buffer =(char*)malloc (length);
            if(buffer)
            {
                if(1 != fread (buffer, length, 1, fptr)) {
                    CcspTraceError(("fread failed \n"));
                    free(buffer);
                    fclose(fptr);
                    return FT_ERROR;
                }
                if((bytes = SSL_write(conn_info->enc.ssl, buffer,length)) <= 0)
                {
                    CcspTraceError(("file data is not transformed\n"));
                }
                CcspTraceDebug(("bytes written = %d and length=%d\n",bytes,(int)length));
            }
            else
            {
                fclose(fptr);
                CcspTraceError(("malloc failed to allocate memory\n"));
                return FT_ERROR;
            }
        }
        else
        {
            CcspTraceError(("length data is not transformed\n"));
        }
#else
        if(send(conn_info->conn, Data, sizeof(payload_t), 0)<0){
            CcspTraceError(("%s %d - send failed failed : %s\n",  __FUNCTION__, __LINE__, strerror(errno)));
            free(buffer);
            fclose(fptr);
            return FT_ERROR;
        }
        free(buffer);
        buffer =(char*)malloc (length);
        if(buffer)
        {
            if(1 != fread (buffer,length, 1,fptr)) {
                 CcspTraceError(("fread failed \n"));
                 free(buffer);
                 fclose(fptr);
                 return FT_ERROR;
            }
            if((bytes = send(conn_info->conn, buffer,length,0))<=0){
                CcspTraceError(("file data is not transformed through send\n"));
            }
            CcspTraceDebug(("bytes written = %d and length=%d through send\n",bytes,(int)length));
        }
        else
        {
            fclose(fptr);
            CcspTraceError(("malloc failed to allocate memory\n"));
            return FT_ERROR;
        }
#endif
    }
    else
    {
        fclose(fptr);
        CcspTraceError(("malloc failed to allocate memory\n"));
        return FT_ERROR;
    }
    if(buffer)
    {
        free(buffer);
    }
    fclose(fptr);
    return FT_SUCCESS;
}

char* sendFile_to_remote(connection_info_t* conn_info,void *payload,char* output_location)
{
    CcspTraceDebug(("Inside %s %d\n",__FUNCTION__,__LINE__));
    FILE* fptr;
    uint32_t length;
    payload_t *Data;
    int bytes = 0;
    char* buffer = NULL;
    errno_t rc = -1;
#ifndef IDM_DEBUG
    if(conn_info->enc.ssl == NULL)
    {
        CcspTraceError(("(%s:%d) SSL CTX is NULL, Data send failed\n", __FUNCTION__, __LINE__));
        return FT_ERROR;
    }
#endif
    Data = (payload_t*)payload;
    fptr = fopen(Data->param_name,"rb");
    CcspTraceInfo(("Inside %s:%d file name=%s\n",__FUNCTION__,__LINE__,Data->param_name));
    if(!fptr)
    {
        CcspTraceError(("%s:%d file not present\n",__FUNCTION__,__LINE__));
        return FT_INVALID_SRC_PATH;
    }
    fseek (fptr, 0, SEEK_END);
    length = ftell (fptr);
    CcspTraceDebug(("length of the file=%zu\n",length));
    fseek (fptr, 0, SEEK_SET);
    PIDM_DML_INFO pidmDmlInfo = IdmMgr_GetConfigData_locked();
    if(pidmDmlInfo == NULL)
    {
        CcspTraceError(("(%s:%d) idmDmlInfo is null\n",__FUNCTION__, __LINE__));
        fclose(fptr);
        return FT_ERROR;
    }
    if(length > (pidmDmlInfo->stRemoteInfo.max_file_size))
    {
        fclose(fptr);
        CcspTraceError(("%s:%d file size is more than the configured value\n",__FUNCTION__,__LINE__));
        IdmMgrDml_GetConfigData_release(pidmDmlInfo);
        return FT_INVALID_FILE_SIZE;
    }
    IdmMgrDml_GetConfigData_release(pidmDmlInfo);
    Data->file_length=(int)length;
    rc = strcpy_s(Data->param_name,sizeof(Data->param_name),output_location);
    if(rc != EOK)
    {
        ERR_CHK(rc);
        fclose(fptr);
        return FT_ERROR;
    }

    buffer = (char*)calloc (1, length);
    if(!buffer)
    {
        CcspTraceError(("memory is not allocated\n"));
        fclose(fptr);
        return FT_ERROR;
    }

    if(1 != fread (buffer, length, 1, fptr)) {
        CcspTraceError(("fread failed \n"));
        free(buffer);
        fclose( fptr );
        return FT_ERROR;
    }
    CcspTraceDebug(("%s:%d output file name = %s length=%zu length in Data=%d\n",__FUNCTION__,__LINE__,Data->param_name,length,Data->file_length));
    fclose( fptr );
#ifndef IDM_DEBUG
    if (conn_info->enc.ssl == NULL)
    {
        CcspTraceError(("%s:%d ssl session is null\n",__FUNCTION__,__LINE__));
        free(buffer);
        return FT_ERROR;
    }
    if ((bytes = SSL_write(conn_info->enc.ssl, Data, sizeof(payload_t))) > 0)
    {
        // above ssl write transfers the information about file length and output file location whereas below one sends the file content
        if((bytes = SSL_write(conn_info->enc.ssl, buffer,length)) <= 0)
        {
            CcspTraceError(("file data is not transformed\n"));
        }
        CcspTraceDebug(("bytes written = %d and length=%d\n",bytes,(int)length));
    }
    else
    {
        CcspTraceError(("length data is not transformed\n"));
    }
#else
    if(conn_info->conn == NULL)
    {
        CcspTraceError(("%s:%d conn value is null\n",__FUNCTION__,__LINE__));
        free(buffer);
        return FT_ERROR;
    }
    if(send(conn_info->conn, Data,sizeof(payload_t), 0) > 0)
    {
        CcspTraceDebug(("bytes written = %d and length=%d\n",bytes,(int)length));
        if((bytes = send(conn_info->conn, buffer,length,0))<=0){
            CcspTraceError(("file data is not transformed through send\n"));
        }
    }
    else
    {
        CcspTraceError(("%s:%d length and file data is not transformed\n",__FUNCTION__,__LINE__));
        free(buffer);
        return FT_ERROR;
    }
#endif
    free(buffer);
    return FT_SUCCESS;
}

int send_remote_message(connection_info_t* conn_info,void *payload)
{
#ifndef IDM_DEBUG
    int val;
    if (conn_info->enc.ctx != NULL && conn_info->enc.ssl != NULL) {
        val = SSL_write(conn_info->enc.ssl, payload, sizeof(payload_t));
        if (val > 0) {
            CcspTraceInfo(("(%s:%d) SSL_write successful connection id %d \n", __FUNCTION__, __LINE__,conn_info->conn));
            return 0;
        }
        else
        {
            int ssl_err = SSL_get_error(conn_info->enc.ssl, val);
            CcspTraceError(("(%s:%d) SSL_write failed (Ret: %d, SSL Error: %d)\n", __FUNCTION__, __LINE__, val, ssl_err));
        }
    }
    else
    {
        CcspTraceError(("(%s:%d) SSL CTX is NULL, Data send failed\n", __FUNCTION__, __LINE__));
    }
#else
    if(send(conn_info->conn, payload, sizeof(payload_t), 0)<0)
    {
        CcspTraceError(("%s %d - send failed failed : %s\n",  __FUNCTION__, __LINE__, strerror(errno)));
        return -1;
    }
#endif
    return -1;
}

int close_remote_connection(connection_info_t* conn_info)
{
    if (conn_info->enc.ssl != NULL) {
        SSL_free(conn_info->enc.ssl);
    }
    close(conn_info->conn);
    if (conn_info->enc.ctx != NULL) {
        SSL_CTX_free(conn_info->enc.ctx);
    }
    CcspTraceInfo(("%s %d - socket closed\n", __FUNCTION__, __LINE__));
    return 1;
}

