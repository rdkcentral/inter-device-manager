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
/*
 * Copyright 2021 RDK Management
 * Licensed under the Apache License, Version 2.0
 */

#include <sysevent/sysevent.h>
#include <syscfg/syscfg.h>
#include "Idm_call_back_apis.h"
#include "Idm_TCP_apis.h"
#include "Idm_msg_process.h"
#include "Idm_data.h"
#include "Idm_rbus.h"

#define DM_REMOTE_DEVICE_TABLE "Device.X_RDK_Remote.Device"
#define DEFAULT_IDM_REQUEST_TIMEOUT 10
#define MIN_BUFF                      128
#define MAX_BUFF                      1024

#define SYSEVENT_FIREWALL_RESTART "firewall-restart"

pthread_mutex_t remoteDeviceStatus_mutex  = PTHREAD_MUTEX_INITIALIZER;

typedef enum {
    REMOTE_DEVICE_NOT_DISCOVERED = 0,
    REMOTE_DEVICE_DISCOVERED = 1
} remote_discovery_status_t;

unsigned int remote_discovery_status = REMOTE_DEVICE_NOT_DISCOVERED;

extern char g_sslCert[SSL_FILE_LEN];
extern char g_sslKey[SSL_FILE_LEN];
extern char g_sslCA[SSL_FILE_LEN];
extern char g_sslCaDir[SSL_FILE_LEN];
#ifdef ENABLE_HW_CERT_USAGE
extern char g_sslSeCert[SSL_FILE_LEN];
extern char g_sslPassCodeFile[SSL_FILE_LEN];
extern char g_sslSeCA[SSL_FILE_LEN];
#endif

typedef struct discovery_cb_threadargs
{
    device_info_t device;
    uint discovery_status;
    uint auth_status;
} Discovery_cb_threadargs;

extern rbusHandle_t        rbusHandle;
extern int sysevent_fd;
extern token_t sysevent_token;
extern IDM_RBUS_SUBS_STATUS sidmRmSubStatus;

void *discovery_cb_thread(void *arg);
char* IDM_Incoming_FT_Response(connection_info_t* conn_info,payload_t * payload);
FILE *v_secure_popen(const char *direction, const char *command, ...);
int v_secure_pclose(FILE *);
int platform_hal_GetBaseMacAddress(char *);
void start_discovery(discovery_config_t* dc_obj,int (*func_callback)(device_info_t*,uint,uint));
int stop_discovery();

int rcv_message_cb( connection_info_t* conn_info, void *payload)
{

    payload_t *recvData = (payload_t*)payload;
    CcspTraceInfo(("%s %d - msgType-%d \n", __FUNCTION__, __LINE__,recvData->msgType));

    if(recvData->msgType == REQ)
    {
        IDM_Incoming_Request_handler(recvData);
    }else if(recvData->msgType == RES)
    {
        IDM_Incoming_Response_handler(recvData);
    }
    else if(recvData->operation == SFT)
    {
        PIDM_DML_INFO pidmDmlInfo = IdmMgr_GetConfigData_locked();
        if( pidmDmlInfo == NULL )
        {
            CcspTraceError(("%s %d idmDmlIndo is null\n",__FUNCTION__,__LINE__));
            strcpy_s(pidmDmlInfo->stRemoteInfo.ft_status,FT_STATUS_SIZE,FT_ERROR);
            return 1;
        }
        strcpy_s(pidmDmlInfo->stRemoteInfo.ft_status,FT_STATUS_SIZE,IDM_SFT_receive(conn_info,recvData));
        CcspTraceInfo(("%s:%d status=%s\n",__FUNCTION__,__LINE__,pidmDmlInfo->stRemoteInfo.ft_status));
        Idm_PublishDmEvent("Device.X_RDK_Remote.FileTransferStatus()",(pidmDmlInfo->stRemoteInfo.ft_status));
        IdmMgrDml_GetConfigData_release(pidmDmlInfo);
        usleep(100000);
    }
    else if(recvData->operation == SFT_RES)
    {
        PIDM_DML_INFO pidmDmlInfo = IdmMgr_GetConfigData_locked();
        if( pidmDmlInfo == NULL )
        {
            CcspTraceError(("%s %d idmDmlIndo is null\n",__FUNCTION__,__LINE__));
            strcpy_s(pidmDmlInfo->stRemoteInfo.ft_status,FT_STATUS_SIZE,FT_ERROR);
            return 1;
        }
        strcpy_s(pidmDmlInfo->stRemoteInfo.ft_status,FT_STATUS_SIZE,recvData->param_value);
        CcspTraceInfo(("%s:%d status=%s\n",__FUNCTION__,__LINE__,pidmDmlInfo->stRemoteInfo.ft_status));
        Idm_PublishDmEvent("Device.X_RDK_Remote.FileTransferStatus()",pidmDmlInfo->stRemoteInfo.ft_status);
        IdmMgrDml_GetConfigData_release(pidmDmlInfo);
    }
    else if(recvData->operation == GFT)
    {
        PIDM_DML_INFO pidmDmlInfo = IdmMgr_GetConfigData_locked();
        if( pidmDmlInfo == NULL )
        {
            CcspTraceError(("%s %d idmDmlIndo is null\n",__FUNCTION__,__LINE__));
            strcpy_s(pidmDmlInfo->stRemoteInfo.ft_status,FT_STATUS_SIZE,FT_ERROR);
            return 1;
        }
        strcpy_s(pidmDmlInfo->stRemoteInfo.ft_status,FT_STATUS_SIZE,IDM_Incoming_FT_Response(conn_info,recvData));
        Idm_PublishDmEvent("Device.X_RDK_Remote.FileTransferStatus()",pidmDmlInfo->stRemoteInfo.ft_status);
        IdmMgrDml_GetConfigData_release(pidmDmlInfo);
    }
    return 0;
}

int Capabilities_get_cb(IDM_REMOTE_DEVICE_INFO *device, ANSC_STATUS status ,char *mac)
{

        if(status == ANSC_STATUS_SUCCESS)
        {
            CcspTraceInfo(("%s %d -IDM Capabilities_get_cb from  device %s success \n", __FUNCTION__, __LINE__,mac));
        }else
            CcspTraceInfo(("%s %d -IDM Capabilities_get_cb from  device %s failed \n", __FUNCTION__, __LINE__,mac));

        //find device entry
        PIDM_DML_INFO pidmDmlInfo = IdmMgr_GetConfigData_locked();
        if( pidmDmlInfo == NULL )
        {
            return  -1;
        }

        IDM_REMOTE_DEVICE_LINK_INFO *remoteDevice = pidmDmlInfo->stRemoteInfo.pstDeviceLink;
        while(remoteDevice!=NULL)
        {
            if(strncasecmp(remoteDevice->stRemoteDeviceInfo.MAC, mac ,MAC_ADDR_SIZE) == 0)
            {
                char param_name[128],
                     prev_cap[128];
                IDM_REMOTE_DEVICE_STATUS   PrevStatus;
                
                CcspTraceInfo(("%s %d : Entry found %s\n",__FUNCTION__, __LINE__,remoteDevice->stRemoteDeviceInfo.MAC));
                PrevStatus = remoteDevice->stRemoteDeviceInfo.Status;
                remoteDevice->stRemoteDeviceInfo.Status = DEVICE_CONNECTED;
                memset(prev_cap, 0, sizeof(prev_cap));
                snprintf(prev_cap,sizeof(prev_cap),"%s",remoteDevice->stRemoteDeviceInfo.Capabilities);
                strncpy(remoteDevice->stRemoteDeviceInfo.Capabilities,device->Capabilities, sizeof(remoteDevice->stRemoteDeviceInfo.Capabilities));
                strncpy(remoteDevice->stRemoteDeviceInfo.ModelNumber,device->ModelNumber, sizeof(remoteDevice->stRemoteDeviceInfo.ModelNumber));
                remoteDevice->stRemoteDeviceInfo.HelloInterval = device->HelloInterval;

                IDM_DeviceChangeEvent DeviceChangeEvent;
                memset(&DeviceChangeEvent, 0, sizeof(IDM_DeviceChangeEvent));
                DeviceChangeEvent.deviceIndex = remoteDevice->stRemoteDeviceInfo.Index;
                DeviceChangeEvent.capability = remoteDevice->stRemoteDeviceInfo.Capabilities;
                DeviceChangeEvent.mac_addr = remoteDevice->stRemoteDeviceInfo.MAC;
                DeviceChangeEvent.available = true;
                Idm_PublishDeviceChangeEvent(&DeviceChangeEvent);

                //Publish MAC Event
                if( sidmRmSubStatus.idmRmMacSubscribed )
                {
                    memset(param_name,0,sizeof(param_name));
                    snprintf(param_name,sizeof(param_name),DM_PUBLISH_REMOTE_DEVICE_MAC,remoteDevice->stRemoteDeviceInfo.Index);
                    CcspTraceInfo(("%s %d Publishing Event for dm '%s' MAC '%s'\n",__FUNCTION__,__LINE__,param_name,remoteDevice->stRemoteDeviceInfo.MAC));
                    Idm_PublishDmEvent(param_name,remoteDevice->stRemoteDeviceInfo.MAC);
                }

                //Publish Status Event
                if( ( sidmRmSubStatus.idmRmStatusSubscribed ) && ( PrevStatus != remoteDevice->stRemoteDeviceInfo.Status ) )
                {
                    memset(param_name,0,sizeof(param_name));
                    snprintf(param_name,sizeof(param_name),DM_PUBLISH_REMOTE_DEVICE_STATUS,remoteDevice->stRemoteDeviceInfo.Index);
                    CcspTraceInfo(("%s %d Publishing Event for dm '%s' MAC '%s' Value '%d'\n",__FUNCTION__,__LINE__,param_name,remoteDevice->stRemoteDeviceInfo.MAC,remoteDevice->stRemoteDeviceInfo.Status));
                    Idm_PublishDmEvent(param_name,&remoteDevice->stRemoteDeviceInfo.Status);
                }

                //Publish Capabilities Event
                if( ( sidmRmSubStatus.idmRmCapSubscribed ) && ( 0 != strcmp(prev_cap,remoteDevice->stRemoteDeviceInfo.Capabilities) ) )
                {
                    memset(param_name,0,sizeof(param_name));
                    snprintf(param_name,sizeof(param_name),DM_PUBLISH_REMOTE_DEVICE_CAP,remoteDevice->stRemoteDeviceInfo.Index);
                    CcspTraceInfo(("%s %d Publishing Event for dm '%s' MAC '%s' Value '%s'\n",__FUNCTION__,__LINE__,param_name,remoteDevice->stRemoteDeviceInfo.MAC,remoteDevice->stRemoteDeviceInfo.Capabilities));
                    Idm_PublishDmEvent(param_name,remoteDevice->stRemoteDeviceInfo.Capabilities);
                }

                break;
            }
            remoteDevice=remoteDevice->next;
        }
            IdmMgrDml_GetConfigData_release(pidmDmlInfo);
    return 0;
}

int connection_cb(device_info_t* Device, connection_info_t* conn_info, uint encryption_status)
{

    //TODO: Send request all parameters of remote device
    //Send request to get Capabilities
    idm_send_msg_Params_t param;
    memset(&param, 0, sizeof(param));
    strncpy(param.Mac_dest, Device->mac_addr, sizeof(param.Mac_dest)-1);
    param.timeout = DEFAULT_IDM_REQUEST_TIMEOUT;
    param.operation = IDM_REQUEST;
    param.resCb = NULL;

    while(1)
    {
        PIDM_DML_INFO pidmDmlInfo = IdmMgr_GetConfigData_locked();
        if( pidmDmlInfo == NULL )
        {
            return  -1;
        }

        IDM_REMOTE_DEVICE_LINK_INFO *remoteDevice = pidmDmlInfo->stRemoteInfo.pstDeviceLink;
        while(remoteDevice!=NULL)
        {
            if(strcmp(remoteDevice->stRemoteDeviceInfo.MAC, Device->mac_addr) == 0)
            {

                break;
            }
            remoteDevice=remoteDevice->next;
        }
        if((encryption_status) && (remoteDevice))
        {
            if(remoteDevice->stRemoteDeviceInfo.Status == DEVICE_CONNECTED || remoteDevice->stRemoteDeviceInfo.Status == DEVICE_NOT_DETECTED)
            {
                IdmMgrDml_GetConfigData_release(pidmDmlInfo);
                break;
            }
            remoteDevice->stRemoteDeviceInfo.conn_info.conn = conn_info->conn;
	    remoteDevice->stRemoteDeviceInfo.conn_info.enc.ctx = conn_info->enc.ctx;
            remoteDevice->stRemoteDeviceInfo.conn_info.enc.ssl = conn_info->enc.ssl;
            IdmMgrDml_GetConfigData_release(pidmDmlInfo);
            CcspTraceInfo(("%s %d - sending Capabilities Request socket : %d\n", __FUNCTION__, __LINE__,remoteDevice->stRemoteDeviceInfo.conn_info.conn));
            IDM_sendMsg_to_Remote_device(&param);

            sleep(5);
        }
        else
        {
            CcspTraceInfo(("%s %d - encryption_status failed\n", __FUNCTION__, __LINE__));
            IdmMgrDml_GetConfigData_release(pidmDmlInfo);
            break;
        }
    }
    return 0;
    
}

void *xupnp_rediscover_thread(void *arg)
{
    pthread_detach(pthread_self());

    int status = 0;
    char param_value[256];
    int retPsmGet = CCSP_SUCCESS;

    while(1)
    {
        int ret = 0;
        sleep(10);
        pthread_mutex_lock(&remoteDeviceStatus_mutex);
        status = remote_discovery_status;
        pthread_mutex_unlock(&remoteDeviceStatus_mutex);
        if(status == REMOTE_DEVICE_NOT_DISCOVERED)
        {
            retPsmGet = IDM_RdkBus_GetParamValuesFromDB(PSM_BROADCAST_INTERFACE_NAME,param_value,sizeof(param_value));
            if (retPsmGet == CCSP_SUCCESS)
            {
                CcspTraceInfo(("%s %d - Remote device not discovered with interface %s \n", __FUNCTION__, __LINE__,param_value));
                if(strncmp(param_value,"br-home",strlen("br-home")) == 0)
                {
                    Idm_UpdateMeshConnectionValue();
                    ret = check_device_status();
                    if(ret == 1) {
                        CcspTraceInfo(("%s %d - Mesh Connected. Restarting upnp and stopping xupnp_rediscover_thread\n", __FUNCTION__, __LINE__));
                        IDM_Stop_Device_Discovery();
                        break;
                    }
                    else {
                        CcspTraceInfo(("%s %d - Mesh not Connected. Skipping upnp restart\n", __FUNCTION__, __LINE__));
                    }
                }
                else
                {
                    CcspTraceInfo(("%s %d - Stopping xupnp_rediscover_thread\n", __FUNCTION__, __LINE__));
                    break;
                }
            }
        }
        else
        {
            CcspTraceInfo(("%s %d - Remote device discovered. Stopping xupnp_rediscover_thread\n", __FUNCTION__, __LINE__));
            break;
        }
    }
    return NULL;
}

int check_device_status()
{
    PIDM_DML_INFO pidmDmlInfo = IdmMgr_GetConfigData_locked();
    if( pidmDmlInfo == NULL )
    {
        return  ANSC_STATUS_FAILURE;
    }

    if(pidmDmlInfo->stConnectionInfo.MeshConnectionStatus == wifi_connection_status_connected)
    {
        CcspTraceInfo(("%s %d - Mesh reconnected status %d \n", __FUNCTION__, __LINE__,pidmDmlInfo->stConnectionInfo.MeshConnectionStatus));
        IdmMgrDml_GetConfigData_release(pidmDmlInfo);
        return 1;
    }
    CcspTraceInfo(("%s %d - Mesh connection down status %d \n", __FUNCTION__, __LINE__,pidmDmlInfo->stConnectionInfo.MeshConnectionStatus));
    IdmMgrDml_GetConfigData_release(pidmDmlInfo);
    return 0;
}

bool check_device_reachability (char *ip)
{
    char    cmd[MIN_BUFF] = {0},buf[MIN_BUFF] = {0},out[MAX_BUFF] = {0};
    FILE    *fp = NULL;
    uint32_t total_read = 0;

    if (ip == NULL)
    {
        CcspTraceInfo(("Ip address null \n"));
        return false;
    }
    CcspTraceInfo(("check ip reachbility %s \n",ip));
    snprintf(cmd, sizeof(cmd), "ping -c 1 %s",ip);
    fp = v_secure_popen("r", cmd);
    if (!fp) {
        CcspTraceInfo(("%s - popen failed, errno = %d \n", cmd, errno));
        return false;
    }
    memset(out, 0, MAX_BUFF);
    while (fgets(buf, MIN_BUFF, fp) != NULL) {
        uint32_t len = strlen(buf);
        if (total_read + len >= MAX_BUFF) {
            CcspTraceInfo(("Exceeded buffer size, clipping output\n"));
            break;
        }
        strncpy(out + total_read, buf, len);
        total_read += len;
    }

    if(v_secure_pclose(fp)) {
        return false;
    } else {
        return true;
    }
}

int discovery_cb(device_info_t* Device, uint discovery_status, uint authentication_status )
{
    CcspTraceInfo(("%s %d -  \n", __FUNCTION__, __LINE__));
    CcspTraceInfo(("IPv4=%s IPv6=%s MAC=%s discovery_status %d authentication_status %d \n",Device->ipv4_addr,Device->ipv6_addr,Device->mac_addr,discovery_status,authentication_status));

    int check_status = 0;
    if(discovery_status == 0)
    {
        PIDM_DML_INFO pidmDmlInfo = IdmMgr_GetConfigData_locked();
        if( pidmDmlInfo == NULL )
        {
            return  -1;
        }

        IDM_REMOTE_DEVICE_LINK_INFO *remoteDevice = pidmDmlInfo->stRemoteInfo.pstDeviceLink;
        while(remoteDevice!=NULL)
        {
            if(strcasecmp(remoteDevice->stRemoteDeviceInfo.MAC, Device->mac_addr) == 0)
            {
                if(remoteDevice->stRemoteDeviceInfo.Status == DEVICE_CONNECTED)
                {
                    check_status = 1;
                }
                break;
            }
            remoteDevice=remoteDevice->next;
        }
        IdmMgrDml_GetConfigData_release(pidmDmlInfo);
    }
    else
    {
        pthread_mutex_lock(&remoteDeviceStatus_mutex);
        remote_discovery_status = REMOTE_DEVICE_DISCOVERED;
        pthread_mutex_unlock(&remoteDeviceStatus_mutex);
        CcspTraceInfo(("%s %d - Setting discovery status\n", __FUNCTION__, __LINE__));
    }

    if(check_status == 1)
    {
        int ret = 0;
        CcspTraceInfo(("%s %d - Check device availability after 5 seconds \n", __FUNCTION__, __LINE__));
        /* After upnp timeout we are allowing 5 secs to see if the timeout was due to short mesh disconnect/reconnects
         * If mesh is reconnected after 5 secs, avoiding GFO */
        sleep(5);
        Idm_UpdateMeshConnectionValue();
        ret = check_device_status();
        if(ret == 1)
        {
            if(check_device_reachability(Device->ipv4_addr))
            {
                CcspTraceInfo(("%s %d - Short mesh disconnection. Restart upnp and returning from discovery_cb \n", __FUNCTION__, __LINE__));

                PIDM_DML_INFO pidmDmlInfo = IdmMgr_GetConfigData_locked();
                if(pidmDmlInfo != NULL)
                {
                    if(pidmDmlInfo->stConnectionInfo.DiscoveryInProgress == TRUE)
                    {
                        IDM_Stop_Device_Discovery();
                    }
                    IdmMgrDml_GetConfigData_release(pidmDmlInfo);
                }
                return 0;
            }
        }

        CcspTraceInfo(("%s %d: Device is still not available after 5 secs, proceeding to GFO  \n", __FUNCTION__, __LINE__));
    }

    if(Device == NULL)
    {
        CcspTraceInfo(("%s %d -Device structre is NULL\n", __FUNCTION__, __LINE__));
        return 0;
    }

    if(checkMacAddr(Device->mac_addr) == FALSE)
    {
        CcspTraceInfo(("%s %d -Discovered device MAC address is not in proper format\n", __FUNCTION__, __LINE__));
        return 0;
    }

    PIDM_DML_INFO pidmDmlInfo = IdmMgr_GetConfigData_locked();
    if( pidmDmlInfo == NULL )
    {
        return  -1;
    }

    if(strncasecmp(Device->mac_addr, pidmDmlInfo->stRemoteInfo.pstDeviceLink->stRemoteDeviceInfo.MAC, MAC_ADDR_SIZE )==0)
    {
        CcspTraceInfo(("%s %d -detected local device, don't add to remote device list, starting xupnp_rediscover_thread\n", __FUNCTION__, __LINE__));
        IdmMgrDml_GetConfigData_release(pidmDmlInfo);
        pthread_t rediscover_threadID;
        pthread_create(&rediscover_threadID, NULL, &xupnp_rediscover_thread, NULL);
        pthread_mutex_lock(&remoteDeviceStatus_mutex);
        remote_discovery_status = REMOTE_DEVICE_NOT_DISCOVERED;
        pthread_mutex_unlock(&remoteDeviceStatus_mutex);
        CcspTraceInfo(("%s %d - Resetting discovery status\n", __FUNCTION__, __LINE__));
        return 0;
    }
    IdmMgrDml_GetConfigData_release(pidmDmlInfo);

    pthread_t                discovery_cb_threadID;
    int                      iErrorCode     = 0;

    Discovery_cb_threadargs *threadArgs = malloc(sizeof(Discovery_cb_threadargs));
    strncpy(threadArgs->device.mac_addr, Device->mac_addr, MAC_ADDR_SIZE);
    strncpy(threadArgs->device.ipv4_addr, Device->ipv4_addr, IPv4_ADDR_SIZE);
    strncpy(threadArgs->device.ipv6_addr, Device->ipv6_addr, IPv6_ADDR_SIZE);
    threadArgs->discovery_status = discovery_status;
    threadArgs->auth_status = authentication_status;


    iErrorCode = pthread_create( &discovery_cb_threadID, NULL, &discovery_cb_thread, threadArgs);
    if( 0 != iErrorCode )
    {
        CcspTraceInfo(("%s %d - Failed to start discovery_cb_thread Thread EC:%d\n", __FUNCTION__, __LINE__, iErrorCode ));
        return -1;
    }
    else
    {
        CcspTraceInfo(("%s %d - IDM discovery_cb_thread Started Successfully\n", __FUNCTION__, __LINE__ ));
    }    
    return 0;
}
void *discovery_cb_thread(void *arg)
{
    Discovery_cb_threadargs *threadArgs = (Discovery_cb_threadargs*) arg;
    errno_t rc = -1;

    device_info_t* Device = &(threadArgs->device);
    uint discovery_status = threadArgs->discovery_status;
    uint authentication_status = threadArgs->auth_status;

    CcspTraceInfo(("%s %d - Discovery callback for Device mac %s \n", __FUNCTION__, __LINE__,Device->mac_addr));

    pthread_detach(pthread_self());

    int entryFount = 0;
    PIDM_DML_INFO pidmDmlInfo = IdmMgr_GetConfigData_locked();
    if( pidmDmlInfo == NULL )
    {
        free(threadArgs);
        return NULL;
    }

    IDM_REMOTE_DEVICE_LINK_INFO *remoteDevice = pidmDmlInfo->stRemoteInfo.pstDeviceLink;
    while(remoteDevice!=NULL)
    {
        if(strcasecmp(remoteDevice->stRemoteDeviceInfo.MAC, Device->mac_addr) == 0)
        {
            CcspTraceInfo(("Entry found %s  \n",remoteDevice->stRemoteDeviceInfo.MAC));
            entryFount = 1;

            if(!discovery_status)
            {
                char param_name[128];

                //TODO: Publish device change event.
                remoteDevice->stRemoteDeviceInfo.Status = DEVICE_NOT_DETECTED;
                if(remoteDevice->stRemoteDeviceInfo.conn_info.conn != 0)
                {
                    close_remote_connection(&remoteDevice->stRemoteDeviceInfo.conn_info);
                }
                remoteDevice->stRemoteDeviceInfo.conn_info.conn = 0;

                IDM_DeviceChangeEvent DeviceChangeEvent;
                memset(&DeviceChangeEvent, 0, sizeof(IDM_DeviceChangeEvent));
                DeviceChangeEvent.deviceIndex = remoteDevice->stRemoteDeviceInfo.Index;
                DeviceChangeEvent.mac_addr = remoteDevice->stRemoteDeviceInfo.MAC;
                DeviceChangeEvent.available = false;
                Idm_PublishDeviceChangeEvent(&DeviceChangeEvent);

                //Publish Status Event
                if(sidmRmSubStatus.idmRmStatusSubscribed )
                {
                    memset(param_name,0,sizeof(param_name));
                    snprintf(param_name,sizeof(param_name),DM_PUBLISH_REMOTE_DEVICE_STATUS,remoteDevice->stRemoteDeviceInfo.Index);
                    CcspTraceInfo(("%s %d Publishing Event for dm '%s' MAC '%s' Value '%d'\n",__FUNCTION__,__LINE__,param_name,remoteDevice->stRemoteDeviceInfo.MAC,remoteDevice->stRemoteDeviceInfo.Status));
                    Idm_PublishDmEvent(param_name,&remoteDevice->stRemoteDeviceInfo.Status);
                }

                break;
            }

            if(authentication_status)
                remoteDevice->stRemoteDeviceInfo.Status = DEVICE_AUTHENTICATED;
            else if(discovery_status)
                remoteDevice->stRemoteDeviceInfo.Status = DEVICE_DETECTED;

            rc = strcpy_s(remoteDevice->stRemoteDeviceInfo.IPv4, sizeof(remoteDevice->stRemoteDeviceInfo.IPv4), Device->ipv4_addr);
            ERR_CHK(rc);
            rc = strcpy_s(remoteDevice->stRemoteDeviceInfo.IPv6, sizeof(remoteDevice->stRemoteDeviceInfo.IPv6), Device->ipv6_addr);
            ERR_CHK(rc);

            memset(remoteDevice->stRemoteDeviceInfo.ARPMac, 0 , sizeof(remoteDevice->stRemoteDeviceInfo.ARPMac));

            if(getARPMac(pidmDmlInfo->stConnectionInfo.Interface, Device->ipv4_addr, remoteDevice->stRemoteDeviceInfo.ARPMac) == 1)
            {
                if(strlen(remoteDevice->stRemoteDeviceInfo.ARPMac) > 0 )
                {
                    CcspTraceInfo(("%s %d -ARP mac :%s \n", __FUNCTION__, __LINE__, remoteDevice->stRemoteDeviceInfo.ARPMac));
                }
                else
                {
                    CcspTraceInfo(("%s %d - Failed to get ARP mac \n", __FUNCTION__, __LINE__));
                }
            }
            else
            {
                CcspTraceInfo(("%s %d - Failed to get ARP mac \n", __FUNCTION__, __LINE__));
            }
            /* Create link */
            connection_config_t connectionConf;
            memset(&connectionConf, 0, sizeof(connection_config_t));
            rc = strcpy_s(connectionConf.interface, sizeof(connectionConf.interface), pidmDmlInfo->stConnectionInfo.Interface);
            ERR_CHK(rc);

            connectionConf.port = pidmDmlInfo->stRemoteInfo.Port;
            connectionConf.device = Device;
            IdmMgrDml_GetConfigData_release(pidmDmlInfo);
            pidmDmlInfo = NULL;
            if(open_remote_connection(&connectionConf, connection_cb, rcv_message_cb) !=0)
            {
                CcspTraceError(("%s %d - open_remote_connection failed\n", __FUNCTION__, __LINE__));
                free(threadArgs);
                return NULL;
            }
            system("touch /tmp/idm_established");
            break;

        }
        remoteDevice=remoteDevice->next;
    }    

    if(!entryFount)
    {
        CcspTraceInfo(("%s %d - New device detected MAC %s \n", __FUNCTION__, __LINE__, Device->mac_addr));

        //Create new entry in remote deice list
        IDM_REMOTE_DEVICE_LINK_INFO *newNode = NULL;
        newNode = (IDM_REMOTE_DEVICE_LINK_INFO*)AnscAllocateMemory(sizeof(IDM_REMOTE_DEVICE_LINK_INFO));

        if( newNode == NULL )
        {
            IdmMgrDml_GetConfigData_release(pidmDmlInfo);
            free(threadArgs);
            return NULL;
        }
        memset(newNode, 0, sizeof(IDM_REMOTE_DEVICE_LINK_INFO));
        if(authentication_status)
            newNode->stRemoteDeviceInfo.Status = DEVICE_AUTHENTICATED;
        else if(discovery_status)
            newNode->stRemoteDeviceInfo.Status = DEVICE_DETECTED;

        newNode->stRemoteDeviceInfo.Index = pidmDmlInfo->stRemoteInfo.ulDeviceNumberOfEntries;
        newNode->stRemoteDeviceInfo.Index++;
        //TODO: convert MAC address to Uppercase
        rc = strcpy_s(newNode->stRemoteDeviceInfo.MAC, sizeof(newNode->stRemoteDeviceInfo.MAC), Device->mac_addr);
	ERR_CHK(rc);
        rc = strcpy_s(newNode->stRemoteDeviceInfo.IPv4, sizeof(newNode->stRemoteDeviceInfo.IPv4), Device->ipv4_addr);
	ERR_CHK(rc);
        rc = strcpy_s(newNode->stRemoteDeviceInfo.IPv6, sizeof(newNode->stRemoteDeviceInfo.IPv6), Device->ipv6_addr);
	ERR_CHK(rc);

        // Remote device found. Store mac obtianed from ARP table
        memset(newNode->stRemoteDeviceInfo.ARPMac, 0 , sizeof(newNode->stRemoteDeviceInfo.ARPMac));

        if(getARPMac(pidmDmlInfo->stConnectionInfo.Interface, Device->ipv4_addr, newNode->stRemoteDeviceInfo.ARPMac) == 1 )
        {

            if(strlen(newNode->stRemoteDeviceInfo.ARPMac) > 0 )
            {
                CcspTraceInfo(("%s %d -ARP mac :%s \n", __FUNCTION__, __LINE__, newNode->stRemoteDeviceInfo.ARPMac));
            }
            else
            {
                CcspTraceInfo(("%s %d - Failed to get ARP mac \n", __FUNCTION__, __LINE__));
            }
        }
        else
        {
            CcspTraceInfo(("%s %d - Failed to get ARP mac \n", __FUNCTION__, __LINE__));
        }
    
        newNode->stRemoteDeviceInfo.conn_info.conn = 0;

        if(addDevice(newNode) == ANSC_STATUS_SUCCESS)
        {
            CcspTraceInfo(("%s %d - new Device entry %d added\n", __FUNCTION__, __LINE__, newNode->stRemoteDeviceInfo.Index ));
            pidmDmlInfo->stRemoteInfo.ulDeviceNumberOfEntries++;
        }
        // add row for table
        rbusTable_registerRow(rbusHandle, DM_REMOTE_DEVICE_TABLE,
                pidmDmlInfo->stRemoteInfo.ulDeviceNumberOfEntries, NULL);

        //Publish Status Event
        if( sidmRmSubStatus.idmRmDeviceNoofEntriesSubscribed )
        {
            CcspTraceInfo(("%s %d Publishing Event for dm '%s' Value '%d'\n",__FUNCTION__,__LINE__,RM_NUM_ENTRIES,pidmDmlInfo->stRemoteInfo.ulDeviceNumberOfEntries));
            Idm_PublishDmEvent(RM_NUM_ENTRIES,&pidmDmlInfo->stRemoteInfo.ulDeviceNumberOfEntries);
        }
                
        /* Create link */
        connection_config_t connectionConf;
        memset(&connectionConf, 0, sizeof(connection_config_t));
        strncpy(connectionConf.interface, pidmDmlInfo->stConnectionInfo.Interface,sizeof(connectionConf.interface)-1);
        connectionConf.port = pidmDmlInfo->stRemoteInfo.Port;
        connectionConf.device = Device;
        IdmMgrDml_GetConfigData_release(pidmDmlInfo);
        pidmDmlInfo = NULL;
        if(open_remote_connection(&connectionConf, connection_cb, rcv_message_cb) !=0)
        {
            CcspTraceError(("%s %d - open_remote_connection failed\n", __FUNCTION__, __LINE__));
            IdmMgrDml_GetConfigData_release(pidmDmlInfo);
            free(threadArgs);
            return NULL;
        }
        system("touch /tmp/idm_established");
    }
    if(pidmDmlInfo != NULL)
    {
        IdmMgrDml_GetConfigData_release(pidmDmlInfo);
    }
    CcspTraceError(("%s %d - exit \n", __FUNCTION__, __LINE__));
    
    free(threadArgs);
    pthread_exit(NULL);
    return NULL;
}

void *start_discovery_thread(void *arg)
{
    (void)(arg);
    CcspTraceInfo(("%s %d - \n", __FUNCTION__, __LINE__));

    pthread_detach(pthread_self());
    int n = 0;
    struct timeval tv;

    while(TRUE)
    {
        /* Wait up to 500 milliseconds */
        tv.tv_sec = 0;
        tv.tv_usec = 500000;

        n = select(0, NULL, NULL, NULL, &tv);
        if (n < 0)
        {
            /* interrupted by signal or something, continue */
            continue;
        }

        ANSC_STATUS retValue = ANSC_STATUS_FAILURE;
        retValue = IDM_UpdateLocalDeviceData();
        if(retValue != ANSC_STATUS_SUCCESS)
        {
            if(retValue == ANSC_STATUS_FAILURE)
            {
                CcspTraceError(("%s %d - IDM UpdateLocalDeviceData initialisation Failed. Retry ...\n", __FUNCTION__, __LINE__));
            }
            else if(retValue == ANSC_STATUS_DO_IT_AGAIN)
            {
                CcspTraceInfo(("%s %d - IDM Restart triggered. Update current interface details. \n", __FUNCTION__, __LINE__));
            } 
            continue;
        }
        CcspTraceInfo(("%s %d - IDM UpdateLocalDeviceData success\n", __FUNCTION__, __LINE__));

        discovery_config_t discoveryConf;

        memset (&discoveryConf, 0, sizeof(discovery_config_t));

        strncpy(discoveryConf.sslCert, g_sslCert, sizeof(discoveryConf.sslCert) - 1 );
        strncpy(discoveryConf.sslKey, g_sslKey, sizeof(discoveryConf.sslKey) - 1 );
        strncpy(discoveryConf.sslCA, g_sslCA, sizeof(discoveryConf.sslCA) - 1 );
#ifdef ENABLE_HW_CERT_USAGE
        // pass the configuration to xupnp 
        strncpy(discoveryConf.sslSeCert, g_sslSeCert, sizeof(discoveryConf.sslSeCert) - 1 );
        strncpy(discoveryConf.sslPassCodeFile, g_sslPassCodeFile, sizeof(discoveryConf.sslPassCodeFile) - 1 );
        strncpy(discoveryConf.sslSeCA, g_sslSeCA, sizeof(discoveryConf.sslSeCA) - 1 );
#endif

        /* Update discovery_config deatils */
        PIDM_DML_INFO pidmDmlInfo = IdmMgr_GetConfigData_locked();
        if(pidmDmlInfo != NULL)
        {
            discoveryConf.discovery_interval = (pidmDmlInfo->stConnectionInfo.HelloInterval / 1000);

            strncpy(discoveryConf.interface, pidmDmlInfo->stConnectionInfo.Interface,sizeof(discoveryConf.interface));
            discoveryConf.loss_detection_window = (pidmDmlInfo->stConnectionInfo.DetectionWindow /1000);
            discoveryConf.port = pidmDmlInfo->stConnectionInfo.Port;
            pidmDmlInfo->stConnectionInfo.DiscoveryInProgress = TRUE;
            IdmMgrDml_GetConfigData_release(pidmDmlInfo);
        }
        platform_hal_GetBaseMacAddress(discoveryConf.base_mac);

        CcspTraceInfo(("%s %d: starting discovery process with base MAC: %s\n", __FUNCTION__, __LINE__, discoveryConf.base_mac));

        /* restart Firewall to add iptable rules for current IDM Interface */
        sysevent_set(sysevent_fd, sysevent_token, SYSEVENT_FIREWALL_RESTART, NULL, 0);

        /*Start CAL Device discovery process */
        start_discovery(&discoveryConf, discovery_cb);
        CcspTraceInfo(("%s %d - IDm device discovery completed.\n", __FUNCTION__, __LINE__));

        pidmDmlInfo = IdmMgr_GetConfigData_locked();
        if(pidmDmlInfo != NULL)
        {
            /* Reset Restart flag to false */
            pidmDmlInfo->stConnectionInfo.DiscoveryInProgress = FALSE;
            IdmMgrDml_GetConfigData_release(pidmDmlInfo);
            pidmDmlInfo = NULL;
        }
    }
    pthread_exit(NULL);
    return NULL;
}
ANSC_STATUS IDM_Start_Device_Discovery()
{
    pthread_t                threadId, discovery_threadId;
    int                      iErrorCode     = 0;

    /* Start incoming req handler thread */
    iErrorCode = pthread_create( &threadId, NULL, &IDM_Incoming_req_handler_thread, NULL);
    if( 0 != iErrorCode )
    {
        CcspTraceInfo(("%s %d - Failed to start Incoming_req_handler_thread Thread EC:%d\n", __FUNCTION__, __LINE__, iErrorCode ));
        return ANSC_STATUS_FAILURE;
    }
    else
    {
        CcspTraceInfo(("%s %d - IDM Incoming_req_handler_thread Started Successfully\n", __FUNCTION__, __LINE__ ));
    }


    /* Start incoming start_discovery thread */
    iErrorCode = pthread_create( &discovery_threadId, NULL, &start_discovery_thread, NULL);
    if( 0 != iErrorCode )
    {
        CcspTraceInfo(("%s %d - Failed to start start_discovery Thread EC:%d\n", __FUNCTION__, __LINE__, iErrorCode ));
        return ANSC_STATUS_FAILURE;
    }
    else
    {
        CcspTraceInfo(("%s %d - IDM start_discovery thread Started Successfully\n", __FUNCTION__, __LINE__ ));
    }

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS IDM_Stop_Device_Discovery()
{
    CcspTraceInfo(("%s %d - called\n", __FUNCTION__, __LINE__ ));

    pthread_mutex_lock(&connect_reset_mutex);
    connect_reset = true; //To exit any previous waiting connect  
    pthread_mutex_unlock(&connect_reset_mutex);

    if(stop_discovery() !=0)
    {
        CcspTraceError(("%s %d - stop_discovery failed\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    CcspTraceInfo(("%s %d - stop_discovery completed \n", __FUNCTION__, __LINE__));
    return ANSC_STATUS_SUCCESS;
}

