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
/*
 * Copyright [2014] [Cisco Systems, Inc.]
 * Licensed under the Apache License, Version 2.0
 */

#ifndef  _IDM_INTERNAL_H_
#define  _IDM_INTERNAL_H_

#include <openssl/ssl.h>
#include <openssl/err.h>
#include "inter_device_manager_global.h"
#include "ansc_debug_wrapper_base.h"
#include "ansc_common_structures.h"
#include "ansc_status.h"

#define  RDK_COMPONENT_ID_INTER_DEVICE_MANAGER                             "com.cisco.spvtg.ccsp.interdevicemanager"
#define  RDK_COMPONENT_NAME_INTER_DEVICE_MANAGER                           "com.cisco.spvtg.ccsp.interdevicemanager"
#define  RDK_COMPONENT_VERSION_INTER_DEVICE_MANAGER                        1
#define  RDK_COMPONENT_PATH_INTER_DEVICE_MANAGER                           "/com/cisco/spvtg/ccsp/interdevicemanager"

#define  RDK_COMMON_COMPONENT_HEALTH_Red                   1
#define  RDK_COMMON_COMPONENT_HEALTH_Yellow                2
#define  RDK_COMMON_COMPONENT_HEALTH_Green                 3

#define  RDK_COMMON_COMPONENT_STATE_Initializing           1
#define  RDK_COMMON_COMPONENT_STATE_Running                2
#define  RDK_COMMON_COMPONENT_STATE_Blocked                3
#define  RDK_COMMON_COMPONENT_STATE_Paused                 3

#define MAC_ADDR_SIZE 18
#define IPv4_ADDR_SIZE 16
#define IPv6_ADDR_SIZE 128
#define LOC_SIZE 128
#define FT_STATUS_SIZE 24
#define INTF_SIZE 32
#define SSL_FILE_LEN 128

typedef  struct
_COMPONENT_COMMON_INTER_DEVICE_MANAGER
{
    char*                           Name;
    uint32_t                           Version;
    char*                           Author;
    uint32_t                           Health;
    uint32_t                           State;

    BOOL                            LogEnable;
    uint32_t                           LogLevel;

    uint32_t                           MemMaxUsage;
    uint32_t                           MemMinUsage;
    uint32_t                           MemConsumed;

}
COMPONENT_COMMON_INTER_DEVICE_MANAGER, *PCOMPONENT_COMMON_INTER_DEVICE_MANAGER;

typedef enum _IDM_REMOTE_DEVICE_STATUS
{
   DEVICE_NOT_DETECTED = 0,
   DEVICE_DETECTED,
   DEVICE_AUTHENTICATED,
   DEVICE_CONNECTED
}IDM_REMOTE_DEVICE_STATUS;

typedef struct {
    SSL_CTX *ctx;
    SSL *ssl;
} ssl_info_t;

typedef struct {
    char interface[32];
    uint  port;
    uint  discovery_interval;
    uint  loss_detection_window;
    char base_mac[32];
    char sslCert[SSL_FILE_LEN];
    char sslKey[SSL_FILE_LEN];
    char sslCA[SSL_FILE_LEN];
#ifdef ENABLE_HW_CERT_USAGE
    char sslSeCert[SSL_FILE_LEN];
    char sslPassCodeFile[SSL_FILE_LEN];
    char sslSeCA[SSL_FILE_LEN];
#endif
} discovery_config_t;

typedef struct {
    char ipv4_addr[IPv4_ADDR_SIZE];
    char ipv6_addr[IPv6_ADDR_SIZE];
    char mac_addr[MAC_ADDR_SIZE];
} device_info_t;

typedef struct {
    char interface[INTF_SIZE];
    uint  port;
    device_info_t* device;
} connection_config_t;

typedef struct {
    int conn; //descriptor/sock
    bool closing;
    int active_senders;
    pthread_mutex_t lock;
    pthread_cond_t cond;
    ssl_info_t enc; // Encryption info
} connection_info_t; 

typedef struct 
{
    IDM_REMOTE_DEVICE_STATUS   Status;
    char                       MAC[18];
    unsigned int               HelloInterval;
    char                       IPv4[16];
    char                       IPv6[128];
    char                       Capabilities[1024];
    char                       ModelNumber[256];
    unsigned int               Index;
    connection_info_t          conn_info;
    char                       ARPMac[MAC_ADDR_SIZE];
} IDM_REMOTE_DEVICE_INFO, *PIDM_REMOTE_DEVICE_INFO;

typedef  struct _IDM_REMOTE_DEVICE_LINK_INFO
{
    IDM_REMOTE_DEVICE_INFO stRemoteDeviceInfo;
    struct _IDM_REMOTE_DEVICE_LINK_INFO* next;
}IDM_REMOTE_DEVICE_LINK_INFO;

typedef  struct _IDM_REMOTE_DEVICE_CAP_INFO
{
    char AddDeviceCapabilities[1024];
    char RemoveDeviceCapabilities[1024];
    unsigned char ResetDeviceCapabilities;
}
IDM_REMOTE_DEVICE_CAP_INFO,  *PIDM_REMOTE_DEVICE_CAP_INFO;

typedef  struct _IDM_REMOTE_INFO
{
    IDM_REMOTE_DEVICE_CAP_INFO      stRemoteDeviceCapInfo;
    unsigned int                    ulDeviceNumberOfEntries;
    unsigned int                    Port;
    int                             max_file_size;
    char                            ft_status[FT_STATUS_SIZE];
    IDM_REMOTE_DEVICE_LINK_INFO     *pstDeviceLink;
}
IDM_REMOTE_INFO,  *PIDM_REMOTE_INFO;

/* connection status of STA */
typedef enum {
    wifi_connection_status_disabled = 0,
    wifi_connection_status_disconnected = 1000000,
    wifi_connection_status_connected = 2000000,
    wifi_connection_status_ap_not_found = 3000000
} wifi_connection_status_t;

typedef  struct _IDM_CONNECTION_INFO
{
    unsigned int HelloInterval;
    char HelloIPv4SubnetList[256];
    char HelloIPv6SubnetList[1024];
    unsigned int DetectionWindow;
    char Capabilities[1024];
    char Interface[32];
    unsigned int Port;
    bool DiscoveryInProgress;
    bool InterfaceChanged;
    wifi_connection_status_t MeshConnectionStatus;
}
IDM_CONNECTION_INFO,  *PIDM_CONNECTION_INFO;

typedef  struct _IDM_DML_INFO
{
    IDM_CONNECTION_INFO             stConnectionInfo;
    IDM_REMOTE_INFO                 stRemoteInfo;
}
IDM_DML_INFO,  *PIDM_DML_INFO;

typedef struct _IDM_DML_LINK_LIST
{

    IDM_REMOTE_DEVICE_LINK_INFO *pListHead;
    IDM_REMOTE_DEVICE_LINK_INFO *pListTail;

}IDM_DML_LINK_LIST;

typedef struct _IDM_RBUS_SUBS_STATUS
{
    bool idmRmStatusSubscribed;
    bool idmRmMacSubscribed;
    bool idmRmHelloIntervalSubscribed;
    bool idmRmIPv4Subscribed;
    bool idmRmIPv6Subscribed;
    bool idmRmCapSubscribed;
    bool idmRmModelNumSubscribed;
    bool idmRmNewDeviceSubscribed;
    bool idmRmDeviceNoofEntriesSubscribed;
    bool idmRmDeviceFTStatusSubscribed;

}IDM_RBUS_SUBS_STATUS;
#endif
