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

#ifndef _IDM_MSG_PROCESS_H_
#define _IDM_MSG_PROCESS_H_

#include "Idm_rbus.h"
#include "ccsp_base_api.h"

typedef  struct _sendReqList
{
    uint reqId;
    char Mac_dest[MAC_ADDR_SIZE];
    rbusMethodAsyncHandle_t resCb;
    char param_name[128];
    uint timeout;
    char output_location[LOC_SIZE];
    struct _sendReqList *next;
}sendReqList;

typedef enum _IDM_MSG_OPERATION
{
    SET = 1,
    GET,
    IDM_SUBS,
    IDM_REQUEST,
    GFT,
    SFT,
    SFT_RES
}IDM_MSG_OPERATION;

typedef enum _IDM_MSG_TYPE
{
    REQ = 1,
    RES,
}IDM_MSG_TYPE;

typedef struct _idm_send_msg_Params
{
    IDM_MSG_OPERATION operation;
    char Mac_dest[MAC_ADDR_SIZE];
    char param_name[128];
    char param_value[2048];
    uint timeout;
    enum dataType_e type;
    rbusMethodAsyncHandle_t resCb;
}idm_send_msg_Params_t;

typedef struct
{
    IDM_MSG_OPERATION operation;
    IDM_MSG_TYPE msgType;
    char Mac_source[MAC_ADDR_SIZE];
    uint32_t reqID;
    uint32_t timeout;
    uint32_t status;
    int file_length;
    char param_name[128];
    enum dataType_e type;
    char param_value[2048];
} payload_t;

typedef  struct _RecvReqList
{
    uint reqId;
    char Mac_dest[MAC_ADDR_SIZE];
    IDM_MSG_OPERATION operation;
    char param_name[128];
    char param_value[2048];
    uint timeout;
    int file_length;
    struct _RecvReqList *next;
    enum dataType_e type;
}RecvReqList;

typedef  struct _sendSubscriptionList
{
    uint reqId;
    rbusMethodAsyncHandle_t resCb;
    struct _sendSubscriptionList *next;
}sendSubscriptionList;

typedef  struct _RecvSubscriptionList
{
    uint reqId;
    char Mac_dest[MAC_ADDR_SIZE];
	char param_name[128];
    struct _RecvSubscriptionList *next;
}RecvSubscriptionList;

void IDM_addToSendRequestList( sendReqList *newReq);

sendReqList* IDM_getFromSendRequestList(uint reqID);

ANSC_STATUS IDM_sendMsg_to_Remote_device(idm_send_msg_Params_t *param);

int IDM_Incoming_Response_handler(payload_t * payload);

void IDM_addToReceivedReqList( RecvReqList *newReq);

RecvReqList* IDM_ReceivedReqList_pop();

int IDM_Incoming_Request_handler(payload_t * payload);

void *IDM_Incoming_req_handler_thread();
void IDM_Broadcast_LocalDeviceInfo();

int Idm_UpdateMeshConnectionValue();

ANSC_STATUS IDM_sendFile_to_Remote_device(char * Mac_dest,char * filename,char * output_location);
ANSC_STATUS IDM_getFile_from_Remote_device(char * Mac_dest,char * filename,char * output_location);
 char * IDM_SFT_receive(connection_info_t* conn_info,void * payload);
#endif
