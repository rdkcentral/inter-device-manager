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

#include "Idm_data.h"
#include "Idm_msg_process.h"
#include "Idm_TCP_apis.h"
#define DM_REMOTE_DEVICE_INVOKE "Device.X_RDK_Remote.Invoke()"

sendReqList *headsendReqList =NULL;
RecvReqList *headRecvReqList = NULL;

sendSubscriptionList *headsendSubscriptionList =NULL;
RecvSubscriptionList *headRecvSubscriptionList = NULL;

uint gReqIdCounter = 0;
extern rbusHandle_t        rbusHandle;
extern int Capabilities_get_cb(IDM_REMOTE_DEVICE_INFO *device, ANSC_STATUS status ,char *mac);
extern char * sendFile_to_remote(connection_info_t* conn_info,void *payload,char * output_location);
extern char * getFile_to_remote(connection_info_t* conn_info,void *payload);

static rbusValueType_t IDM_rbusValueChange_GetDataType(enum dataType_e dt)
{
    switch(dt)
    {
    case ccsp_string: return RBUS_STRING;
    case ccsp_int: return RBUS_INT32;
    case ccsp_unsignedInt: return RBUS_UINT32;
    case ccsp_boolean: return RBUS_BOOLEAN;
    case ccsp_dateTime: return RBUS_DATETIME;
    case ccsp_long: return RBUS_INT64;
    case ccsp_unsignedLong: return RBUS_UINT64;
    case ccsp_float: return RBUS_SINGLE;
    case ccsp_double: return RBUS_DOUBLE;
    case ccsp_byte: return RBUS_BYTES;
    case ccsp_none:
    default: return RBUS_NONE;
    }
}

void IDM_addToSendRequestList( sendReqList *newReq)
{
    if(!headsendReqList)
    {
        headsendReqList  = newReq;
    }else
    {

        sendReqList *temp = headsendReqList;
        while (temp->next != NULL)
        {
            temp = temp->next;
        }
        temp->next = newReq;
    }
}

sendReqList* IDM_getFromSendRequestList(uint reqID)
{
    /* find req entry in LL */
    sendReqList *req = headsendReqList, *temp = NULL;
    if(headsendReqList == NULL)
    {
        return NULL;
    }
    if(headsendReqList->reqId == reqID)
    {
        temp = headsendReqList;
        headsendReqList = headsendReqList->next;
        return temp;
    }else
    {
        while (req->next != NULL)
        {
            if(req->next->reqId == reqID)
            {
                /*entry found */
                temp = req->next;
                //Remove from LL. memory should br freed in calling function
                req->next = req->next->next;
                break;
            }
            req = req->next;
        }
        return temp;
    }
}

sendReqList* IDM_searchFromSendRequestList(const char *param_mac, const char *param_name)
{

    if(param_mac == NULL)
    {
        return NULL;
    }

    sendReqList *cur = headsendReqList;
    while (cur != NULL) 
    {
        if (strncmp(cur->Mac_dest, param_mac, sizeof(cur->Mac_dest) - 1) == 0)
        {
            if (strncmp(cur->param_name, param_name, sizeof(cur->param_name) -1) == 0)
            {
                return cur;
            }
        }
        cur = cur->next;
    }
    return NULL;
}

void IDM_addToSendSubscriptionuestList( sendSubscriptionList *newSubscription)
{
    if(!headsendSubscriptionList)
    {
        headsendSubscriptionList  = newSubscription;
    }else
    {

        sendSubscriptionList *temp = headsendSubscriptionList;
        while (temp->next != NULL)
        {
            temp = temp->next;
        }
        temp->next = newSubscription;
    }
}

void IDM_addToReceivedSubscriptionList( RecvSubscriptionList *newSubscription)
{
    if(!headRecvSubscriptionList)
    {
        headRecvSubscriptionList  = newSubscription;
    }else
    {

        RecvSubscriptionList *temp = headRecvSubscriptionList;
        while (temp->next != NULL)
        {
            temp = temp->next;
        }
        temp->next = newSubscription;
    }
}
ANSC_STATUS IDM_sendFile_to_Remote_device(char* Mac_dest,char* filename,char* output_location)
{
    CcspTraceDebug(("Inside %s:%d\n",__FUNCTION__,__LINE__));
    int match=0,ind=0;
    errno_t rc = -1;
    char *send_status = NULL;

    PIDM_DML_INFO pidmDmlInfo = IdmMgr_GetConfigData_locked();
    if( pidmDmlInfo == NULL )
    {
        return  ANSC_STATUS_FAILURE;
    }
    IDM_REMOTE_DEVICE_LINK_INFO *remoteDevice = pidmDmlInfo->stRemoteInfo.pstDeviceLink;
    IDM_REMOTE_DEVICE_LINK_INFO *localDevice = pidmDmlInfo->stRemoteInfo.pstDeviceLink;
    while(remoteDevice!=NULL)
    {
        if(strcasecmp(remoteDevice->stRemoteDeviceInfo.MAC,Mac_dest) == 0 && (remoteDevice->stRemoteDeviceInfo.Status == DEVICE_CONNECTED ))
        {
            if((remoteDevice->stRemoteDeviceInfo.conn_info.conn !=0))
            {
                payload_t payload;
                memset(&payload, 0, sizeof(payload_t));
                payload.operation = SFT;
                payload.msgType = SFT;
                strncpy(payload.Mac_source, localDevice->stRemoteDeviceInfo.MAC,MAC_ADDR_SIZE-1);
                strncpy(payload.param_name,filename,sizeof(payload.param_name)-1);
                CcspTraceDebug(("Inside %s:%d peer MAC=%s\n",__FUNCTION__,__LINE__,Mac_dest));
                send_status = sendFile_to_remote(&remoteDevice->stRemoteDeviceInfo.conn_info, &payload,output_location);
                if(send_status)
                {
                    CcspTraceInfo(("%s:%d send_status %s\n",__FUNCTION__,__LINE__,send_status));
                    rc = strcpy_s(pidmDmlInfo->stRemoteInfo.ft_status, FT_STATUS_SIZE, send_status);
                    ERR_CHK(rc);
	            if(rc == EOK)
                    {
                        Idm_PublishDmEvent("Device.X_RDK_Remote.FileTransferStatus()",pidmDmlInfo->stRemoteInfo.ft_status);
                    }
                }
                rc = strcmp_s(FT_SUCCESS,strlen(FT_SUCCESS),pidmDmlInfo->stRemoteInfo.ft_status,&ind);
                ERR_CHK(rc);
                if(rc != EOK || ind)
                {
                    usleep(250000);
                    IdmMgrDml_GetConfigData_release(pidmDmlInfo);
                    return  ANSC_STATUS_FAILURE;
                }
                usleep(250000);
                match = 1;
                break;
            }
            else
            {
                CcspTraceError(("%s: conn value is equals to zero\n",__FUNCTION__));
                rc = strcpy_s(pidmDmlInfo->stRemoteInfo.ft_status,FT_STATUS_SIZE,FT_ERROR);
                ERR_CHK(rc);
	        if(rc == EOK)
                {
                    Idm_PublishDmEvent("Device.X_RDK_Remote.FileTransferStatus()",pidmDmlInfo->stRemoteInfo.ft_status);
                }
                IdmMgrDml_GetConfigData_release(pidmDmlInfo);
                return  ANSC_STATUS_FAILURE;
            }
        }
        else
        {
            remoteDevice=remoteDevice->next;
        }
    }
    if(match == 0)
    {
        rc = strcpy_s(pidmDmlInfo->stRemoteInfo.ft_status,FT_STATUS_SIZE,FT_INVALID_DST_MAC);
        ERR_CHK(rc);
	if(rc == EOK)
        {
             Idm_PublishDmEvent("Device.X_RDK_Remote.FileTransferStatus()",pidmDmlInfo->stRemoteInfo.ft_status);
        }
    }
    IdmMgrDml_GetConfigData_release(pidmDmlInfo);
    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS IDM_getFile_from_Remote_device(char* Mac_dest,char* filename,char* output_location)
{
    CcspTraceDebug(("Inside %s:%d\n",__FUNCTION__,__LINE__));
    int match = 0;
    errno_t rc = -1;
    PIDM_DML_INFO pidmDmlInfo = IdmMgr_GetConfigData_locked();
    if( pidmDmlInfo == NULL )
    {
        return  ANSC_STATUS_FAILURE;
    }
    IDM_REMOTE_DEVICE_LINK_INFO *remoteDevice = pidmDmlInfo->stRemoteInfo.pstDeviceLink;
    IDM_REMOTE_DEVICE_LINK_INFO *localDevice = pidmDmlInfo->stRemoteInfo.pstDeviceLink;

    while(remoteDevice!=NULL)
    {
        if(strcasecmp(remoteDevice->stRemoteDeviceInfo.MAC,Mac_dest) == 0 && (remoteDevice->stRemoteDeviceInfo.Status == DEVICE_CONNECTED ))
        {
            if((remoteDevice->stRemoteDeviceInfo.conn_info.conn !=0))
            {
                payload_t payload;
                memset(&payload, 0, sizeof(payload_t));
                sendReqList *newReq = malloc(sizeof(sendReqList));
                if (newReq != NULL) {
                    memset(newReq, 0, sizeof(sendReqList));
                    newReq->reqId = gReqIdCounter++;
                    strncpy(newReq->Mac_dest,Mac_dest, MAC_ADDR_SIZE-1);
                    payload.operation = GFT;
                    payload.msgType = REQ;
                    strncpy(payload.Mac_source, localDevice->stRemoteDeviceInfo.MAC,MAC_ADDR_SIZE-1);
                    strncpy(payload.param_name,filename,sizeof(payload.param_name)-1);
                    strncpy(newReq->output_location,output_location,sizeof(newReq->output_location)-1);
                    payload.reqID = newReq->reqId;
		    strncpy(newReq->param_name, payload.param_name, sizeof(newReq->param_name)-1);
                    IDM_addToSendRequestList(newReq);
                    CcspTraceDebug(("Inside %s:%d peer MAC=%s\n",__FUNCTION__,__LINE__,Mac_dest));
                    send_remote_message(&remoteDevice->stRemoteDeviceInfo.conn_info, &payload);
                    usleep(250000);
                    match = 1;
		}
                break;
            }
            else
            {
                CcspTraceError(("%s: conn value is equals to zero\n",__FUNCTION__));
                rc = strcpy_s(pidmDmlInfo->stRemoteInfo.ft_status,FT_STATUS_SIZE,FT_ERROR);
                ERR_CHK(rc);
		if(rc == EOK)
                {
                    Idm_PublishDmEvent("Device.X_RDK_Remote.FileTransferStatus()",pidmDmlInfo->stRemoteInfo.ft_status);
                }

                IdmMgrDml_GetConfigData_release(pidmDmlInfo);
                return  ANSC_STATUS_FAILURE;
            }
        }
        else
        {
            remoteDevice=remoteDevice->next;
        }
    }
    if(match == 0)
    {
        rc = strcpy_s(pidmDmlInfo->stRemoteInfo.ft_status,FT_STATUS_SIZE,FT_INVALID_DST_MAC);        
        ERR_CHK(rc);
	if(rc == EOK)
        {
             Idm_PublishDmEvent("Device.X_RDK_Remote.FileTransferStatus()",pidmDmlInfo->stRemoteInfo.ft_status);
        }
    }
    IdmMgrDml_GetConfigData_release(pidmDmlInfo);
    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS IDM_sendMsg_to_Remote_device(idm_send_msg_Params_t *param)
{

    PIDM_DML_INFO pidmDmlInfo = IdmMgr_GetConfigData_locked();
    if( pidmDmlInfo == NULL )
    {
        return  ANSC_STATUS_FAILURE;
    }
    IDM_REMOTE_DEVICE_LINK_INFO *remoteDevice = pidmDmlInfo->stRemoteInfo.pstDeviceLink;
    IDM_REMOTE_DEVICE_LINK_INFO *localDevice = pidmDmlInfo->stRemoteInfo.pstDeviceLink;

    while(remoteDevice!=NULL)
    {
        if(strcasecmp(remoteDevice->stRemoteDeviceInfo.MAC, param->Mac_dest) == 0)
        {
            if((remoteDevice->stRemoteDeviceInfo.conn_info.conn !=0))
            {
                /* Create payload */
                payload_t payload;
                memset(&payload, 0, sizeof(payload_t));
                if(param->operation == GET || param->operation == SET || param->operation == IDM_REQUEST)
                {
                    sendReqList *SendReq = IDM_searchFromSendRequestList(param->Mac_dest, param->param_name);
                    if(SendReq != NULL)
                    {
                        CcspTraceInfo(("%s:%d Resending the same request with request id %d  \n",__FUNCTION__, __LINE__,SendReq->reqId));
                        payload.reqID = SendReq->reqId; 
                    }
                    else
                    {
                        /* Create request entry */
                        sendReqList *newReq = malloc(sizeof(sendReqList));
                        if (newReq != NULL) {
                            memset(newReq, 0, sizeof(sendReqList));
                            newReq->reqId = gReqIdCounter++;
                            strncpy(newReq->Mac_dest,param->Mac_dest, sizeof(newReq->Mac_dest)-1);
                            newReq->resCb = param->resCb;
                            newReq->timeout = param->timeout;
                            newReq->next = NULL;
                            strncpy(newReq->param_name, param->param_name, sizeof(newReq->param_name)-1);
                            IDM_addToSendRequestList(newReq);
                            payload.reqID = newReq->reqId;
                        }
                    }
                }else if(param->operation == IDM_SUBS)
                {
                    /* Create request entry */
                    sendSubscriptionList *newReq = malloc(sizeof(sendSubscriptionList));
                    if (newReq != NULL) {
                        memset(newReq, 0, sizeof(sendSubscriptionList));
                        newReq->reqId = gReqIdCounter++;
                        newReq->resCb = param->resCb;
                        newReq->next = NULL;
                        IDM_addToSendSubscriptionuestList(newReq);
                        payload.reqID = newReq->reqId;
                    }
                }

                payload.operation = param->operation;
                payload.msgType = REQ;
                strncpy(payload.Mac_source, localDevice->stRemoteDeviceInfo.MAC,sizeof(payload.Mac_source)-1);
                strncpy(payload.param_name,param->param_name,sizeof(payload.param_name)-1);
                strncpy(payload.param_value,param->param_value,sizeof(payload.param_value)-1);
                payload.type = param->type;

                /* send message */
                int ret = send_remote_message(&remoteDevice->stRemoteDeviceInfo.conn_info, &payload);
                usleep(250000); //Sleep for 250ms
                if(ret != 0)
                {
                    CcspTraceError(("%s:%d send_remote_message failed for request id %d\n",__FUNCTION__, __LINE__,payload.reqID));
                    if(param->operation == GET || param->operation == SET || param->operation == IDM_REQUEST)
                    {
                        sendReqList *req;
                        req = IDM_getFromSendRequestList(payload.reqID);
                        if(req == NULL)
                        {
                            CcspTraceError(("%s:%d Request not found in SendRequestList \n",__FUNCTION__, __LINE__));
                        }else{
                            CcspTraceInfo(("%s:%d Removing request from SendRequestList \n",__FUNCTION__, __LINE__));
                            free(req);
                        }
                    }
                }
            }else
            {
                IdmMgrDml_GetConfigData_release(pidmDmlInfo);
                return  ANSC_STATUS_FAILURE;
            }
            break;
        }
        remoteDevice=remoteDevice->next;
    }
    IdmMgrDml_GetConfigData_release(pidmDmlInfo);
    return ANSC_STATUS_SUCCESS;
}

char* IDM_Incoming_FT_Response(connection_info_t* conn_info,payload_t* payload)
{
    CcspTraceDebug(("Inside %s:%d\n",__FUNCTION__,__LINE__));
    char* buf;
    int bytes=0,length=0,total_bytes=0,rc = -1,ind = -1;
    if(payload != NULL)
    {
        sendReqList *req;
        req = IDM_getFromSendRequestList(payload->reqID);
        if(req == NULL)
        {
            CcspTraceError(("%s:%d req is null\n",__FUNCTION__,__LINE__));
            return FT_ERROR;
        }
        rc = strcmp_s(FT_INVALID_FILE_NAME,strlen(FT_INVALID_FILE_NAME),payload->param_value,&ind);
        ERR_CHK(rc);
        if((!ind) && (rc == EOK))
        {
            free(req);
            return FT_INVALID_SRC_PATH;
        }
        rc = strcmp_s(FT_FILE_SIZE_EXCEED,strlen(FT_FILE_SIZE_EXCEED),payload->param_value,&ind);
        ERR_CHK(rc);
        if((!ind) && (rc == EOK))
        {
            CcspTraceError(("%s %d transfer file size exceeded on peer device\n",__FUNCTION__,__LINE__));
            free(req);
            return FT_INVALID_FILE_SIZE;
        }
        total_bytes=atoi(payload->param_value);
        CcspTraceInfo(("%s file with size %d will be transferred\n",payload->param_name,total_bytes));
        PIDM_DML_INFO pidmDmlInfo = IdmMgr_GetConfigData_locked();
        if( pidmDmlInfo == NULL )
        {
            CcspTraceError(("%s:%d DmlInfo is NULL\n",__FUNCTION__,__LINE__));
	    free(req);
            return  FT_ERROR;
        }
        if(total_bytes > (pidmDmlInfo->stRemoteInfo.max_file_size))
        {
            CcspTraceError(("%s:%d transfer file size exceeded on self device compared to %d configured value\n",__FUNCTION__,__LINE__,(pidmDmlInfo->stRemoteInfo.max_file_size)));
            IdmMgrDml_GetConfigData_release(pidmDmlInfo);
	    free(req);
            return FT_INVALID_FILE_SIZE;
        }
        IdmMgrDml_GetConfigData_release(pidmDmlInfo);
        FILE* fptr;
        fptr = fopen(req->output_location,"wb");
        CcspTraceInfo(("output location = %s\n",req->output_location));
        if(!fptr){
            CcspTraceError(("%s:%d file not found\n",__FUNCTION__,__LINE__));
            int rc = -1,ind = -1;
            char* tok = strtok(req->output_location,"/");
            rc = strcmp_s(FT_NVRAM,strlen(FT_NVRAM),tok,&ind);
            ERR_CHK(rc);
            if((!ind) && (rc == EOK))
            {
	        free(req);
                return FT_INVALID_DST_PATH;
            }
            rc = strcmp_s(FT_TMP,strlen(FT_TMP),tok,&ind);
            ERR_CHK(rc);
            if((!ind) && (rc == EOK))
            {
	        free(req);
                return FT_INVALID_DST_PATH;
            }
	    free(req);
            return FT_NOT_WRITABLE_PATH;
        }
        else{
            buf = (char*) malloc(total_bytes);
            if(buf == NULL)
            {
                fclose(fptr);
                CcspTraceError(("malloc failed to allocate memory\n"));
	        free(req);
                return FT_ERROR;
            }
            while(length<total_bytes){
#ifndef IDM_DEBUG
                if(conn_info->enc.ssl != NULL){
                    bytes = SSL_read(conn_info->enc.ssl, buf, total_bytes-bytes);
                }
                else{
                    CcspTraceError(("%s:%d ssl session is null\n",__FUNCTION__,__LINE__));
                    fclose(fptr);
                    free(buf);
	            free(req);
                    return FT_ERROR;
                }
#else
                bytes = read( conn_info->conn , buf, total_bytes-bytes);
#endif
                CcspTraceInfo(("bytes transfered : %d\n",bytes));
                if(bytes > 0){
                    fwrite(buf,1,bytes,fptr);
                    length+=bytes;
                }
                else{
                    CcspTraceError(("(%s:%d) Data encryption failed (Err: %d)\n", __FUNCTION__, __LINE__,bytes));
                }
            }
            if(buf){
                free(buf);
            }
        }
        fclose(fptr);
        free(req);
        return FT_SUCCESS;
    }
    else
    {
        CcspTraceError(("%s:%d payload is null\n",__FUNCTION__, __LINE__));
    }
    return FT_ERROR;
}

int IDM_Incoming_Response_handler(payload_t * payload)
{
    rbusMethodAsyncHandle_t async_callBack_handler;
    rbusError_t ret = RBUS_ERROR_SUCCESS;
    CcspTraceInfo(("%s:%d operation - %d req id %d \n",__FUNCTION__, __LINE__,payload->operation, payload->reqID));
    /* find req entry in LL */
    if(payload->operation == IDM_SUBS)
    {
        sendSubscriptionList *subsReq = headsendSubscriptionList;
        while(subsReq != NULL)
        {
            if (payload->reqID == subsReq->reqId)
            {
                //TODO: Subscription call back is handled by DM_REMOTE_DEVICE_INVOKE publish event. Call back not required
                async_callBack_handler = subsReq->resCb;
                break;
            }
            subsReq = subsReq->next;
        }

    }else
    {
        sendReqList *req;
        req = IDM_getFromSendRequestList(payload->reqID);
        if(req == NULL)
        {
            if(payload->operation != IDM_REQUEST) /* Async device info update. */
                return -1; //Entry not found. may be timed out.
        }else{
            async_callBack_handler = req->resCb;
            free(req);
        }
    }
    //call the responce callback API
    if(payload->operation == IDM_REQUEST)
    {
        if (Capabilities_get_cb((IDM_REMOTE_DEVICE_INFO *)payload->param_value, payload->status,payload->Mac_source) != 0)
        {
            return -1;
        }
    }else
    {
        rbusObject_t outParams;
        rbusValue_t value;
        rbusError_t err= RBUS_ERROR_SUCCESS;

        rbusObject_Init(&outParams, NULL);

        /*set DM Value */
        rbusValue_Init(&value);
        rbusValue_SetString(value, payload->param_value);
        rbusObject_SetValue(outParams, "param_value", value);
        rbusValue_Release(value);

        /*set source mac */
        rbusValue_Init(&value);
        rbusValue_SetString(value, payload->Mac_source);
        rbusObject_SetValue(outParams, "Mac_source", value);
        rbusValue_Release(value);

        /*set DM Name */
        rbusValue_Init(&value);
        rbusValue_SetString(value, payload->param_name);
        rbusObject_SetValue(outParams, "param_name", value);
        rbusValue_Release(value);

        /*set OPeration type */
        rbusValue_Init(&value);
        rbusValue_SetInt32(value, payload->operation);
        rbusObject_SetValue(outParams, "operation", value);
        rbusValue_Release(value);

        if(payload->operation == IDM_SUBS)
        {
            rbusEvent_t event = {0};
            event.name = DM_REMOTE_DEVICE_INVOKE;
            event.data = outParams;
            event.type = RBUS_EVENT_GENERAL;

            CcspTraceInfo(("%s sending rbus Subcription responce using RM_REMOTE_INVOKE publish\n", __FUNCTION__));
            err = rbusEvent_Publish(rbusHandle, &event);
            if(err != RBUS_ERROR_SUCCESS)
            {
                CcspTraceInfo(("%s rbusEvent_Publish failed err:%d\n", __FUNCTION__, err));
            }

        }else
        {
            if(payload->status == ANSC_STATUS_SUCCESS)
            {
                err = rbusMethod_SendAsyncResponse(async_callBack_handler, RBUS_ERROR_SUCCESS, outParams);
                if(err != RBUS_ERROR_SUCCESS)
                {
                    CcspTraceInfo(("%s rbusMethod_SendAsyncResponse failed err:%d\n", __FUNCTION__, err));
                }
            }else
            {
                err = rbusMethod_SendAsyncResponse(async_callBack_handler, RBUS_ERROR_BUS_ERROR, outParams);
                if(err != RBUS_ERROR_SUCCESS)
                {
                    CcspTraceInfo(("%s rbusMethod_SendAsyncResponse failed err:%d\n", __FUNCTION__, err));
                }
            }
        }
        rbusObject_Release(outParams);
    }

    return 0;
}

void IDM_addToReceivedReqList( RecvReqList *newReq)
{
    if(!headRecvReqList)
    {
        headRecvReqList  = newReq;
    }else
    {
        RecvReqList *temp = headRecvReqList;
        while (temp->next != NULL)
        {
            temp = temp->next;
        }
        temp->next = newReq;
    }
}

RecvReqList* IDM_ReceivedReqList_pop()
{
    if(!headRecvReqList)
    {
        return NULL;
    }
    /* return Head. Memory should be freed in calling funtion */
    RecvReqList *temp = headRecvReqList;
    headRecvReqList = headRecvReqList->next;
    return temp;
}

static void IDM_Rbus_subscriptionEventHandler(rbusHandle_t handle, rbusEvent_t const* event, rbusEventSubscription_t* subscription)
{
    (void)handle;
    (void)subscription;

    const char* eventName = event->name;
    rbusValue_t valBuff = rbusObject_GetValue(event->data, NULL );

    if((valBuff == NULL) || (eventName == NULL))
    {
        CcspTraceError(("%s : FAILED , value is NULL\n",__FUNCTION__));
        return;
    }

    PIDM_DML_INFO pidmDmlInfo = IdmMgr_GetConfigData_locked();
    if( pidmDmlInfo == NULL )
    {
        return;
    }

    RecvSubscriptionList *req = headRecvSubscriptionList;

    while(req != NULL)
    {
        if (strcmp(eventName, req->param_name) == 0)
        {
            IDM_REMOTE_DEVICE_LINK_INFO *remoteDevice = pidmDmlInfo->stRemoteInfo.pstDeviceLink;
            payload_t payload;
            memset(&payload, 0, sizeof(payload_t));
            payload.operation = IDM_SUBS;
            payload.msgType = RES;
            payload.reqID = req->reqId;
            strncpy(payload.Mac_source,remoteDevice->stRemoteDeviceInfo.MAC, sizeof(payload.Mac_source)-1);
            strncpy(payload.param_name,req->param_name,sizeof(payload.param_name)-1);
            //Convert rbus value to string.
            rbusValue_ToString(valBuff,payload.param_value, sizeof(payload.param_value)-1);
            payload.status =  ANSC_STATUS_SUCCESS;

            while(remoteDevice!=NULL)
            {
                if(strcasecmp(remoteDevice->stRemoteDeviceInfo.MAC, req->Mac_dest) == 0)
                {
                    if(remoteDevice->stRemoteDeviceInfo.conn_info.conn !=0)
                        send_remote_message(&remoteDevice->stRemoteDeviceInfo.conn_info, &payload);
                    break;
                }
                remoteDevice=remoteDevice->next;
            }

        }
        req = req->next;
    }
    IdmMgrDml_GetConfigData_release(pidmDmlInfo);
}
char* IDM_SFT_receive(connection_info_t* conn_info,void* payload)
{
    CcspTraceDebug(("Inside %s:%d\n",__FUNCTION__,__LINE__));
    char* buf;
    int bytes=0,length=0,total_bytes=0;
#ifndef IDM_DEBUG
    SSL* ssl= NULL;
#else
    int conn=0;
#endif
    payload_t *Data;
    PIDM_DML_INFO pidmDmlInfo = IdmMgr_GetConfigData_locked();
    if( pidmDmlInfo == NULL )
    {
        CcspTraceError(("%s:%d DmlInfo is NULL\n",__FUNCTION__,__LINE__));
        return  FT_ERROR;
    }
    Data = (payload_t*)payload;
    if(Data != NULL)
    {
        Data->operation = SFT_RES;
        IDM_REMOTE_DEVICE_LINK_INFO *remoteDevice = pidmDmlInfo->stRemoteInfo.pstDeviceLink;
        total_bytes=Data->file_length;
        CcspTraceDebug(("%s file with size total_bytes=%d file length=%d param_value=%s\n",Data->param_name,total_bytes,Data->file_length,Data->param_value));
        while(remoteDevice!=NULL)
        {
            if(strcasecmp(remoteDevice->stRemoteDeviceInfo.MAC,Data->Mac_source) == 0 && (remoteDevice->stRemoteDeviceInfo.Status == DEVICE_CONNECTED ))
            {
#ifndef IDM_DEBUG
                if(remoteDevice->stRemoteDeviceInfo.conn_info.enc.ssl != NULL)
                {
                    ssl = remoteDevice->stRemoteDeviceInfo.conn_info.enc.ssl;
                }
#else
                if(remoteDevice->stRemoteDeviceInfo.conn_info.conn != 0)
                {
                    conn = remoteDevice->stRemoteDeviceInfo.conn_info.conn;
                }
#endif
            }
            remoteDevice=remoteDevice->next;
        }
        if(total_bytes > (pidmDmlInfo->stRemoteInfo.max_file_size))
        {
            CcspTraceError(("%s:%d total_bytes is greater than configured max file size = %d\n",__FUNCTION__,__LINE__,pidmDmlInfo->stRemoteInfo.max_file_size));
            strncpy_s(Data->param_value,sizeof(Data->param_value),FT_INVALID_FILE_SIZE,strlen(FT_INVALID_FILE_SIZE));
            CcspTraceDebug(("%s:%d Data->operation=%d Data->param_value=%s \n",__FUNCTION__,__LINE__,Data->operation,Data->param_value));
#ifndef IDM_DEBUG
            if(ssl != NULL)
            {
                if(bytes = (SSL_write(ssl,Data,sizeof(payload_t))) <= 0 )
#else
                    if(bytes = (send(conn,Data,sizeof(payload_t),0)) <= 0 )
#endif
                    {
                        CcspTraceError(("%s:%d file size information not exchanged to peer device\n",__FUNCTION__,__LINE__));
                        IdmMgrDml_GetConfigData_release(pidmDmlInfo);
                        return FT_ERROR;
                    }
                CcspTraceInfo(("%s:%d \n",__FUNCTION__,__LINE__));
#ifndef IDM_DEBUG
            }
            else
            {
                CcspTraceError(("%s:%d ssl value is null\n",__FUNCTION__,__LINE__));
                IdmMgrDml_GetConfigData_release(pidmDmlInfo);
                return FT_ERROR;
            }
#endif
            IdmMgrDml_GetConfigData_release(pidmDmlInfo);
            CcspTraceInfo(("%s:%d \n",__FUNCTION__,__LINE__));
            return FT_INVALID_FILE_SIZE;
        }
        IdmMgrDml_GetConfigData_release(pidmDmlInfo);
        FILE* fptr;
        fptr = fopen(Data->param_name,"wb");
        if(!fptr){
            CcspTraceError(("file not found\n"));
            int rc = -1,ind = -1,invalid_dst=0;
            char* tok = strtok(Data->param_name,"/");
            rc = strcmp_s(FT_NVRAM,strlen(FT_NVRAM),tok,&ind);
            ERR_CHK(rc);
            if((!ind) && (rc == EOK))
            {
                invalid_dst = 1;
            }
            rc = strcmp_s(FT_TMP,strlen(FT_TMP),tok,&ind);
            ERR_CHK(rc);
            if((!ind) && (rc == EOK))
            {
                invalid_dst = 1;
            }
            if(invalid_dst == 1)
            {
                strncpy_s(Data->param_value,sizeof(Data->param_value),FT_INVALID_DST_PATH,strlen(FT_INVALID_DST_PATH));
                CcspTraceDebug(("%s:%d Data->operation=%d Data->param_value%s\n",__FUNCTION__,__LINE__,Data->operation,Data->param_value));
#ifndef IDM_DEBUG
                if(ssl != NULL)
                {
                    SSL_write(ssl,Data,sizeof(payload_t));
                }
#else
                send(conn,Data,sizeof(payload_t),0);
#endif
                return FT_INVALID_DST_PATH;
            }
#ifndef IDM_DEBUG
            strncpy_s(Data->param_value,sizeof(Data->param_value),FT_NOT_WRITABLE_PATH,strlen(FT_NOT_WRITABLE_PATH));            
            CcspTraceDebug(("%s:%d Data->operation=%d Data->param_value%s\n",__FUNCTION__,__LINE__,Data->operation,Data->param_value));
            if(ssl != NULL)
            {
                SSL_write(ssl,Data,sizeof(payload_t));
            }
#else
            send(conn,Data,sizeof(payload_t),0);
#endif
            return FT_NOT_WRITABLE_PATH;
        }
        else
        {
            buf = (char*) malloc(total_bytes);
            if(buf == NULL)
            {
                fclose(fptr);
                CcspTraceError(("malloc failed to allocate memory\n"));
                return FT_ERROR;
            }
            while(length<total_bytes){
#ifndef IDM_DEBUG
                if(conn_info->enc.ssl != NULL){
                    bytes = SSL_read(conn_info->enc.ssl, buf, total_bytes-bytes);
                }
                else{
                    CcspTraceError(("%s:%d ssl session is null\n",__FUNCTION__,__LINE__));
                    fclose(fptr);
                    if(buf){
                        free(buf);
                    }
                    return FT_ERROR;
                }
#else
                bytes = read( conn_info->conn , buf, total_bytes-bytes);
#endif
                CcspTraceInfo(("bytes transfered : %d\n",bytes));
                if(bytes > 0){
                    fwrite(buf,1,bytes,fptr);
                    length+=bytes;
                }
                else{
                    CcspTraceError(("(%s:%d) Data encryption failed (Err: %d)\n", __FUNCTION__, __LINE__,bytes));
                }
            }
            if(buf){
                free(buf);
            }
            fclose(fptr);
        }
    }
    else
    {
        CcspTraceError(("%s:%d Data is null\n",__FUNCTION__, __LINE__));
        IdmMgrDml_GetConfigData_release(pidmDmlInfo);
        return FT_ERROR;
    }
    return FT_SUCCESS;
}

int IDM_Incoming_Request_handler(payload_t * payload)
{
    CcspTraceInfo(("%s %d - \n", __FUNCTION__, __LINE__));
    rbusError_t err= RBUS_ERROR_SUCCESS;

    if(payload->operation == IDM_SUBS)
    {
        /*Create entry in incoming subscription list */
        RecvSubscriptionList *getReq =  malloc(sizeof(RecvSubscriptionList));
        if (getReq != NULL) {
            memset(getReq, 0, sizeof(RecvSubscriptionList));
            strncpy(getReq->Mac_dest, payload->Mac_source,sizeof(getReq->Mac_dest)-1);
            strncpy(getReq->param_name, payload->param_name,sizeof(getReq->param_name)-1);
            getReq->reqId = payload->reqID;
            IDM_addToReceivedSubscriptionList(getReq);
	}
        //TODO: check timeout and userdata
        err = rbusEvent_Subscribe(rbusHandle, payload->param_name, IDM_Rbus_subscriptionEventHandler, NULL, 0);
        if(err != RBUS_ERROR_SUCCESS)
        {
            CcspTraceInfo(("%s rbusEvent_Publish failed err:%d\n", __FUNCTION__, err));
        }
    }else
    {
        /*Create entry in incoming req list */
        RecvReqList *getReq = malloc(sizeof(RecvReqList));
        if (getReq != NULL) {
            memset(getReq, 0, sizeof(RecvReqList));
            getReq->reqId = payload->reqID;
            getReq->operation = payload->operation;
            getReq->timeout = payload->timeout;
            getReq->type = payload->type;
            getReq->file_length = payload->file_length;
            strncpy(getReq->Mac_dest, payload->Mac_source,sizeof(getReq->Mac_dest)-1);
            strncpy(getReq->param_name, payload->param_name,sizeof(getReq->param_name)-1);
            strncpy(getReq->param_value, payload->param_value,sizeof(getReq->param_value)-1);
            getReq->next = NULL;
            IDM_addToReceivedReqList(getReq);
	}
    }
    return 0;
}

void *IDM_Incoming_req_handler_thread()
{
    // event handler
    int n = 0;
    struct timeval tv;
    errno_t ec = -1;
    char *get_status = NULL;

    PIDM_DML_INFO pidmDmlInfo = NULL;
    while(true)
    {
        /* Wait up to 250 milliseconds */
        tv.tv_sec = 0;
        tv.tv_usec = 250000;

        n = select(0, NULL, NULL, NULL, &tv);
        if (n < 0)
        {
            /* interrupted by signal or something, continue */
            continue;
        }
        RecvReqList *ReqEntry = IDM_ReceivedReqList_pop();
        if(ReqEntry!= NULL)
        {
            payload_t payload;
            memset(&payload, 0, sizeof(payload_t));

            CcspTraceInfo(("%s %d -processing request from %s \n \tparamName %s \n", __FUNCTION__, __LINE__,ReqEntry->Mac_dest, ReqEntry->param_name));
            /* Rbus get implementation */
            if(ReqEntry->operation == GET)
            {
                rbusValue_t value;
                int rc = RBUS_ERROR_SUCCESS;
                if((rc = rbus_get(rbusHandle, ReqEntry->param_name, &value)) == RBUS_ERROR_SUCCESS)
                {
                    rbusValue_ToString(value,payload.param_value, (sizeof(payload.param_value)-1));
                    CcspTraceInfo(("%s %d - payload.param_value %s \n", __FUNCTION__, __LINE__,payload.param_value));
                    rbusValue_Release(value);
                    payload.status = ANSC_STATUS_SUCCESS;
                }else
                {
                    CcspTraceError(("%s %d - get  %s failed \n", __FUNCTION__, __LINE__,ReqEntry->param_name));
                    payload.status = ANSC_STATUS_FAILURE;
                }
            }else if(ReqEntry->operation == SET)
            {
                CcspTraceInfo(("%s %d -Processing Set request from %s paramName %s paramValue %s\n", __FUNCTION__, __LINE__,ReqEntry->Mac_dest, ReqEntry->param_name,ReqEntry->param_value));
                rbusValue_t value;
                rbusValueType_t type;
                int rc = RBUS_ERROR_SUCCESS;
                rbusSetOptions_t opts;

                type  = IDM_rbusValueChange_GetDataType(ReqEntry->type);
                opts.commit = true;
                rbusValue_Init(&value);
                rbusValue_SetFromString(value, type, ReqEntry->param_value);

                if((rc = rbus_set(rbusHandle, ReqEntry->param_name, value, &opts)) == RBUS_ERROR_SUCCESS)
                {
                    payload.status = ANSC_STATUS_SUCCESS;
                    CcspTraceInfo(("%s-%d  set %s Successful\n",__FUNCTION__,__LINE__,ReqEntry->param_name));
                }else
                {
                    CcspTraceError(("%s-%d Failed to set %s\n",__FUNCTION__,__LINE__,ReqEntry->param_name));
                    payload.status = ANSC_STATUS_FAILURE;
                }
                rbusValue_Release(value);
            }else if(ReqEntry->operation == IDM_REQUEST)
            {
                CcspTraceInfo(("%s %d -Processing IDM_REQUEST request from %s \n", __FUNCTION__, __LINE__,ReqEntry->Mac_dest));

                pidmDmlInfo = IdmMgr_GetConfigData_locked();
                if( pidmDmlInfo == NULL )
                {
                    payload.status =  ANSC_STATUS_FAILURE;
                }
                /*get local deivce struct */
                memcpy(payload.param_value, &(pidmDmlInfo->stRemoteInfo.pstDeviceLink->stRemoteDeviceInfo),sizeof(IDM_REMOTE_DEVICE_INFO));
                payload.status =  ANSC_STATUS_SUCCESS;
                IdmMgrDml_GetConfigData_release(pidmDmlInfo);

            }else if(ReqEntry->operation == GFT)
            {
                pidmDmlInfo = IdmMgr_GetConfigData_locked();
                if( pidmDmlInfo == NULL )
                {
                    ec = strcpy_s(pidmDmlInfo->stRemoteInfo.ft_status,FT_STATUS_SIZE,FT_ERROR);
                    ERR_CHK(ec);
	            if(ec == EOK)
                    {
                        Idm_PublishDmEvent("Device.X_RDK_Remote.FileTransferStatus()",pidmDmlInfo->stRemoteInfo.ft_status);
                    }
                }
                IDM_REMOTE_DEVICE_LINK_INFO *remoteDevice = pidmDmlInfo->stRemoteInfo.pstDeviceLink;
                payload.reqID = ReqEntry->reqId;
                payload.operation = ReqEntry->operation;
                payload.msgType = GFT;
                strncpy(payload.Mac_source,remoteDevice->stRemoteDeviceInfo.MAC,MAC_ADDR_SIZE);
                strncpy(payload.param_name,ReqEntry->param_name,sizeof(payload.param_name));
                //Find the device using MAC
                while(remoteDevice!=NULL)
                {
                    CcspTraceDebug(("Inside %s:%d remote device MAC=%s\n",__FUNCTION__,__LINE__,remoteDevice->stRemoteDeviceInfo.MAC));
                    if(strcasecmp(remoteDevice->stRemoteDeviceInfo.MAC, ReqEntry->Mac_dest) == 0 && (remoteDevice->stRemoteDeviceInfo.Status == DEVICE_CONNECTED ))
                    {
                        if(remoteDevice->stRemoteDeviceInfo.conn_info.conn !=0)
                        {
                            get_status = getFile_to_remote(&remoteDevice->stRemoteDeviceInfo.conn_info, &payload);
                            if(get_status)
                            {
                                ec = strcpy_s(pidmDmlInfo->stRemoteInfo.ft_status,FT_STATUS_SIZE, get_status);
                                ERR_CHK(ec);
	                        if(ec == EOK)
                                {
                                    Idm_PublishDmEvent("Device.X_RDK_Remote.FileTransferStatus()",pidmDmlInfo->stRemoteInfo.ft_status);
                                }
                            }
                        }
                        break;
                    }
                    remoteDevice=remoteDevice->next;
                }
                IdmMgrDml_GetConfigData_release(pidmDmlInfo);
                free(ReqEntry);
                pidmDmlInfo = NULL;
                continue;
            }

            //create payload
            pidmDmlInfo = IdmMgr_GetConfigData_locked();
            if( pidmDmlInfo == NULL )
            {
                free(ReqEntry);
                return NULL;
            }
            IDM_REMOTE_DEVICE_LINK_INFO *remoteDevice = pidmDmlInfo->stRemoteInfo.pstDeviceLink;
            payload.reqID = ReqEntry->reqId;
            payload.operation = ReqEntry->operation;
            payload.msgType = RES;
            /* Update local device mac */
            strncpy(payload.Mac_source,remoteDevice->stRemoteDeviceInfo.MAC, sizeof(payload.Mac_source)-1);
            strncpy(payload.param_name,ReqEntry->param_name,sizeof(payload.param_name)-1);
            //Find the device using mac
            while(remoteDevice!=NULL)
            {
                if(strcasecmp(remoteDevice->stRemoteDeviceInfo.MAC, ReqEntry->Mac_dest) == 0)
                {
                    if(remoteDevice->stRemoteDeviceInfo.conn_info.conn !=0)
                        send_remote_message(&remoteDevice->stRemoteDeviceInfo.conn_info, &payload);
                    break;
                }
                remoteDevice=remoteDevice->next;
            }

            IdmMgrDml_GetConfigData_release(pidmDmlInfo);
            free(ReqEntry);
        }
    }
    return NULL;
}


void IDM_Broadcast_LocalDeviceInfo()
{
    PIDM_DML_INFO pidmDmlInfo = NULL;
    /*Create Payload */
    payload_t payload;
    memset(&payload, 0, sizeof(payload_t));

    pidmDmlInfo = IdmMgr_GetConfigData_locked();
    if( pidmDmlInfo == NULL )
    {
        payload.status =  ANSC_STATUS_FAILURE;
        return;
    }
    IDM_REMOTE_DEVICE_LINK_INFO *remoteDevice = pidmDmlInfo->stRemoteInfo.pstDeviceLink;
    /*get local deivce struct */
    memcpy(payload.param_value, &(pidmDmlInfo->stRemoteInfo.pstDeviceLink->stRemoteDeviceInfo),sizeof(IDM_REMOTE_DEVICE_INFO));
    payload.status =  ANSC_STATUS_SUCCESS;

    payload.reqID = -1; //It's an Async message reqID not avaiable.
    payload.operation = IDM_REQUEST;
    payload.msgType = RES;
    strncpy(payload.Mac_source,remoteDevice->stRemoteDeviceInfo.MAC,sizeof(payload.Mac_source)-1);

    remoteDevice=remoteDevice->next; 
    while(remoteDevice!=NULL)
    {
        if(remoteDevice->stRemoteDeviceInfo.Status == DEVICE_CONNECTED)
        {
            if(remoteDevice->stRemoteDeviceInfo.conn_info.conn !=0)
                send_remote_message(&remoteDevice->stRemoteDeviceInfo.conn_info, &payload);
        }
        remoteDevice=remoteDevice->next;
    }
    IdmMgrDml_GetConfigData_release(pidmDmlInfo);
}

