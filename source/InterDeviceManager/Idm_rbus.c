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

#include "Idm_rbus.h"
#include "Idm_msg_process.h"
#include "Idm_data.h"
#include "Idm_utils.h"
#include "Idm_call_back_apis.h"

#define CONN_HC_ELEMENTS   4
#define CONN_METHOD_ELEMENTS   3
#define RM_NEW_DEVICE_FOUND "Device.X_RDK_Remote.DeviceChange"
#define  ARRAY_SZ(x) (sizeof(x) / sizeof((x)[0]))

#define DM_CONN_HELLO_INTERVAL "Device.X_RDK_Connection.HelloInterval"
#define DM_CONN_HELLO_IPV4SUBNET_LIST "Device.X_RDK_Connection.HelloIPv4SubnetList"
#define DM_CONN_HELLO_IPV6SUBNET_LIST "Device.X_RDK_Connection.HelloIPv6SubnetList"
#define DM_CONN_DETECTION_WINDOW "Device.X_RDK_Connection.DetectionWindow"
#define DM_CONN_INTF "Device.X_RDK_Connection.Interface"
#define DM_CONN_PORT "Device.X_RDK_Connection.Port"

// table parameters
#define DM_REMOTE_DEVICE_TABLE "Device.X_RDK_Remote.Device" 
#define DM_REMOTE_DEVICE "Device.X_RDK_Remote.Device.{i}."
#define DM_REMOTE_DEVICE_STATUS "Device.X_RDK_Remote.Device.{i}.Status"
#define DM_REMOTE_DEVICE_MAC "Device.X_RDK_Remote.Device.{i}.MAC"
#define DM_REMOTE_DEVICE_HELLO_INTERVAL "Device.X_RDK_Remote.Device.{i}.HelloInterval"
#define DM_REMOTE_DEVICE_IPV4 "Device.X_RDK_Remote.Device.{i}.IPv4"
#define DM_REMOTE_DEVICE_IPV6 "Device.X_RDK_Remote.Device.{i}.IPv6"
#define DM_REMOTE_DEVICE_CAP "Device.X_RDK_Remote.Device.{i}.Capabilities"
#define DM_REMOTE_DEVICE_MODEL_NUM "Device.X_RDK_Remote.Device.{i}.ModelNumber"

#define DM_REMOTE_DEVICE_ADD_CAP "Device.X_RDK_Remote.AddDeviceCapabilities()"
#define DM_REMOTE_DEVICE_REM_CAP "Device.X_RDK_Remote.RemoveDeviceCapabilities()"
#define DM_REMOTE_DEVICE_RESET_CAP "Device.X_RDK_Remote.ResetDeviceCapabilities()"
#define DM_REMOTE_DEVICE_INVOKE "Device.X_RDK_Remote.Invoke()"

#define DM_REMOTE_DEVICE_GET_FILE "Device.X_RDK_Remote.getFile()"
#define DM_REMOTE_DEVICE_SEND_FILE "Device.X_RDK_Remote.sendFile()"
#define DM_REMOTE_DEVICE_FT_SIZE "Device.X_RDK_Remote.FileTransferMaxSize()"
#define DM_REMOTE_DEVICE_FT_STATUS "Device.X_RDK_Remote.FileTransferStatus()"
#define RM_PORT "Device.X_RDK_Remote.Port"
#define IDM_DISCOVERY_RESTART "Device.X_RDK_Connection.Restart()"
#define WIFI_STA_STATUS_NUM_OF_BYTES 4
#define WIFI_STA_PARAM_NAME "Device.WiFi.STA.%d.Connection.Status"
#define WIFI_RADIO_COUNT_PARAM_NAME "Device.WiFi.RadioNumberOfEntries"
#define MESH_ETHBACKHAUL_LINKSTATUS "Device.X_RDK_MeshAgent.EthernetBhaulUplink.Status"

rbusHandle_t        rbusHandle;
char                idmComponentName[32] = "IDM_RBUS";

// Instance for the global structure. This will be allocated and initialised by rbus
IDM_RBUS_SUBS_STATUS sidmRmSubStatus;

/**************************Array declarations for RBUS registrations************************/
rbusDataElement_t idmRmPublishElements[] = {
    {DM_REMOTE_DEVICE, RBUS_ELEMENT_TYPE_TABLE, {NULL, NULL, NULL, NULL, NULL, NULL}},
    {DM_REMOTE_DEVICE_STATUS, RBUS_ELEMENT_TYPE_EVENT | RBUS_ELEMENT_TYPE_PROPERTY, {X_RDK_Remote_Device_GetHandler, NULL, NULL, NULL, idmDmPublishEventHandler, NULL}},
    {DM_REMOTE_DEVICE_MAC, RBUS_ELEMENT_TYPE_EVENT | RBUS_ELEMENT_TYPE_PROPERTY, { X_RDK_Remote_Device_GetHandler, NULL, NULL, NULL, idmDmPublishEventHandler, NULL}},
    {DM_REMOTE_DEVICE_HELLO_INTERVAL, RBUS_ELEMENT_TYPE_EVENT | RBUS_ELEMENT_TYPE_PROPERTY, { X_RDK_Remote_Device_GetHandler, NULL, NULL, NULL, idmDmPublishEventHandler, NULL}},
    {DM_REMOTE_DEVICE_IPV4, RBUS_ELEMENT_TYPE_EVENT | RBUS_ELEMENT_TYPE_PROPERTY, { X_RDK_Remote_Device_GetHandler, NULL, NULL, NULL, idmDmPublishEventHandler, NULL}},
    {DM_REMOTE_DEVICE_IPV6, RBUS_ELEMENT_TYPE_EVENT | RBUS_ELEMENT_TYPE_PROPERTY, { X_RDK_Remote_Device_GetHandler, NULL, NULL, NULL, idmDmPublishEventHandler, NULL}},
    {DM_REMOTE_DEVICE_CAP, RBUS_ELEMENT_TYPE_EVENT | RBUS_ELEMENT_TYPE_PROPERTY, { X_RDK_Remote_Device_GetHandler, NULL, NULL, NULL, idmDmPublishEventHandler, NULL}},
    {DM_REMOTE_DEVICE_MODEL_NUM, RBUS_ELEMENT_TYPE_EVENT | RBUS_ELEMENT_TYPE_PROPERTY, { X_RDK_Remote_Device_GetHandler, NULL, NULL, NULL, idmDmPublishEventHandler, NULL}},
    {RM_NEW_DEVICE_FOUND, RBUS_ELEMENT_TYPE_EVENT, { NULL, NULL, NULL, NULL, idmDmPublishEventHandler, NULL}},
    {RM_NUM_ENTRIES, RBUS_ELEMENT_TYPE_EVENT | RBUS_ELEMENT_TYPE_PROPERTY, { X_RDK_Remote_Device_GetHandler, NULL, NULL, NULL, idmDmPublishEventHandler, NULL}},
    {RM_PORT, RBUS_ELEMENT_TYPE_PROPERTY |RBUS_ELEMENT_TYPE_EVENT, { X_RDK_Remote_Device_GetHandler, X_RDK_Remote_Device_SetHandler, NULL, NULL, idmDmPublishEventHandler, NULL}},
};

//2. local data
rbusDataElement_t idmConnHcElements[] = {
    {DM_CONN_HELLO_INTERVAL, RBUS_ELEMENT_TYPE_PROPERTY, {X_RDK_Connection_GetHandler, X_RDK_Connection_SetHandler, NULL, NULL, NULL, NULL}},
    {DM_CONN_HELLO_IPV4SUBNET_LIST, RBUS_ELEMENT_TYPE_PROPERTY, {X_RDK_Connection_GetHandler, NULL, NULL, NULL, NULL, NULL}},
    {DM_CONN_HELLO_IPV6SUBNET_LIST, RBUS_ELEMENT_TYPE_PROPERTY, {X_RDK_Connection_GetHandler, NULL, NULL, NULL, NULL, NULL}},
    {DM_CONN_DETECTION_WINDOW, RBUS_ELEMENT_TYPE_PROPERTY, {X_RDK_Connection_GetHandler, X_RDK_Connection_SetHandler, NULL, NULL, NULL, NULL}},
    {DM_CONN_INTF, RBUS_ELEMENT_TYPE_PROPERTY | RBUS_ELEMENT_TYPE_EVENT, {X_RDK_Connection_GetHandler, X_RDK_Connection_SetHandler, NULL, NULL, idmDmPublishEventHandler, NULL}},
    {DM_CONN_PORT, RBUS_ELEMENT_TYPE_PROPERTY |RBUS_ELEMENT_TYPE_EVENT , {X_RDK_Connection_GetHandler, X_RDK_Connection_SetHandler, NULL, NULL, idmDmPublishEventHandler, NULL}},
    {DM_REMOTE_DEVICE_FT_SIZE, RBUS_ELEMENT_TYPE_METHOD, {NULL, NULL, NULL, NULL, NULL, X_RDK_Remote_MethodHandler}}
};

//3. Remote cap
rbusDataElement_t idmRmCapElements[] = {
        {DM_REMOTE_DEVICE_ADD_CAP, RBUS_ELEMENT_TYPE_METHOD, {NULL, NULL, NULL, NULL, NULL, X_RDK_Remote_MethodHandler}},
        {DM_REMOTE_DEVICE_REM_CAP, RBUS_ELEMENT_TYPE_METHOD, {NULL, NULL, NULL, NULL, NULL, X_RDK_Remote_MethodHandler}},
        {DM_REMOTE_DEVICE_RESET_CAP, RBUS_ELEMENT_TYPE_METHOD, {NULL, NULL, NULL, NULL, NULL, X_RDK_Remote_MethodHandler}},
        {DM_REMOTE_DEVICE_GET_FILE, RBUS_ELEMENT_TYPE_METHOD, {NULL, NULL, NULL, NULL, NULL, X_RDK_Remote_MethodHandler}},
        {DM_REMOTE_DEVICE_SEND_FILE, RBUS_ELEMENT_TYPE_METHOD, {NULL, NULL, NULL, NULL, NULL, X_RDK_Remote_MethodHandler}},
        {DM_REMOTE_DEVICE_FT_STATUS, RBUS_ELEMENT_TYPE_EVENT | RBUS_ELEMENT_TYPE_METHOD, {NULL, NULL, NULL, NULL, idmDmPublishEventHandler, X_RDK_Remote_MethodHandler}},
        {DM_REMOTE_DEVICE_INVOKE, RBUS_ELEMENT_TYPE_METHOD | RBUS_ELEMENT_TYPE_EVENT, {NULL, NULL, NULL, NULL, NULL, X_RDK_Remote_MethodHandler}},
        {IDM_DISCOVERY_RESTART, RBUS_ELEMENT_TYPE_METHOD, {NULL, NULL, NULL, NULL, NULL, X_RDK_Remote_MethodHandler}},
    };

ANSC_STATUS Idm_Create_Rbus_Obj()
{
    ANSC_STATUS returnStatus   =  ANSC_STATUS_SUCCESS;
    IDM_REMOTE_DEVICE_LINK_INFO *firstNode = NULL;

    PIDM_DML_INFO pidmDmlInfo = IdmMgr_GetConfigData_locked();
    if( pidmDmlInfo == NULL )
    {
        return  ANSC_STATUS_FAILURE;
    }

    // first node
    firstNode = (IDM_REMOTE_DEVICE_LINK_INFO*)AnscAllocateMemory(sizeof(IDM_REMOTE_DEVICE_LINK_INFO));

    if( firstNode == NULL )
    {
        IdmMgrDml_GetConfigData_release(pidmDmlInfo);
        return  ANSC_STATUS_FAILURE;
    }

    AnscZeroMemory(firstNode, (sizeof(IDM_REMOTE_DEVICE_LINK_INFO)));

    firstNode->stRemoteDeviceInfo.Status = DEVICE_CONNECTED;

    // TODO: Get device Mac
    //getDeviceMac(firstNode->MAC);
   
    //fill local data in remote table 
    firstNode->stRemoteDeviceInfo.HelloInterval = pidmDmlInfo->stConnectionInfo.HelloInterval;
    firstNode->stRemoteDeviceInfo.Index = 0;
    if(pidmDmlInfo->stConnectionInfo.HelloIPv4SubnetList[0] != '\0')
        strncpy(firstNode->stRemoteDeviceInfo.IPv4, pidmDmlInfo->stConnectionInfo.HelloIPv4SubnetList,sizeof(firstNode->stRemoteDeviceInfo.IPv4)-1);
    if(pidmDmlInfo->stConnectionInfo.HelloIPv6SubnetList[0] != '\0')
        strncpy(firstNode->stRemoteDeviceInfo.IPv6, pidmDmlInfo->stConnectionInfo.HelloIPv6SubnetList,sizeof(firstNode->stRemoteDeviceInfo.IPv6)-1);

    // TODO: Get device cap
    //getDeviceCap(firstNode->Capabilities);
    pidmDmlInfo->stRemoteInfo.pstDeviceLink = firstNode;
    pidmDmlInfo->stRemoteInfo.pstDeviceLink->next = NULL;

    firstNode->stRemoteDeviceInfo.Index = 1;
    returnStatus = addDevice(firstNode);

    if(returnStatus == ANSC_STATUS_SUCCESS)
    {
        pidmDmlInfo->stRemoteInfo.ulDeviceNumberOfEntries++;
        CcspTraceInfo(("%s %d - Number of entries : %d\n", __FUNCTION__, __LINE__,
                                        pidmDmlInfo->stRemoteInfo.ulDeviceNumberOfEntries));
        
        //Publish number of device entries if it is already subscribed
        if( sidmRmSubStatus.idmRmDeviceNoofEntriesSubscribed )
        {
            CcspTraceInfo(("%s %d Publishing Event for dm '%s' Value '%d'\n",__FUNCTION__,__LINE__,RM_NUM_ENTRIES,pidmDmlInfo->stRemoteInfo.ulDeviceNumberOfEntries));
            Idm_PublishDmEvent(RM_NUM_ENTRIES,&pidmDmlInfo->stRemoteInfo.ulDeviceNumberOfEntries);
        } 
        else
        {
            CcspTraceInfo(("%s %d - %s  not yet subscribed \n", __FUNCTION__, __LINE__, RM_NUM_ENTRIES));
        }

    }
    else
    {
        CcspTraceInfo(("%s %d - Add device failed \n", __FUNCTION__, __LINE__));
    }

    // Register a row for the table such that it will be populated. 
    // This should be repeated whenever we added a new device
    rbusTable_registerRow(rbusHandle, DM_REMOTE_DEVICE_TABLE, 
                        pidmDmlInfo->stRemoteInfo.ulDeviceNumberOfEntries, NULL);

    IdmMgrDml_GetConfigData_release(pidmDmlInfo);
    return  returnStatus;
}

ANSC_STATUS Idm_Rbus_Init()
{
    rbusError_t rc;

    rc = rbus_open(&rbusHandle, idmComponentName);

    if(rc != RBUS_ERROR_SUCCESS)
        return ANSC_STATUS_FAILURE;

     return rc;
}

ANSC_STATUS Idm_Rbus_DM_Init()
{
    rbusError_t rc;
    // 1. Register publish events
    rc = rbus_regDataElements(rbusHandle, ARRAY_SZ(idmRmPublishElements), idmRmPublishElements);

    if(rc != RBUS_ERROR_SUCCESS)
    {
        rbus_close(rbusHandle);
        return ANSC_STATUS_FAILURE;
    }
    CcspTraceInfo(("%s %d - Successfully registered  idmRmPublishElements\n", __FUNCTION__, __LINE__ ));

    // 2. Register local data info
    rc = rbus_regDataElements(rbusHandle, ARRAY_SZ(idmConnHcElements), idmConnHcElements);

    if(rc != RBUS_ERROR_SUCCESS)
    {
        rbus_unregDataElements(rbusHandle, ARRAY_SZ(idmRmPublishElements), idmRmPublishElements);
        rbus_close(rbusHandle);
        return ANSC_STATUS_FAILURE;
    }
    CcspTraceInfo(("%s %d - Successfully registered  idmConnHcElements\n", __FUNCTION__, __LINE__ ));

    // 3. Register remote cap info
    rc = rbus_regDataElements(rbusHandle, ARRAY_SZ(idmRmCapElements), idmRmCapElements);

    if(rc != RBUS_ERROR_SUCCESS)
    {
        rbus_unregDataElements(rbusHandle, ARRAY_SZ(idmRmPublishElements), idmRmPublishElements);
        rbus_unregDataElements(rbusHandle, ARRAY_SZ(idmConnHcElements), idmConnHcElements);
        rbus_close(rbusHandle);
        return ANSC_STATUS_FAILURE;
    }
    CcspTraceInfo(("%s %d - Successfully registered  idmRmCapElements\n", __FUNCTION__, __LINE__ ));

    rc = Idm_Create_Rbus_Obj();
 
    return rc;    
}

//idm manager can call this during idm graceful exit
ANSC_STATUS Idm_RbusExit()
{
    rbus_unregDataElements(rbusHandle, ARRAY_SZ(idmRmPublishElements), idmRmPublishElements);
    rbus_unregDataElements(rbusHandle, ARRAY_SZ(idmConnHcElements), idmConnHcElements);
    rbus_unregDataElements(rbusHandle, ARRAY_SZ(idmRmCapElements), idmRmCapElements);
    rbus_close(rbusHandle);
    return ANSC_STATUS_SUCCESS;
}

rbusError_t idmDmPublishEventHandler(rbusHandle_t handle, rbusEventSubAction_t action, const char* eventName, rbusFilter_t filter, int32_t interval, bool* autoPublish)
{
    char *subscribe_action = NULL;

    CcspTraceInfo(("%s %d - Event %s has been subscribed from subscribed\n", __FUNCTION__, __LINE__,eventName ));
    /* Subscription is NOT supported for below DMs */
    if((strcmp(eventName, RM_PORT) == 0) ||
       (strcmp(eventName, DM_CONN_INTF) == 0) ||
       (strcmp(eventName, DM_CONN_PORT) == 0))
    {
        CcspTraceWarning(("%s %d - Event %s subscribe not allowed\n", __FUNCTION__, __LINE__,eventName ));
        return RBUS_ERROR_ACCESS_NOT_ALLOWED;
    }
    subscribe_action = action == RBUS_EVENT_ACTION_SUBSCRIBE ? "subscribe" : "unsubscribe";
    CcspTraceInfo(("%s %d - action=%s \n", __FUNCTION__, __LINE__, subscribe_action ));
    updteSubscriptionStatus(eventName, &sidmRmSubStatus);
    return RBUS_ERROR_SUCCESS;
}

//IDM manager should call when it has remote device data
ANSC_STATUS Idm_PublishDmEvent(char *dm_event, void *dm_value)
{
    rbusEvent_t event;
    rbusObject_t rdata;
    rbusValue_t value;
    uint32_t timeout = 0; // wait for 2 minutes

    if(dm_event == NULL || dm_value == NULL)
    {
        CcspTraceInfo(("%s %d - Failed publishing\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    rbusValue_Init(&value);
    rbusObject_Init(&rdata, NULL);

    rbusObject_SetValue(rdata, dm_event, value);

    EVENT_DATA_TYPES type = getEventType(dm_event);

    CcspTraceInfo(("%s %d - event type %d\n", __FUNCTION__, __LINE__, type));
    switch(type)
    {
        case EV_BOOLEAN:
            rbusValue_SetBoolean(value, (*(bool*)(dm_value)));
            break;
        case EV_INTEGER:
            rbusValue_SetInt32(value, (*(int*)(dm_value)));
            break;
        case EV_STRING:
            rbusValue_SetString(value, (char*)dm_value);
            break;
        case EV_UNSIGNEDINT:
            rbusValue_SetUInt32(value, (*(unsigned int*)(dm_value)));
            break;
        default:
            CcspTraceInfo(("%s %d - Cannot identify event type %d\n", __FUNCTION__, __LINE__, type));
            rbusValue_Release(value);
            rbusObject_Release(rdata); 
            return ANSC_STATUS_FAILURE;
    }
    event.name = dm_event;
    event.data = rdata;
    event.type = RBUS_EVENT_GENERAL;
    if ((strncmp(dm_event, DM_REMOTE_DEVICE_FT_STATUS, strlen(dm_event)) == 0) && (sidmRmSubStatus.idmRmDeviceFTStatusSubscribed != TRUE))
    {
        // no need to publish FT status if there is no subscribers. This is a success case
        CcspTraceInfo(("%s %d -  no subscribers for %s. Not publishing\n", __FUNCTION__, __LINE__, dm_event));
        rbusValue_Release(value);
        rbusObject_Release(rdata);
        return ANSC_STATUS_SUCCESS;
    }
    if(rbusEvent_Publish(rbusHandle, &event) != RBUS_ERROR_SUCCESS) {
        CcspTraceInfo(("%s %d - event pusblishing failed for type %d\n", __FUNCTION__, __LINE__, type));
        rbusValue_Release(value);
        rbusObject_Release(rdata);
        return ANSC_STATUS_FAILURE;
    }
    CcspTraceInfo(("%s %d - Successfully Pusblished event for event %s \n", __FUNCTION__, __LINE__, dm_event));
    rbusValue_Release(value);
    rbusObject_Release(rdata);

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS Idm_PublishDeviceChangeEvent(IDM_DeviceChangeEvent * pDeviceChangeEvent)
{
    rbusEvent_t event;
    rbusObject_t rdata;
    rbusValue_t value;

    if(pDeviceChangeEvent == NULL || pDeviceChangeEvent->deviceIndex <= 1)
    {
        CcspTraceInfo(("%s %d: Invalid args\n", __FUNCTION__, __LINE__)); 
        return ANSC_STATUS_FAILURE;
    }
    CcspTraceInfo(("%s %d: Enter\n", __FUNCTION__, __LINE__));

    if(sidmRmSubStatus.idmRmNewDeviceSubscribed == FALSE)
    {
        CcspTraceInfo(("%s %d - New device sucbscription wait time excceded.......\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    rbusObject_Init(&rdata, NULL);
    if (pDeviceChangeEvent->capability != NULL)
    {
        rbusValue_Init(&value);
        rbusValue_SetString(value, pDeviceChangeEvent->capability);
        rbusObject_SetValue(rdata, "Capabilities", value);
        rbusValue_Release(value);
    }

    rbusValue_Init(&value);
    rbusValue_SetUInt32(value, pDeviceChangeEvent->deviceIndex);
    rbusObject_SetValue(rdata, "Index", value);
    rbusValue_Release(value);

    /*set source mac */
    rbusValue_Init(&value);
    rbusValue_SetString(value, pDeviceChangeEvent->mac_addr);
    rbusObject_SetValue(rdata, "Mac_addr", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetBoolean(value, pDeviceChangeEvent->available);
    rbusObject_SetValue(rdata, "available", value);
    rbusValue_Release(value);


    event.name = RM_NEW_DEVICE_FOUND;
    event.data = rdata;
    event.type = RBUS_EVENT_GENERAL;

    if (rbusEvent_Publish(rbusHandle, &event) != RBUS_ERROR_SUCCESS) {
        rbusObject_Release(rdata);
        return ANSC_STATUS_FAILURE;
    }
    CcspTraceInfo(("%s %d - Successfully Pusblished new device event RM_NEW_DEVICE_FOUND\n", __FUNCTION__, __LINE__));
    rbusObject_Release(rdata);

    return ANSC_STATUS_SUCCESS;
}

/***********************************************Get handler************************/
rbusError_t X_RDK_Remote_Device_GetHandler(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    char const* name = rbusProperty_GetName(property);
    IDM_REMOTE_DEVICE_LINK_INFO *index_node = NULL;
    rbusValue_t value;
    uint32_t index = 0;

     PIDM_DML_INFO pidmDmlInfo = IdmMgr_GetConfigData_locked();
     if( pidmDmlInfo == NULL )
     {
         return  ANSC_STATUS_FAILURE;
     }

    if(name == NULL)
    {
        CcspTraceInfo(("%s %d - Property get name is NULL\n", __FUNCTION__, __LINE__));
        IdmMgrDml_GetConfigData_release(pidmDmlInfo);
        return RBUS_ERROR_BUS_ERROR;   
    }

    rbusValue_Init(&value);

    if(strstr(name, ".Status"))
    {
        sscanf(name, "Device.X_RDK_Remote.Device.%d.Status", &index);
        // get node from index
        index_node = getRmDeviceNode(pidmDmlInfo, index);
        if(index_node == NULL)
        {
            CcspTraceInfo(("%s %d - index node for %d is NULL\n", __FUNCTION__, __LINE__, index));
            IdmMgrDml_GetConfigData_release(pidmDmlInfo);
            rbusValue_Release(value);
            return RBUS_ERROR_BUS_ERROR;   
        }
        rbusValue_SetUInt32(value, index_node->stRemoteDeviceInfo.Status);
    }
    if(strstr(name, ".HelloInterval"))
    {
        sscanf(name, "Device.X_RDK_Remote.Device.%d.HelloInterval", &index);
        // get node from index
        index_node = getRmDeviceNode(pidmDmlInfo, index);
        if(index_node == NULL)
        {
            CcspTraceInfo(("%s %d - index node for %d is NULL\n", __FUNCTION__, __LINE__, index));
            IdmMgrDml_GetConfigData_release(pidmDmlInfo);
            rbusValue_Release(value);
            return RBUS_ERROR_BUS_ERROR;
        }
        rbusValue_SetUInt32(value, index_node->stRemoteDeviceInfo.HelloInterval);
    }
    if(strstr(name, ".MAC"))
    {
        sscanf(name, "Device.X_RDK_Remote.Device.%d.MAC", &index);
        index_node = getRmDeviceNode(pidmDmlInfo, index);
        if(index_node == NULL)
        {
            CcspTraceInfo(("%s %d - index node for %d is NULL\n", __FUNCTION__, __LINE__, index));
            IdmMgrDml_GetConfigData_release(pidmDmlInfo);
            rbusValue_Release(value);
            return RBUS_ERROR_BUS_ERROR;   
        }
        rbusValue_SetString(value, index_node->stRemoteDeviceInfo.MAC);
    }
    if(strstr(name, ".IPv4"))
    {
        sscanf(name, "Device.X_RDK_Remote.Device.%d.IPv4", &index);
        index_node = getRmDeviceNode(pidmDmlInfo, index);
        if(index_node == NULL)
        {
            CcspTraceInfo(("%s %d - index node for %d is NULL\n", __FUNCTION__, __LINE__, index));
            IdmMgrDml_GetConfigData_release(pidmDmlInfo);
            rbusValue_Release(value);
            return RBUS_ERROR_BUS_ERROR;   
        }
        rbusValue_SetString(value, index_node->stRemoteDeviceInfo.IPv4);
    }
    if(strstr(name, ".IPv6"))
    {
        sscanf(name, "Device.X_RDK_Remote.Device.%d.IPv6", &index);
        index_node = getRmDeviceNode(pidmDmlInfo, index);
        if(index_node == NULL)
        {
            CcspTraceInfo(("%s %d - index node for %d is NULL\n", __FUNCTION__, __LINE__, index));
            IdmMgrDml_GetConfigData_release(pidmDmlInfo);
            rbusValue_Release(value);
            return RBUS_ERROR_BUS_ERROR;   
        }
        rbusValue_SetString(value, index_node->stRemoteDeviceInfo.IPv6);
    }
    if(strstr(name, ".Capabilities"))
    {
        sscanf(name, "Device.X_RDK_Remote.Device.%d.Capabilities", &index);
        index_node = getRmDeviceNode(pidmDmlInfo, index);
        if(index_node == NULL)
        {
            CcspTraceInfo(("%s %d - index node for %d is NULL\n", __FUNCTION__, __LINE__, index));
            IdmMgrDml_GetConfigData_release(pidmDmlInfo);
            rbusValue_Release(value);
            return RBUS_ERROR_BUS_ERROR;   
        }
        rbusValue_SetString(value, index_node->stRemoteDeviceInfo.Capabilities);
    }
    if(strstr(name, ".ModelNumber"))
    {
        sscanf(name, "Device.X_RDK_Remote.Device.%d.ModelNumber", &index);
        index_node = getRmDeviceNode(pidmDmlInfo, index);
        if(index_node == NULL)
        {
            CcspTraceInfo(("%s %d - index node for %d is NULL\n", __FUNCTION__, __LINE__, index));
            IdmMgrDml_GetConfigData_release(pidmDmlInfo);
            rbusValue_Release(value);
            return RBUS_ERROR_BUS_ERROR;   
        }
        rbusValue_SetString(value, index_node->stRemoteDeviceInfo.ModelNumber);
    }

    if(strcmp(name, RM_NUM_ENTRIES) == 0)
    {
        if(pidmDmlInfo == NULL)
        {
            CcspTraceInfo(("%s %d - Failed to get number of entries\n", __FUNCTION__, __LINE__));
            IdmMgrDml_GetConfigData_release(pidmDmlInfo);
            rbusValue_Release(value);
            return RBUS_ERROR_BUS_ERROR;   
        }
        
        rbusValue_SetUInt32(value, pidmDmlInfo->stRemoteInfo.ulDeviceNumberOfEntries);
        CcspTraceInfo(("%s %d - Number of entries:%d\n", __FUNCTION__, __LINE__, 
                            pidmDmlInfo->stRemoteInfo.ulDeviceNumberOfEntries));
    }
    else if (strcmp(name, RM_PORT) == 0)
    {
        if(pidmDmlInfo == NULL)
        {
            CcspTraceInfo(("%s %d - Failed to get remote port\n", __FUNCTION__, __LINE__));
            IdmMgrDml_GetConfigData_release(pidmDmlInfo);
            rbusValue_Release(value);
            return RBUS_ERROR_BUS_ERROR;
        }

        rbusValue_SetUInt32(value, pidmDmlInfo->stRemoteInfo.Port);
        CcspTraceInfo(("%s %d - Port :%d\n", __FUNCTION__, __LINE__,
                            pidmDmlInfo->stRemoteInfo.Port));
    }

    rbusProperty_SetValue(property, value);

    rbusValue_Release(value);
    IdmMgrDml_GetConfigData_release(pidmDmlInfo);

    return RBUS_ERROR_SUCCESS;
}

/****************************************Cap handler**********************************/
rbusError_t X_RDK_Remote_MethodHandler(rbusHandle_t handle, char const* methodName, rbusObject_t inParams, rbusObject_t outParams, rbusMethodAsyncHandle_t asyncHandle)
{
    IDM_REMOTE_DEVICE_LINK_INFO* indexNode = NULL;
    PIDM_DML_INFO pidmDmlInfo = IdmMgr_GetConfigData_locked();
    errno_t rc = -1;
    if( pidmDmlInfo == NULL )
    {
        return  ANSC_STATUS_FAILURE;
    }

    if(strcmp(methodName, "Device.X_RDK_Remote.AddDeviceCapabilities()") == 0)
    {
        char *str = NULL;
        uint32_t len = 0;

        rbusValue_t value = rbusObject_GetValue(inParams, NULL );

        str = (char *)rbusValue_GetString(value, &len);

        indexNode = getRmDeviceNode(pidmDmlInfo, 1);
        
        if(!indexNode || (!str) || 
                (sizeof(indexNode->stRemoteDeviceInfo.Capabilities) < (strlen(indexNode->stRemoteDeviceInfo.Capabilities) + strlen(str) + 2)))
        {
            IdmMgrDml_GetConfigData_release(pidmDmlInfo);
            return RBUS_ERROR_BUS_ERROR;
        }
        CcspTraceInfo(("%s %d - Device.X_RDK_Remote.AddDeviceCapabilities() - %s \n", __FUNCTION__, __LINE__, str));

        CcspTraceInfo(("%s %d - PSM capabilities before addition: %s  \n", __FUNCTION__, __LINE__,pidmDmlInfo->stConnectionInfo.Capabilities));

        CcspTraceInfo(("%s %d - Local device capabilities before addition: %s  \n", __FUNCTION__, __LINE__,indexNode->stRemoteDeviceInfo.Capabilities));

        if(strlen(indexNode->stRemoteDeviceInfo.Capabilities) == 0)
        {
            CcspTraceInfo(("%s %d - local device capabilities is empty \n", __FUNCTION__, __LINE__));
            if(strlen(pidmDmlInfo->stConnectionInfo.Capabilities) > 0)
            {
                CcspTraceInfo(("%s %d - Updating local device capabilities from PSM %s  \n", __FUNCTION__, __LINE__));
                rc = strcpy_s(indexNode->stRemoteDeviceInfo.Capabilities, sizeof(indexNode->stRemoteDeviceInfo.Capabilities), pidmDmlInfo->stConnectionInfo.Capabilities);
	        ERR_CHK(rc);
            }
            else
            {
                // PSM data structre is also empty. Read it from factory and update local device cap
                IdmMgr_GetFactoryDefaultValue(PSM_DEVICE_CAPABILITIES, pidmDmlInfo->stConnectionInfo.Capabilities);
                CcspTraceInfo(("%s %d - Updating local device capabilities from factory PSM: %s  \n", __FUNCTION__, __LINE__));
                rc = strcpy_s(indexNode->stRemoteDeviceInfo.Capabilities, sizeof(indexNode->stRemoteDeviceInfo.Capabilities), pidmDmlInfo->stConnectionInfo.Capabilities);
	        ERR_CHK(rc);
            }
        }
        /* Append local device capabilities from rbus value */
        char* token = strtok(str, ",");
        while (token != NULL) 
        {
            if(!strstr(indexNode->stRemoteDeviceInfo.Capabilities, token))
            {
                if (strlen(indexNode->stRemoteDeviceInfo.Capabilities) > 0)
                {
                    rc = strcat_s(indexNode->stRemoteDeviceInfo.Capabilities, sizeof(indexNode->stRemoteDeviceInfo.Capabilities), ",");
		    ERR_CHK(rc);
                }
                rc = strcat_s(indexNode->stRemoteDeviceInfo.Capabilities, sizeof(indexNode->stRemoteDeviceInfo.Capabilities), token);
		ERR_CHK(rc);
            }
            token = strtok(NULL, ",");
        }

        CcspTraceInfo(("%s %d - New local device capabilities after addition: %s  \n", __FUNCTION__, __LINE__,indexNode->stRemoteDeviceInfo.Capabilities));

        CcspTraceInfo(("%s %d - Updating PSM with new local device capabilities: %s  \n", __FUNCTION__, __LINE__,indexNode->stRemoteDeviceInfo.Capabilities));

        rc = strcpy_s(pidmDmlInfo->stConnectionInfo.Capabilities, sizeof(pidmDmlInfo->stConnectionInfo.Capabilities), indexNode->stRemoteDeviceInfo.Capabilities);
	ERR_CHK(rc);
        IdmMgrDml_GetConfigData_release(pidmDmlInfo);
        CcspTraceInfo(("%s %d - Broadcsting local device capabilities \n", __FUNCTION__, __LINE__));
        IDM_Broadcast_LocalDeviceInfo();
        IdmMgr_write_IDM_ParametersToPSM();

        return RBUS_ERROR_SUCCESS;
    }
    else if(strcmp(methodName, "Device.X_RDK_Remote.RemoveDeviceCapabilities()") == 0)
    {
        const char *out = NULL;
        char *capPos = NULL;
        uint32_t len = 0;
        uint32_t source_len = 0;
        char *source = NULL;

        CcspTraceInfo(("%s %d - Device.X_RDK_Remote.RemoveDeviceCapabilities()  \n", __FUNCTION__, __LINE__));

        rbusValue_t value = rbusObject_GetValue(inParams, NULL );
        out = rbusValue_GetString(value, &len);

        indexNode = getRmDeviceNode(pidmDmlInfo, 1);
        
        if(!indexNode || len == 0 || !out)
        {
            IdmMgrDml_GetConfigData_release(pidmDmlInfo);
            return RBUS_ERROR_BUS_ERROR;
        }
        CcspTraceInfo(("%s %d - Device.X_RDK_Remote.RemoveDeviceCapabilities() - %s \n", __FUNCTION__, __LINE__,out));

        CcspTraceInfo(("%s %d - PSM capabilities before removal: %s  \n", __FUNCTION__, __LINE__,pidmDmlInfo->stConnectionInfo.Capabilities));

        CcspTraceInfo(("%s %d - Local device capabilities before removal: %s  \n", __FUNCTION__, __LINE__,indexNode->stRemoteDeviceInfo.Capabilities));

        if(strlen(indexNode->stRemoteDeviceInfo.Capabilities) == 0)
        {
            CcspTraceInfo(("%s %d - local device capabilities is empty \n", __FUNCTION__, __LINE__));
            if(strlen(pidmDmlInfo->stConnectionInfo.Capabilities) > 0)
            {
                CcspTraceInfo(("%s %d - Updating local device capabilities from PSM: %s  \n", __FUNCTION__, __LINE__));
                rc = strcpy_s(indexNode->stRemoteDeviceInfo.Capabilities, sizeof(indexNode->stRemoteDeviceInfo.Capabilities), pidmDmlInfo->stConnectionInfo.Capabilities);
	        ERR_CHK(rc);
            }
            else
            {
                // PSM data structre is also empty. Read it from factory and update local device cap
                IdmMgr_GetFactoryDefaultValue(PSM_DEVICE_CAPABILITIES, pidmDmlInfo->stConnectionInfo.Capabilities);
                CcspTraceInfo(("%s %d - Updating local device capabilities from factory PSM: %s  \n", __FUNCTION__, __LINE__));
                rc = strcpy_s(indexNode->stRemoteDeviceInfo.Capabilities, sizeof(indexNode->stRemoteDeviceInfo.Capabilities), pidmDmlInfo->stConnectionInfo.Capabilities);
	        ERR_CHK(rc);
            }
        }

        /* Remove capability as requested by rbus value */
        char * arr = indexNode->stRemoteDeviceInfo.Capabilities;
        char* token = strtok((char *)out, ",");
        while (token != NULL) 
        {
            capPos = strstr(arr, token);
            if(capPos)
            {
                if (*(capPos + strlen(token)) == '\0')
                {
                    // removing last capability, so set null char
                    *capPos = '\0';
                    if (strlen(arr) > 0)
                    {
                        // removing last ; char
                        *(capPos - 1) = '\0';
                    }
                    // allow to update PSM and broadcast the capabilites after removal
                    break;
                }
                // Copy remaining strings excluding token and comma
                source = capPos + (strlen(token) + 1);
                if(source)
                {
                    source_len = strlen(capPos + (strlen(token) + 1));
                    // To copy data between overlapped memory with size, use memmove
                    // since source is overallped within destination, source_len is always less than dest
                    memmove(capPos, source, source_len);
                    capPos[source_len] = '\0';
                }
            }
            token = strtok(NULL, ",");
        }

        /* Some capabilites might have removed in local device. write back to PSM */
        CcspTraceInfo(("%s %d - New local device capabilities after removal : %s  \n", __FUNCTION__, __LINE__, indexNode->stRemoteDeviceInfo.Capabilities));

        CcspTraceInfo(("%s %d - Updating PSM with new local device capabilities : %s \n", __FUNCTION__, __LINE__, indexNode->stRemoteDeviceInfo.Capabilities));

        rc = strcpy_s(pidmDmlInfo->stConnectionInfo.Capabilities, sizeof(pidmDmlInfo->stConnectionInfo.Capabilities), indexNode->stRemoteDeviceInfo.Capabilities);
	ERR_CHK(rc);
        IdmMgrDml_GetConfigData_release(pidmDmlInfo);
        CcspTraceInfo(("%s %d - Publishing local device info \n", __FUNCTION__, __LINE__));
        IDM_Broadcast_LocalDeviceInfo();
        IdmMgr_write_IDM_ParametersToPSM();
        return RBUS_ERROR_SUCCESS;
    }
    else if(strcmp(methodName, "Device.X_RDK_Remote.ResetDeviceCapabilities()") == 0)
    {
        const char *str = NULL;
        uint32_t len = 0;

        rbusValue_t value = rbusObject_GetValue(inParams, NULL );

        str = rbusValue_GetString(value, &len);

        indexNode = getRmDeviceNode( pidmDmlInfo, 1);

        if(!indexNode)
        {
            IdmMgrDml_GetConfigData_release(pidmDmlInfo);
            return RBUS_ERROR_BUS_ERROR;
        }
        memset(indexNode->stRemoteDeviceInfo.Capabilities, 0, sizeof(indexNode->stRemoteDeviceInfo.Capabilities));
        IdmMgr_GetFactoryDefaultValue(PSM_DEVICE_CAPABILITIES, indexNode->stRemoteDeviceInfo.Capabilities);
        rc = strcpy_s(pidmDmlInfo->stConnectionInfo.Capabilities, sizeof(pidmDmlInfo->stConnectionInfo.Capabilities), indexNode->stRemoteDeviceInfo.Capabilities);
	ERR_CHK(rc);
        IdmMgrDml_GetConfigData_release(pidmDmlInfo);
        IDM_Broadcast_LocalDeviceInfo();
        IdmMgr_write_IDM_ParametersToPSM();
        return RBUS_ERROR_SUCCESS;
    }
    else if(strcmp(methodName, "Device.X_RDK_Remote.Invoke()") == 0)
    {
        CcspTraceInfo(("%s %d - Device.X_RDK_Remote.Invoke() called  \n", __FUNCTION__, __LINE__));
        uint32_t len = 0;
        rbusValue_t value;

        idm_send_msg_Params_t param;
        memset(&param,0,sizeof(param));

        value = rbusObject_GetValue(inParams, "DEST_MAC_ADDR");
        strncpy(param.Mac_dest, rbusValue_GetString(value, NULL),sizeof(param.Mac_dest)-1);
        CcspTraceInfo(("%s %d - param.Mac_dest %s\n", __FUNCTION__, __LINE__,param.Mac_dest));

        value = rbusObject_GetValue(inParams, "paramName");
        strncpy(param.param_name, rbusValue_GetString(value, NULL),sizeof(param.param_name)-1);
        CcspTraceInfo(("%s %d - param.param_name %s\n", __FUNCTION__, __LINE__,param.param_name));

        value = rbusObject_GetValue(inParams, "paramValue");
        strncpy(param.param_value, rbusValue_GetString(value, NULL),sizeof(param.param_value)-1);
        CcspTraceInfo(("%s %d - param.param_value %s\n", __FUNCTION__, __LINE__,param.param_value));

        value = rbusObject_GetValue(inParams, "Timeout");
        param.timeout = rbusValue_GetInt32(value);
        CcspTraceInfo(("%s %d - param. %d\n", __FUNCTION__, __LINE__,param.timeout));

        value = rbusObject_GetValue(inParams, "DataType");
        param.type = rbusValue_GetInt32(value);
        CcspTraceInfo(("%s %d - param. %d\n", __FUNCTION__, __LINE__,param.type));

        value = rbusObject_GetValue(inParams, "Operation");
        param.operation = rbusValue_GetInt32(value);
        CcspTraceInfo(("%s %d - param. %d\n", __FUNCTION__, __LINE__,param.operation));

        //TODO: Check possibility to make subscription request as synchronous call.
        param.resCb = asyncHandle;

        IDM_sendMsg_to_Remote_device(&param);
        IdmMgrDml_GetConfigData_release(pidmDmlInfo);
        return RBUS_ERROR_ASYNC_RESPONSE;
    }
    else if(strcmp(methodName, "Device.X_RDK_Remote.sendFile()") == 0 )
    {
        char *mac_dest = NULL;
        char *filename = NULL;
        char *output_location = NULL;
        rbusValue_t value;

        value = rbusObject_GetValue(inParams, "MacAddr");
        mac_dest = (char*)rbusValue_GetString(value,NULL);

        value = rbusObject_GetValue(inParams, "FileName");
        filename = (char*)rbusValue_GetString(value,NULL);

        value = rbusObject_GetValue(inParams, "OutputFile");
        output_location  = (char*)rbusValue_GetString(value,NULL);

        CcspTraceInfo(("Inside %s:%d dest mac = %s filename = %s output file location = %s\n",__FUNCTION__,__LINE__,mac_dest,filename,output_location));
        IDM_sendFile_to_Remote_device(mac_dest,filename,output_location);
        IdmMgrDml_GetConfigData_release(pidmDmlInfo);
        return RBUS_ERROR_SUCCESS;
    }
    else if(strcmp(methodName, "Device.X_RDK_Remote.getFile()") == 0 )
    {
        char *mac_dest = NULL;
        char *filename = NULL;
        char *output_location = NULL;
        rbusValue_t value;

        value = rbusObject_GetValue(inParams, "MacAddr");
        mac_dest = (char*)rbusValue_GetString(value,NULL);

        value = rbusObject_GetValue(inParams, "FileName");
        filename = (char*)rbusValue_GetString(value,NULL);

        value = rbusObject_GetValue(inParams, "OutputFile");
        output_location  = (char*)rbusValue_GetString(value,NULL);

        CcspTraceInfo(("Inside %s:%d dest mac=%s filename=%s output file location = %s\n",__FUNCTION__,__LINE__,mac_dest,filename,output_location));
        IDM_getFile_from_Remote_device(mac_dest,filename,output_location);
        IdmMgrDml_GetConfigData_release(pidmDmlInfo);
        return RBUS_ERROR_SUCCESS;
    }
    else if(strcmp(methodName,"Device.X_RDK_Remote.FileTransferMaxSize()") == 0 )
    {
        int size_value=0;
        char* type = NULL;
        rbusValue_t value;
        value = rbusObject_GetValue(inParams, "Size");
        size_value = rbusValue_GetInt32(value);

        value = rbusObject_GetValue(inParams,"Type");
        type = (char*)rbusValue_GetString(value,NULL);
        if(strcmp(type,"MB") == 0)
        {
            if(size_value > 1)
            {
                CcspTraceError(("%s:%d max file transfer is only 1 MB. Please reduce the size\n",__FUNCTION__,__LINE__));
                IdmMgrDml_GetConfigData_release(pidmDmlInfo);
                return RBUS_ERROR_INVALID_INPUT;
            }
            size_value = size_value*1000000;
        }
        else if(strcmp(type,"KB") == 0)
        {
            if((size_value*1000) > 1000000)
            {
                CcspTraceError(("%s:%d max file transfer is only 1 MB. Please reduce the size\n",__FUNCTION__,__LINE__));
                IdmMgrDml_GetConfigData_release(pidmDmlInfo);
                return RBUS_ERROR_INVALID_INPUT;
            }
            size_value*=1000;
        }
        else if(strcmp(type,"B") == 0)
        {
            if(size_value > 1000000)
            {
                CcspTraceError(("%s:%d max file transfer is only 1 MB. Please reduce the size\n",__FUNCTION__,__LINE__));
                IdmMgrDml_GetConfigData_release(pidmDmlInfo);
                return RBUS_ERROR_INVALID_INPUT;
            }
        }
        else
        {
            CcspTraceInfo(("%s:%d memory type should be MB/KB/B\n",__FUNCTION__,__LINE__));
            IdmMgrDml_GetConfigData_release(pidmDmlInfo);
            return RBUS_ERROR_INVALID_INPUT;
        }
        pidmDmlInfo->stRemoteInfo.max_file_size  = size_value;
    }
    else if(strcmp(methodName,"Device.X_RDK_Remote.FileTransferStatus()") == 0)
    {
        CcspTraceInfo(("status of last file transfer = %s\n", pidmDmlInfo->stRemoteInfo.ft_status));
    }
    else if(strcmp(methodName, IDM_DISCOVERY_RESTART) == 0 )
    {
        rbusValue_t value;
        bool restart = false;
        bool interface_status = FALSE;
        char interface_name[64] = { 0 };

        value = rbusObject_GetValue(inParams, "Restart");
        restart = (bool)rbusValue_GetBoolean(value);
        if(restart)
        {
            CcspTraceInfo(("Inside %s:%d dest Restarting IDM \n",__FUNCTION__,__LINE__));
            // call upnp restart only if current interface has IP and it is up
            // Release the lock until initerface is up and allow other threads continue
            strncpy(interface_name, pidmDmlInfo->stConnectionInfo.Interface, sizeof(interface_name) -1 );
            IdmMgrDml_GetConfigData_release(pidmDmlInfo);
            interface_status = checkInterfaceStatus(interface_name);
            if(interface_status == TRUE)
            {
                // take the lock and release for updating and restarting upnp 
                CcspTraceInfo(("%s:%d Waiting for lock to restart upnp \n",__FUNCTION__,__LINE__));
                pidmDmlInfo = IdmMgr_GetConfigData_locked();
                if( pidmDmlInfo == NULL )
                {
                    return  ANSC_STATUS_FAILURE;
                }
               
                // upnp restart should be initiated only when IDM is already in a start discovery state
                if(pidmDmlInfo->stConnectionInfo.DiscoveryInProgress == TRUE)
                {
                    CcspTraceInfo(("%s:%d Restarting xupnp \n",__FUNCTION__,__LINE__));
                    IDM_Stop_Device_Discovery();
                }
                // IDM is not in discovery state. Just set the new flag so that IDM will fetch new interface again
                // and restart start discovery 
                else
                {
                    pidmDmlInfo->stConnectionInfo.InterfaceChanged = TRUE;
                }
                IdmMgrDml_GetConfigData_release(pidmDmlInfo);
                return RBUS_ERROR_SUCCESS;
            }
            else
            {
                CcspTraceInfo(("%s:%d Interface does not have IP or not operational \n",__FUNCTION__,__LINE__));
                CcspTraceInfo(("%s:%d Ignoring upnp restart \n",__FUNCTION__,__LINE__));
                return RBUS_ERROR_SUCCESS;
            }
        }
        // if this is not a restart, release lock
        IdmMgrDml_GetConfigData_release(pidmDmlInfo);
        return RBUS_ERROR_SUCCESS;
    }
    else
    {
        IdmMgrDml_GetConfigData_release(pidmDmlInfo);
        return RBUS_ERROR_BUS_ERROR;
    }
    IdmMgrDml_GetConfigData_release(pidmDmlInfo);
    return RBUS_ERROR_SUCCESS;
}

/**************************************Get hanlder for local data*****************************************/
rbusError_t X_RDK_Connection_GetHandler(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    (void)handle;
    (void)opts;
    rbusValue_t value;
    char const* name;

    PIDM_DML_INFO pidmDmlInfo = IdmMgr_GetConfigData_locked();
    if(pidmDmlInfo == NULL)
        return RBUS_ERROR_BUS_ERROR;

    rbusValue_Init(&value);
    name = rbusProperty_GetName(property);

    if(strcmp(name, "Device.X_RDK_Connection.HelloInterval") == 0)
    {
        rbusValue_SetUInt32(value, pidmDmlInfo->stConnectionInfo.HelloInterval);
    }
    else if(strcmp(name, "Device.X_RDK_Connection.HelloIPv4SubnetList") == 0)
    {
        rbusValue_SetString(value, pidmDmlInfo->stConnectionInfo.HelloIPv4SubnetList);
    }
    else if (strcmp(name, "Device.X_RDK_Connection.HelloIPv6SubnetList") == 0)
    {
        rbusValue_SetString(value, pidmDmlInfo->stConnectionInfo.HelloIPv6SubnetList);
    }
    else if (strcmp(name, "Device.X_RDK_Connection.DetectionWindow") == 0)
    {
        rbusValue_SetUInt32(value, pidmDmlInfo->stConnectionInfo.DetectionWindow);
    }
    else if (strcmp(name, "Device.X_RDK_Connection.Interface") == 0)
    {
        rbusValue_SetString(value, pidmDmlInfo->stConnectionInfo.Interface);
    }
    else if (strcmp(name, "Device.X_RDK_Connection.Port") == 0)
    {
        rbusValue_SetUInt32(value, pidmDmlInfo->stConnectionInfo.Port);
    }
    else
    {
        IdmMgrDml_GetConfigData_release(pidmDmlInfo);
        rbusValue_Release(value);
        return RBUS_ERROR_BUS_ERROR;
    }

    rbusProperty_SetValue(property, value);

    rbusValue_Release(value); 
    IdmMgrDml_GetConfigData_release(pidmDmlInfo);

    return RBUS_ERROR_SUCCESS;   

}
/*************************Set hanlder for local data*****************************************/
rbusError_t X_RDK_Connection_SetHandler(rbusHandle_t handle, rbusProperty_t prop, rbusSetHandlerOptions_t* opts)
{
    (void)opts;
    char const* name = rbusProperty_GetName(prop);
    rbusValue_t value = rbusProperty_GetValue(prop);
    rbusValueType_t type = rbusValue_GetType(value);

    PIDM_DML_INFO pidmDmlInfo = IdmMgr_GetConfigData_locked();
    if(pidmDmlInfo == NULL)
        return RBUS_ERROR_BUS_ERROR;

    if(strcmp(name, "Device.X_RDK_Connection.HelloInterval") == 0)
    {
        if (type != RBUS_UINT32)
        {
            IdmMgrDml_GetConfigData_release(pidmDmlInfo);
            return RBUS_ERROR_INVALID_INPUT;
        }

        pidmDmlInfo->stConnectionInfo.HelloInterval = rbusValue_GetUInt32(value);
    }
    if(strcmp(name, "Device.X_RDK_Connection.DetectionWindow") == 0)
    {
        if (type != RBUS_UINT32)
        {
            IdmMgrDml_GetConfigData_release(pidmDmlInfo);
            return RBUS_ERROR_INVALID_INPUT;
        }

        pidmDmlInfo->stConnectionInfo.DetectionWindow = rbusValue_GetUInt32(value);
    }
    if(strcmp(name, "Device.X_RDK_Connection.Interface") == 0)
    {
        if (value) 
        {
            char *InterfaceName = (char *)rbusValue_GetString(value, NULL);
            if((InterfaceName == NULL) || (type != RBUS_STRING))
            {
                IdmMgrDml_GetConfigData_release(pidmDmlInfo);
                CcspTraceInfo(("%s %d - Invalid interface name \n", __FUNCTION__, __LINE__));
                return RBUS_ERROR_INVALID_INPUT;
            }

            if(strlen(InterfaceName) > 0)
            {
                strncpy(pidmDmlInfo->stConnectionInfo.Interface, InterfaceName, sizeof(pidmDmlInfo->stConnectionInfo.Interface) - 1);
                CcspTraceInfo(("%s %d - InterfaceName set in DML: %s\n", __FUNCTION__, __LINE__, pidmDmlInfo->stConnectionInfo.Interface));

            }
            else { 
                CcspTraceInfo(("%s %d - Interface name is empty string\n", __FUNCTION__, __LINE__));
                IdmMgrDml_GetConfigData_release(pidmDmlInfo);
                return RBUS_ERROR_INVALID_INPUT;
            }
        }
        else
        {
            IdmMgrDml_GetConfigData_release(pidmDmlInfo);
            CcspTraceInfo(("%s %d - value is NULL for interface name \n", __FUNCTION__, __LINE__));
            return RBUS_ERROR_INVALID_INPUT;
        }
    }
    if(strcmp(name, "Device.X_RDK_Connection.Port") == 0)
    {
        if (type != RBUS_UINT32)
        {
            IdmMgrDml_GetConfigData_release(pidmDmlInfo);
	    return RBUS_ERROR_INVALID_INPUT;
	}
	pidmDmlInfo->stConnectionInfo.Port = rbusValue_GetUInt32(value);
    }
    IdmMgrDml_GetConfigData_release(pidmDmlInfo);
    IdmMgr_write_IDM_ParametersToPSM();
    return RBUS_ERROR_SUCCESS;
}

rbusError_t X_RDK_Remote_Device_SetHandler(rbusHandle_t handle, rbusProperty_t prop, rbusSetHandlerOptions_t* opts)
{
    (void)opts;
    char const* name = rbusProperty_GetName(prop);
    rbusValue_t value = rbusProperty_GetValue(prop);
    rbusValueType_t type = rbusValue_GetType(value);

    PIDM_DML_INFO pidmDmlInfo = IdmMgr_GetConfigData_locked();
    if(pidmDmlInfo == NULL)
        return RBUS_ERROR_BUS_ERROR;

    if(strcmp(name, "Device.X_RDK_Remote.Port") == 0)
    {
        if (type != RBUS_UINT32)
        {
            IdmMgrDml_GetConfigData_release(pidmDmlInfo);
            CcspTraceInfo(("%s %d - set Device.X_RDK_Remote.Port Failed\n", __FUNCTION__, __LINE__));
            return RBUS_ERROR_INVALID_INPUT;
        }
        pidmDmlInfo->stRemoteInfo.Port = rbusValue_GetUInt32(value);
    }
    CcspTraceInfo(("%s %d - Device.X_RDK_Remote.Port updated to %d\n", __FUNCTION__, __LINE__, pidmDmlInfo->stRemoteInfo.Port));
    IdmMgrDml_GetConfigData_release(pidmDmlInfo);
    IdmMgr_write_IDM_ParametersToPSM();
    return RBUS_ERROR_SUCCESS;
}
unsigned int GetStaStatusFromString(char *pStr)
{
    char sta_status[12] = {0};
    if (!pStr)
        return 0;

    // pStr will have value in this format "020000005A963040CE0C"
    // parse only first 8 character from pStr
    if (strlen(pStr) >= (WIFI_STA_STATUS_NUM_OF_BYTES * 2))
    {
        if(sscanf(pStr,"%08c",sta_status) > 0) {
            return atoi(sta_status);
        }
    }
    return 0;
}

int Idm_UpdateMeshConnectionValue()
{
    int rc = RBUS_ERROR_BUS_ERROR;
    char param_name[128] = {0};
    rbusValue_t value;
    int noOfRadios;
    char* newValue = NULL;
    unsigned int staConnValue = 0;
    wifi_connection_status_t conn_status = wifi_connection_status_disabled;

    snprintf(param_name,sizeof(param_name),"%s",MESH_ETHBACKHAUL_LINKSTATUS);
    if((rc = rbus_get(rbusHandle, param_name, &value)) == RBUS_ERROR_SUCCESS)
    {
        if(rbusValue_GetBoolean(value))
        {
            conn_status = wifi_connection_status_connected;
        }
        else
        {
            memset(param_name,0,sizeof(param_name));
            snprintf(param_name,sizeof(param_name),"%s",WIFI_RADIO_COUNT_PARAM_NAME);
            if((rc = rbus_get(rbusHandle, param_name, &value)) == RBUS_ERROR_SUCCESS)
            {
                newValue = rbusValue_ToString(value, NULL, 0);
                if(newValue == NULL)
                {
                    CcspTraceInfo(("%s : rbusValue_ToString returned NULL \n", __FUNCTION__));
                    return 0;
                }
                noOfRadios = atoi(newValue);
                free(newValue);
                for(int index=1;index<=noOfRadios;index++)
                {
                    memset(param_name,0,sizeof(param_name));
                    snprintf(param_name,sizeof(param_name),WIFI_STA_PARAM_NAME,index);
                    if((rc = rbus_get(rbusHandle, param_name, &value)) == RBUS_ERROR_SUCCESS)
                    {
                        newValue = rbusValue_ToString(value, NULL, 0);
                        if(newValue == NULL)
                        {
                            CcspTraceInfo(("%s : rbusValue_ToString returned NULL \n", __FUNCTION__));
                            return 0;
                        }
                        staConnValue = GetStaStatusFromString(newValue);
                        free(newValue);
                        if(staConnValue == wifi_connection_status_connected)
                        {
                            conn_status = wifi_connection_status_connected;
                            break;
                        }
                    }
                    else {
                        CcspTraceInfo(("%s : rbus_get failed for %s with error code %d \n", __FUNCTION__, param_name, rc));
                    }
                }
            }
            else
            {
                CcspTraceInfo(("%s : rbus_get failed for %s with error code %d \n", __FUNCTION__, param_name, rc));
            }
        }
    }
    else
    {
        CcspTraceInfo(("%s : rbus_get failed for %s with error code %d \n", __FUNCTION__, param_name, rc));
    }

    PIDM_DML_INFO pidmDmlInfo = IdmMgr_GetConfigData_locked();
    if( pidmDmlInfo == NULL )
    {
        return  ANSC_STATUS_FAILURE;
    }
    CcspTraceInfo(("%s : MeshConnectionStatus %d \n", __FUNCTION__, conn_status));
    pidmDmlInfo->stConnectionInfo.MeshConnectionStatus = conn_status;
    IdmMgrDml_GetConfigData_release(pidmDmlInfo);
    return 0;
}
