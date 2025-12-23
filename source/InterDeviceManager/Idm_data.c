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

#include "Idm_data.h"

#define DEFAULT_SUBNET_LIST "255.255.255.0"
#define DEFAULT_HELLO_INTERVAL 10000 /* 10000 msec */
#define DEFAULT_DETECTION_WINDOW 30000 /* 30000 msec */
#define DEFAULT_BC_INTF "br403"
#define DEFAULT_PSM_FILE "/usr/ccsp/config/bbhm_def_cfg.xml"
#define IDM_DEFAULT_DEVICE_BROADCAST_PORT 50765 //TODO: port no TBD
#define IDM_DEVICE_MESSAGING_PORT 4444 //TODO: port no TBD
#define DEFAULT_MAX_FT_SIZE 512000 /* 512 KB */

IDMMGR_CONFIG_DATA gpidmDmlInfo;

static int IdmMgr_get_IDM_ParametersFromPSM()
{
    int retPsmGet = CCSP_SUCCESS;
    char param_value[256];
    char param_name[512];

    PIDM_DML_INFO pidmDmlInfo = IdmMgr_GetConfigData_locked();
    _ansc_memset(param_name, 0, sizeof(param_name));
    _ansc_memset(param_value, 0, sizeof(param_value));
    _ansc_sprintf(param_name, PSM_DEVICE_CAPABILITIES);

    retPsmGet = IDM_RdkBus_GetParamValuesFromDB(param_name,param_value,sizeof(param_value));

    CcspTraceInfo(("%s %d - Capabilities initial value from PSM  %s \n", __FUNCTION__, __LINE__ , param_value));

    if (retPsmGet == CCSP_SUCCESS)
    {
        AnscCopyString(pidmDmlInfo->stConnectionInfo.Capabilities, param_value);
    }

    _ansc_memset(param_name, 0, sizeof(param_name));
    _ansc_memset(param_value, 0, sizeof(param_value));
    _ansc_sprintf(param_name, PSM_BROADCAST_INTERFACE_NAME);

    retPsmGet = IDM_RdkBus_GetParamValuesFromDB(param_name,param_value,sizeof(param_value));

    if (retPsmGet == CCSP_SUCCESS)
    {
        AnscCopyString(pidmDmlInfo->stConnectionInfo.Interface, param_value);
    }

    _ansc_memset(param_name, 0, sizeof(param_name));
    _ansc_memset(param_value, 0, sizeof(param_value));
    _ansc_sprintf(param_name, PSM_DEVICE_HELLO_INTERVAL);

    retPsmGet = IDM_RdkBus_GetParamValuesFromDB(param_name,param_value,sizeof(param_value));

    if (retPsmGet == CCSP_SUCCESS)
    {
        _ansc_sscanf(param_value, "%d", &(pidmDmlInfo->stConnectionInfo.HelloInterval));
    }

    _ansc_memset(param_name, 0, sizeof(param_name));
    _ansc_memset(param_value, 0, sizeof(param_value));
    _ansc_sprintf(param_name, PSM_DEVICE_DETECION_WINDOW);

    retPsmGet = IDM_RdkBus_GetParamValuesFromDB(param_name,param_value,sizeof(param_value));

    if (retPsmGet == CCSP_SUCCESS)
    {
        _ansc_sscanf(param_value, "%d", &(pidmDmlInfo->stConnectionInfo.DetectionWindow));
    }

    _ansc_memset(param_name, 0, sizeof(param_name));
    _ansc_memset(param_value, 0, sizeof(param_value));
    _ansc_sprintf(param_name, PSM_DEVICE_PORT);

    retPsmGet = IDM_RdkBus_GetParamValuesFromDB(param_name,param_value,sizeof(param_value));

    if (retPsmGet == CCSP_SUCCESS)
    {
        _ansc_sscanf(param_value, "%d", &(pidmDmlInfo->stConnectionInfo.Port));
    }

    _ansc_memset(param_name, 0, sizeof(param_name));
    _ansc_memset(param_value, 0, sizeof(param_value));
    _ansc_sprintf(param_name, PSM_DEVICE_REMOTE_PORT);

    retPsmGet = IDM_RdkBus_GetParamValuesFromDB(param_name,param_value,sizeof(param_value));

    if (retPsmGet == CCSP_SUCCESS)
    {
        _ansc_sscanf(param_value, "%d", &(pidmDmlInfo->stRemoteInfo.Port));
    }

    IdmMgrDml_GetConfigData_release(pidmDmlInfo);

    return retPsmGet;
}

int IdmMgr_write_IDM_ParametersToPSM()
{
    int retPsmGet = CCSP_SUCCESS;
    char param_value[256];
    char param_name[512];

    PIDM_DML_INFO pidmDmlInfo = IdmMgr_GetConfigData_locked();

    _ansc_memset(param_name, 0, sizeof(param_name));
    _ansc_memset(param_value, 0, sizeof(param_value));
    _ansc_sprintf(param_name, PSM_DEVICE_CAPABILITIES);
    _ansc_sprintf(param_value, pidmDmlInfo->stConnectionInfo.Capabilities);
    CcspTraceInfo(("%s %d - Setting %s with value %s \n", __FUNCTION__, __LINE__ ,PSM_DEVICE_CAPABILITIES, pidmDmlInfo->stConnectionInfo.Capabilities));
    retPsmGet = IDM_RdkBus_SetParamValuesToDB(param_name,param_value);

    _ansc_memset(param_name, 0, sizeof(param_name));
    _ansc_memset(param_value, 0, sizeof(param_value));
    _ansc_sprintf(param_name, PSM_BROADCAST_INTERFACE_NAME);
    _ansc_sprintf(param_value, pidmDmlInfo->stConnectionInfo.Interface);
    retPsmGet = IDM_RdkBus_SetParamValuesToDB(param_name,param_value);

    _ansc_memset(param_name, 0, sizeof(param_name));
    _ansc_memset(param_value, 0, sizeof(param_value));
    _ansc_sprintf(param_name, PSM_DEVICE_HELLO_INTERVAL);
    _ansc_sprintf(param_value, "%d", pidmDmlInfo->stConnectionInfo.HelloInterval);
    retPsmGet = IDM_RdkBus_SetParamValuesToDB(param_name,param_value);


    _ansc_memset(param_name, 0, sizeof(param_name));
    _ansc_memset(param_value, 0, sizeof(param_value));
    _ansc_sprintf(param_name, PSM_DEVICE_DETECION_WINDOW);
    _ansc_sprintf(param_value, "%d", pidmDmlInfo->stConnectionInfo.DetectionWindow);
    retPsmGet = IDM_RdkBus_SetParamValuesToDB(param_name,param_value);


    _ansc_memset(param_name, 0, sizeof(param_name));
    _ansc_memset(param_value, 0, sizeof(param_value));
    _ansc_sprintf(param_name, PSM_DEVICE_PORT);
    _ansc_sprintf(param_value, "%d", pidmDmlInfo->stConnectionInfo.Port);
    retPsmGet = IDM_RdkBus_SetParamValuesToDB(param_name,param_value);

    _ansc_memset(param_name, 0, sizeof(param_name));
    _ansc_memset(param_value, 0, sizeof(param_value));
    _ansc_sprintf(param_name, PSM_DEVICE_REMOTE_PORT);
    _ansc_sprintf(param_value, "%d", pidmDmlInfo->stRemoteInfo.Port);
    retPsmGet = IDM_RdkBus_SetParamValuesToDB(param_name,param_value);

    IdmMgrDml_GetConfigData_release(pidmDmlInfo);

    return retPsmGet;
}

PIDM_DML_INFO IdmMgr_GetConfigData_locked(void)
{
    //lock
    if(pthread_mutex_lock(&(gpidmDmlInfo.mDataMutex)) == 0)
    {
        return gpidmDmlInfo.pidmDmlInfo;
    }

    return NULL;
}

void IdmMgrDml_GetConfigData_release(PIDM_DML_INFO pidmDmlInfo)
{

    if(pidmDmlInfo != NULL)
    {
        pthread_mutex_unlock (&(gpidmDmlInfo.mDataMutex));
    }
}

void IdmMgr_SetConfigData_Default()
{
    PIDM_DML_INFO pidmDmlInfo = gpidmDmlInfo.pidmDmlInfo;

    if(pidmDmlInfo != NULL)
    { 
        CcspTraceInfo(("%s %d - Setting default value\n", __FUNCTION__, __LINE__ ));
        AnscZeroMemory(pidmDmlInfo, (sizeof(IDM_DML_INFO)));
        pidmDmlInfo->stConnectionInfo.HelloInterval = DEFAULT_HELLO_INTERVAL;

        strncpy(pidmDmlInfo->stConnectionInfo.Interface, DEFAULT_BC_INTF, sizeof(pidmDmlInfo->stConnectionInfo.Interface));
        pidmDmlInfo->stConnectionInfo.DetectionWindow = DEFAULT_DETECTION_WINDOW;
        pidmDmlInfo->stConnectionInfo.Port = IDM_DEFAULT_DEVICE_BROADCAST_PORT;
        pidmDmlInfo->stConnectionInfo.DiscoveryInProgress = FALSE;
        pidmDmlInfo->stConnectionInfo.InterfaceChanged = FALSE;
        // Initially the remote table will have a single entry with local device info
        pidmDmlInfo->stRemoteInfo.ulDeviceNumberOfEntries = 0;
        pidmDmlInfo->stRemoteInfo.Port = IDM_DEVICE_MESSAGING_PORT;
        pidmDmlInfo->stRemoteInfo.max_file_size = DEFAULT_MAX_FT_SIZE;
        AnscCopyString(pidmDmlInfo->stRemoteInfo.ft_status,FT_SUCCESS);
    }

}

ANSC_STATUS IdmMgr_Data_Init(void)
{
    pthread_mutexattr_t     muttex_attr;

    //Initialise mutex attributes
    pthread_mutexattr_init(&muttex_attr);
    pthread_mutexattr_settype(&muttex_attr, PTHREAD_MUTEX_RECURSIVE);

    /*** IDMMGR_CONFIG_DATA ***/
    gpidmDmlInfo.pidmDmlInfo = NULL;
    gpidmDmlInfo.pidmDmlInfo = (PIDM_DML_INFO)AnscAllocateMemory(sizeof(IDM_DML_INFO));

    IdmMgr_SetConfigData_Default();
    CcspTraceInfo(("%s %d: Calling IdmMgr_get_IDM_ParametersFromPSM\n", __FUNCTION__, __LINE__));
    IdmMgr_get_IDM_ParametersFromPSM();
    pthread_mutex_init(&(gpidmDmlInfo.mDataMutex), &(muttex_attr));
    return ANSC_STATUS_SUCCESS;
}

/* IdmMgr_GetFactoryDefaultValue()
 * This function Reads factory default value from PSM DB.
 * Returns ANSC_STATUS_SUCCESS on successful read.
 */
ANSC_STATUS IdmMgr_GetFactoryDefaultValue(const char * param_name,char * param_value)
{

    FILE * fp = NULL;
    uint32_t len = 0;
    char *line = NULL;

    if ((param_name == NULL))
    {
        CcspTraceError(("%s %d: Invalid args\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    fp = fopen(DEFAULT_PSM_FILE, "r");
    if (fp == NULL)
    {
        CcspTraceError(("%s %d: unable to open file %s", __FUNCTION__, __LINE__, strerror(errno)));
        return ANSC_STATUS_FAILURE;
    }

    while (getline(&line, &len, fp) != -1)
    {
        if(strstr(line, param_name) != NULL)
        {
            // PSM entry stored as <Record name="dmsb.interdevicemanager.Capabilities" type="astr">Gateway</Record>
            sscanf (line,"%*[^>]>%[^<]%*[^\n]", param_value);
            break;
        }
    }
    if (line)
    {
        free(line);
    }
    fclose (fp);

    return ANSC_STATUS_SUCCESS;
}
