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

#include "inter_device_manager_internal.h"
#include "inter_device_manager_global.h"
#include "ccsp_trace.h"
#include "ccsp_dm_api.h"
#include "cap.h"
#include <execinfo.h>
#include <stdio.h>
cap_user appcaps;

#define DEBUG_INI_NAME  "/etc/debug.ini"

char g_Subsystem[32]         = {0};
extern char*                                pComponentName;

char g_sslCert[128];
char g_sslKey[128];
char g_sslCA[128];
char g_sslCaDir[128];
#ifdef ENABLE_HW_CERT_USAGE
char g_sslSeCert[128];
char g_sslPassCodeFile[128];
char g_sslSeCA[128];
#endif

extern ANSC_STATUS Idm_Init();
extern int syscfg_init();

#ifdef INCLUDE_BREAKPAD 
void breakpad_ExceptionHandler(void);
#endif

#if defined(_ANSC_LINUX)
static void daemonize(void)
{
    int fd;
    switch (fork()) {
        case 0:
            break;
        case -1:
            // Error
            CcspTraceInfo(("Error demonizing (fork)! %d - %s\n", errno, strerror(
                            errno)));
            exit(0);
            break;
        default:
            _exit(0);
    }

    if (setsid() < 0)
    {
        CcspTraceInfo(("Error demonizing (setsid)! %d - %s\n", errno, strerror(errno)));
        exit(0);
    }

#ifndef  _DEBUG
    fd = open("/dev/null", O_RDONLY);
    if (fd != 0) {
        dup2(fd, 0);
        close(fd);
    }
    fd = open("/dev/null", O_WRONLY);
    if (fd != 1) {
        dup2(fd, 1);
        close(fd);
    }
    fd = open("/dev/null", O_WRONLY);
    if (fd != 2) {
        dup2(fd, 2);
        close(fd);
    }
#endif
}

static void _print_stack_backtrace(void)
{
#ifdef __GNUC__
#ifndef _BUILD_ANDROID
        void* tracePtrs[100];
        char** funcNames = NULL;
        int i, count = 0;

        count = backtrace( tracePtrs, 100 );
        backtrace_symbols_fd( tracePtrs, count, 2 );

        funcNames = backtrace_symbols( tracePtrs, count );

        if ( funcNames ) {
            // Print the stack trace
            for( i = 0; i < count; i++ )
                printf("%s\n", funcNames[i] );

            // Free the string pointers
            free( funcNames );
        }
#endif
#endif
}
#endif

void sig_handler(int sig)
{
    if ( sig == SIGINT )
    {
        signal(SIGINT, sig_handler); /* reset it to this function */
        CcspTraceInfo(("SIGINT received!\n"));
        exit(0);
    }
    else if ( sig == SIGUSR1 )
    {
        signal(SIGUSR1, sig_handler); /* reset it to this function */
        CcspTraceInfo(("SIGUSR1 received!\n"));
    }
    else if ( sig == SIGUSR2 )
    {
        CcspTraceInfo(("SIGUSR2 received!\n"));
    }
    else if ( sig == SIGCHLD )
    {
        signal(SIGCHLD, sig_handler); /* reset it to this function */
        CcspTraceInfo(("SIGCHLD received!\n"));
    }
    else if ( sig == SIGPIPE )
    {
        signal(SIGPIPE, sig_handler); /* reset it to this function */
        CcspTraceInfo(("SIGPIPE received!\n"));
    }
    else if ( sig == SIGALRM )
    {
        signal(SIGALRM, sig_handler); /* reset it to this function */
        CcspTraceInfo(("SIGALRM received!\n"));
    }
    else
    {
        /* get stack trace first */
        _print_stack_backtrace();
        CcspTraceInfo(("Signal %d received, exiting!\n", sig));
        exit(0);
    }

}

int main(int argc, char* argv[])
{
    BOOL                bRunAsDaemon = TRUE;
    int                 idx = 0;
    int                 ind = -1;
    int                 cmdChar = 0;
    char                *subSys = NULL;
    appcaps.caps = NULL;
    appcaps.user_name = NULL;

#ifdef FEATURE_SUPPORT_RDKLOG
    RDK_LOGGER_INIT();
#endif
    CcspTraceInfo(("NonRoot feature is enabled, dropping root privileges for RdkInterDeviceManager Process\n"));
    init_capability();
    drop_root_caps(&appcaps);
    update_process_caps(&appcaps);
    read_capability(&appcaps);

    printf("Test coverity workflow: %s\n");

    for(idx = 1; idx < argc; idx++)
    {
        if((strcmp(argv[idx], "-subsys") == 0))
        {
            if((idx + 1) < argc)
            {
                if (strlen(argv[idx+1]) > 0)
                {
                    snprintf(g_Subsystem, sizeof(g_Subsystem), "%s", argv[idx+1]);
                }
            }
            else
            {
                CcspTraceError(("parameter after -subsys is missing"));
            }
        }
        else if ( strcmp(argv[idx], "-c") == 0 )
        {
            bRunAsDaemon = FALSE;
        }
        else if(idx == 1)
        {
            if (strlen(argv[idx]) > 0)
            {
                strncpy(g_sslCert, argv[idx], sizeof(g_sslCert) - 1);
                CcspTraceInfo(("SSL Cert file :%s\n", g_sslCert));
            }
        }
        else if(idx == 2)
        {
            if (strlen(argv[idx]) > 0)
            {
                strncpy(g_sslKey, argv[idx], sizeof(g_sslKey) - 1);
                CcspTraceInfo(("SSL Key file :%s\n", g_sslKey));
            }
        }
        else if(idx == 3)
        {
            if (strlen(argv[idx]) > 0)
            {
                strncpy(g_sslCA, argv[idx], sizeof(g_sslCA) - 1);
                CcspTraceInfo(("SSL CA file :%s\n", g_sslCA));
            }
        }
        else if(idx == 4)
        {
            if (strlen(argv[idx]) > 0)
            {
                strncpy(g_sslCaDir, argv[idx], sizeof(g_sslCaDir) - 1);
                CcspTraceInfo(("SSL CA dir :%s\n", g_sslCaDir));
            }
        }
#ifdef ENABLE_HW_CERT_USAGE
        else if(idx == 5)
        {
            if (strlen(argv[idx]) > 0)
            {
                strncpy(g_sslSeCert, argv[idx], sizeof(g_sslSeCert) - 1);
                CcspTraceInfo(("SSL SE cert file copied\n"));
            }
        }
        else if(idx == 6)
        {
            if (strlen(argv[idx]) > 0)
            {
                strncpy(g_sslPassCodeFile, argv[idx], sizeof(g_sslPassCodeFile) - 1);
                CcspTraceInfo(("SSL passcode file copied\n"));
            }
        }
        else if(idx == 7)
        {
            if (strlen(argv[idx]) > 0)
            {
                strncpy(g_sslSeCA, argv[idx], sizeof(g_sslSeCA) - 1);
                CcspTraceInfo(("SSL CA file file copied\n"));
            }
        }
#endif
    }
    pComponentName          = RDK_COMPONENT_NAME_INTER_DEVICE_MANAGER;

#if defined(_ANSC_LINUX)

    if ( bRunAsDaemon )
        daemonize();

   CcspTraceInfo(("\nAfter daemonize before signal\n"));

#ifdef INCLUDE_BREAKPAD
    breakpad_ExceptionHandler();
#else
    signal(SIGTERM, sig_handler);
    signal(SIGINT, sig_handler);
    /*signal(SIGCHLD, sig_handler);*/
    signal(SIGUSR1, sig_handler);
    signal(SIGUSR2, sig_handler);

    signal(SIGSEGV, sig_handler);
    signal(SIGBUS, sig_handler);
    signal(SIGKILL, sig_handler);
    signal(SIGFPE, sig_handler);
    signal(SIGILL, sig_handler);
    signal(SIGQUIT, sig_handler);
    signal(SIGHUP, sig_handler);
#endif

    system("touch /tmp/interdevicemanager_initialized");

    if(ANSC_STATUS_FAILURE == Idm_Init())
    {
        CcspTraceError(("%s %d IDM Initiliasation Failed \n", __FUNCTION__,__LINE__));
    }

    if ( bRunAsDaemon )
    {
        while(1)
        {
            sleep(30);
        }
    }

#endif

    CcspTraceInfo(("\nExiting the main function\n"));
    return 0;

}
