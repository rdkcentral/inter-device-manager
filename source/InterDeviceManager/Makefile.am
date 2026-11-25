#############################################################################
# If not stated otherwise in this file or this component's LICENSE file the
# following copyright and licenses apply:
#
# Copyright 2022 Sky
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#############################################################################
#############################################################################
#
# Copyright 2021 RDK Management
# Licensed under the Apache License, Version 2.0
#############################################################################
AM_CFLAGS = -D_ANSC_LINUX
AM_CFLAGS += -D_ANSC_USER
AM_LDFLAGS = -lccsp_common
AM_LDFLAGS +=

AM_LDFLAGS += -lulog
AM_CPPFLAGS = -Wall -Werror -Wno-error=format
ACLOCAL_AMFLAGS = -I m4
hardware_platform = i686-linux-gnu
bin_PROGRAMS = interdevicemanager
interdevicemanager_CPPFLAGS = -I$(top_srcdir)/source/TR-181/include                   \
        -I$(top_srcdir)/../hal/include                                                \
        -I$(top_srcdir)/../CcspCommonLibrary/source/cosa/include/                  \
        -I$(top_srcdir)/../CcspCommonLibrary/source/ccsp/components/include/       \
        -I$(top_srcdir)/source/TR-181/middle_layer_src $(CPPFLAGS)                 \
        -I${PKG_CONFIG_SYSROOT_DIR}$(includedir)/rbus

interdevicemanager_DEPENDENCIES= \
    $(EXTRA_DEPENDENCIES) \
    ${top_builddir}/source/TR-181/middle_layer_src/libinterdevicemanager_middle_layer_src.la

interdevicemanager_CFLAGS = $(SYSTEMD_CFLAGS) $(NONROOT_CFLAGS)
interdevicemanager_SOURCES =  inter_device_manager_internal.h inter_device_manager_main.c Idm_mgr.c Idm_utils.c Idm_rbus.c Idm_data.c Idm_call_back_apis.c Idm_TCP_apis.c Idm_msg_process.c
interdevicemanager_LDFLAGS = -lccsp_common -ldl $(SYSTEMD_LDFLAGS) -lrdkloggers -lsyscfg -lrbus -lhal_platform -lupnpidm -lsysevent -lcrypto -lssl -lsecure_wrapper
interdevicemanager_LDADD =  $(interdevicemanager_DEPENDENCIES)
