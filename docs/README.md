# Inter Device Manager

## Overview

Inter Device Manager (`inter-device-manager`) is an RDK-B software component that discovers other RDK devices on the local network, establishes secure connections with them, and exchanges data and files between them.

It exposes the TR-181 data model subtree `Device.X_RDK_Remote.*` and `Device.X_RDK_Connection.*` to the platform over rbus, and communicates with remote devices over UDP discovery and TLS-secured TCP connections.

Inter Device Manager runs as a background daemon process and is responsible for:

- Initialising the rbus component and registering its data model elements.
- Discovering remote devices on a configured interface using periodic hello messages.
- Maintaining a list of remote devices and their status (`NOT_DETECTED`, `DETECTED`, `AUTHENTICATED`, `CONNECTED`).
- Sending and receiving request, response, subscription, and file-transfer messages with remote devices.
- Persisting its configuration parameters through the PSM (Persistent Storage Manager).

---

## Features

- TR-181 data model exposure (`Device.X_RDK_Remote.*`, `Device.X_RDK_Connection.*`) over rbus.
- UDP-based device discovery with a configurable hello interval and detection window.
- TCP server and client connections secured with OpenSSL (TLS), unless built with `IDM_DEBUG`.
- Request/response messaging with `GET`, `SET`, subscription, and request operations.
- File transfer (`sendFile`, `getFile`) with a configurable maximum file size.
- Optional hardware-backed certificate loading through a secure element (`ENABLE_HW_CERT_USAGE`).
- Optional systemd build flag (`--enable-notify`, which sets `ENABLE_SD_NOTIFY`; no repository source reads it) and Google Breakpad crash reporting (`INCLUDE_BREAKPAD`).

---

## Build Instructions

### Prerequisites

- RDK-B build environment.
- Autotools (`autoconf`, `automake`, `libtool`).
- OpenSSL (`SSL_CTX_new`, `SSL_connect`, and related calls are used in `Idm_TCP_apis.c`).
- rbus client library (`rbus_open`, `rbus_regDataElements`, and related calls are used in `Idm_rbus.c`).
- PSM and CCSP common libraries used by `Idm_data.c` and `Idm_utils.c`.
- systemd (`-lsystemd`) only when configured with `--enable-notify`.

### Build Process

The component uses autotools. From the repository root:

```bash
autoreconf -i
./configure --with-ccsp-arch=<arch> --with-ccsp-platform=<platform>
make
make install
```

Supported `--with-ccsp-arch` values are `arm`, `atom`, `pc`, and `mips`. Supported `--with-ccsp-platform` values are `intel_usg`, `pc`, and `bcm`. See [configuration-guide.md](configuration-guide.md) for all configure options.

---

## Documentation

### Architecture

- [architecture/component-diagram.md](architecture/component-diagram.md)

### Components

- [components/main-and-init.md](components/main-and-init.md)
- [components/data-model-layer.md](components/data-model-layer.md)
- [components/discovery-and-transport.md](components/discovery-and-transport.md)
- [components/message-processing.md](components/message-processing.md)

### Configuration

- [configuration-guide.md](configuration-guide.md)

---

## Directory Structure

```text
inter-device-manager/
├── docs/                                   # Component documentation
│   ├── architecture/
│   │   └── component-diagram.md
│   ├── components/
│   │   ├── data-model-layer.md
│   │   ├── discovery-and-transport.md
│   │   ├── main-and-init.md
│   │   └── message-processing.md
│   ├── configuration-guide.md
│   └── README.md
│
├── source/
│   ├── Makefile.am
│   │
│   ├── InterDeviceManager/                 # Core Inter Device Manager component
│   │   ├── Idm_call_back_apis.c            # Discovery callbacks and discovery threads
│   │   ├── Idm_call_back_apis.h
│   │   ├── Idm_data.c                      # Configuration data, PSM access, defaults
│   │   ├── Idm_data.h
│   │   ├── Idm_mgr.c                       # Idm_Init()
│   │   ├── Idm_msg_process.c               # Message processing and file transfer
│   │   ├── Idm_msg_process.h
│   │   ├── Idm_rbus.c                      # rbus registration and data model handlers
│   │   ├── Idm_rbus.h
│   │   ├── Idm_TCP_apis.c                  # TCP server, TLS, and client connections
│   │   ├── Idm_TCP_apis.h
│   │   ├── Idm_utils.c                     # sysevent, ARP lookup, certificates, helpers
│   │   ├── Idm_utils.h
│   │   ├── inter_device_manager_global.h
│   │   ├── inter_device_manager_internal.h
│   │   ├── inter_device_manager_main.c     # Process entry point
│   │   └── Makefile.am
│   │
│   ├── TR-181/                             # Autotools wiring for the TR-181 layer
│   │   ├── Makefile.am
│   │   └── middle_layer_src/
│   │       └── Makefile.am
│   │
│   └── test/                               # gtest-based unit tests
│       ├── gtest_main.cpp
│       ├── Makefile.am
│       └── RdkInterDeviceManagerTest.cpp
│
├── systemd_units/
│   ├── RdkInterDeviceManager.service       # systemd unit
│   └── ssl.conf                            # Certificate environment variables
│
├── configure.ac
├── CONTRIBUTING.md
├── COPYING
├── LICENSE
├── Makefile.am
├── NOTICE
└── README.md
```

---

## Quick Start

### Building the Component

```bash
autoreconf -i
./configure --with-ccsp-arch=<arch> --with-ccsp-platform=<platform>
make
```

### Configuration

The systemd unit loads certificate paths from `/etc/idm/ssl.conf`. The repository copy is [systemd_units/ssl.conf](../systemd_units/ssl.conf). Defaults are applied to the PSM keys listed in the [configuration guide](configuration-guide.md).

### Key Interfaces

| Interface                        | Purpose                                                  | Notes                                                                 |
| -------------------------------- | -------------------------------------------------------- | --------------------------------------------------------------------- |
| rbus                             | Data model access (`Device.X_RDK_Remote.*`, `Device.X_RDK_Connection.*`) | Component name `IDM_RBUS` (`idmComponentName` in `Idm_rbus.c`)        |
| PSM (through rbus methods)       | Persistent configuration storage                         | Keys under `dmsb.interdevicemanager.*`                                |
| UDP discovery                    | Hello messages to find remote devices                    | Interface, interval, and window from configuration                    |
| TCP with TLS                     | Messaging, subscriptions, and file transfer with peers   | Messaging port from configuration (default 4444, see configuration guide) |
| Factory defaults XML             | Initial default values                                   | `/usr/ccsp/config/bbhm_def_cfg.xml`                                   |

---

For system architecture, component internals, and data flow details, see [architecture/component-diagram.md](architecture/component-diagram.md).
