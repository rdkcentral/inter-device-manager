# Inter Device Manager Configuration Guide

## Overview

This guide describes how to configure Inter Device Manager on a platform. It covers build options, the systemd service, certificate configuration, the PSM-backed connection parameters, and the default values used by the component.

---

## Platform Integration Guide

### Step 1: Build the Component

Configure the build with the target architecture and platform:

```bash
./configure --with-ccsp-arch=<arch> --with-ccsp-platform=<platform> [options]
make
make install
```

Build options are listed in [Build Options](#build-options).

### Step 2: Install the Certificate Environment File

The systemd unit reads certificate variables from `/etc/idm/ssl.conf`. The repository provides a template at [systemd_units/ssl.conf](../systemd_units/ssl.conf):

```text
IDM_CERT_FILE=/tmp/idm_xpki_cert
IDM_KEY_FILE=/tmp/idm_xpki_key
IDM_CA_FILE=/tmp/idm_UPnP_CA
IDM_CA_DIR=/etc/cert/
```

These values are passed as the first four arguments of the daemon. The certificate and key files at the `/tmp` paths must exist before the service starts. The repository does not create them.

### Step 3: Install the Systemd Unit

Install [RdkInterDeviceManager.service](../systemd_units/RdkInterDeviceManager.service). Key settings:

| Setting            | Value                                                                                                   |
| ------------------ | ------------------------------------------------------------------------------------------------------- |
| `Type`             | `forking`                                                                                               |
| `After`            | `PsmSsp.service`, `CcspCrSsp.service`, `rbus.service`, `network-online.target`, `rdkssainit.service`, `utopia.service` |
| `Requires`         | `apparmor.service`                                                                                      |
| `EnvironmentFile`  | `/etc/device.properties`, `/etc/idm/ssl.conf`                                                           |
| `ExecStart`        | `/usr/bin/interdevicemanager ${IDM_CERT_FILE} ${IDM_KEY_FILE} ${IDM_CA_FILE} ${IDM_CA_DIR} -subsys eRT.` |
| `WorkingDirectory` | `/usr/rdk/interdevicemanager`                                                                           |
| `Restart`          | `on-failure`                                                                                            |

The `-subsys eRT.` argument is stored in `g_Subsystem`.

### Step 4: Verify Startup

Before calling `Idm_Init()`, the daemon creates the marker file `/tmp/interdevicemanager_initialized`. Its presence indicates that `main()` reached the initialisation step.

```bash
ls -l /tmp/interdevicemanager_initialized
systemctl status RdkInterDeviceManager
```

---

## Command-Line Arguments

| Position / Option | Meaning                                                                               |
| ----------------- | ------------------------------------------------------------------------------------- |
| `argv[1]`         | SSL certificate file (`IDM_CERT_FILE`)                                                |
| `argv[2]`         | SSL private key file (`IDM_KEY_FILE`)                                                 |
| `argv[3]`         | SSL CA file (`IDM_CA_FILE`)                                                           |
| `argv[4]`         | SSL CA directory (`IDM_CA_DIR`)                                                       |
| `argv[5]` to `argv[7]` | Secure element certificate, passcode file, and secure element CA. Used only with `ENABLE_HW_CERT_USAGE`. |
| `-subsys <name>`  | Sets the subsystem prefix                                                             |
| `-c`              | Runs in the foreground (disables daemonization)                                       |

---

## Configuration Parameters

Connection parameters are stored in PSM under the `dmsb.interdevicemanager` namespace. They are read at startup and written when changed through the data model.

| PSM Key                                          | Data Model Parameter                       | Description                                              | Default             |
| ------------------------------------------------ | ------------------------------------------ | -------------------------------------------------------- | ------------------- |
| `dmsb.interdevicemanager.BroadcastInterface`     | `Device.X_RDK_Connection.Interface`        | Network interface used for discovery                     | `br403`             |
| `dmsb.interdevicemanager.HelloInterval`          | `Device.X_RDK_Connection.HelloInterval`    | Interval between hello messages, in milliseconds         | `10000`             |
| `dmsb.interdevicemanager.DetectionWindow`        | `Device.X_RDK_Connection.DetectionWindow`  | Window used to detect loss of a remote device, in milliseconds | `30000`       |
| `dmsb.interdevicemanager.BroadcastPort`          | Not confirmed                              | Port passed to discovery (`discoveryConf.port`)          | `50765`             |
| `dmsb.interdevicemanager.MessagingPort`          | Not confirmed                              | Remote messaging port                                    | `4444`              |
| `dmsb.interdevicemanager.Capabilities`           | Not confirmed                              | Capabilities of the local device                         | Not identifiable from available sources |

The discovery loop converts `HelloInterval` and `DetectionWindow` from milliseconds to seconds before calling discovery (`/ 1000`).

### Default Values

Default values are set in `IdmMgr_SetConfigData_Default()` (`Idm_data.c`). The broadcast and messaging port defaults are marked as TODO in the source and may change.

Factory defaults are read from `/usr/ccsp/config/bbhm_def_cfg.xml` through `IdmMgr_GetFactoryDefaultValue()`.

### Subnet Lists

`Device.X_RDK_Connection.HelloIPv4SubnetList` and `Device.X_RDK_Connection.HelloIPv6SubnetList` are read-only through the data model. They are used to populate the local device entry (`Idm_Create_Rbus_Obj()`).

---

## Certificate Configuration

| Variable         | Purpose                                         | Default in `ssl.conf`         |
| ---------------- | ----------------------------------------------- | ----------------------------- |
| `IDM_CERT_FILE`  | Local certificate                               | `/tmp/idm_xpki_cert`          |
| `IDM_KEY_FILE`   | Private key for the certificate                 | `/tmp/idm_xpki_key`           |
| `IDM_CA_FILE`    | CA certificate used to verify peers             | `/tmp/idm_UPnP_CA`            |
| `IDM_CA_DIR`     | CA directory                                    | `/etc/cert/`                  |

Certificate loading is performed in `load_certificate()` (`Idm_TCP_apis.c`). If the certificate cannot be loaded, the TCP server does not start.

---

## Build Options

Options are defined in `configure.ac`:

| Option                          | Effect                                                                 |
| ------------------------------- | ---------------------------------------------------------------------- |
| `--enable-gtestapp`             | Sets `GTEST_ENABLE_FLAG` (`-DGTEST_ENABLE`) and enables the test Makefile                   |
| `--enable-notify`               | Adds `-DENABLE_SD_NOTIFY` to `SYSTEMD_CFLAGS` and `-lsystemd` to `SYSTEMD_LDFLAGS`          |
| `--enable-dropearly`            | Adds `-DDROP_ROOT_EARLY` to `NONROOT_CFLAGS`. No source file reads this macro.             |
| `--with-ccsp-arch=<arch>`       | Target architecture: `arm`, `atom`, `pc`, `mips`                       |
| `--with-ccsp-platform=<name>`   | Target platform: `intel_usg`, `pc`, `bcm`                              |

### Compile-Time Macros

These macros are used in the source but are not defined by `configure.ac`. They must be set by the build environment.

| Macro                    | Effect when defined                                                        |
| ------------------------ | -------------------------------------------------------------------------- |
| `IDM_DEBUG`              | Skips TLS context creation and certificate loading in the TCP server       |
| `ENABLE_HW_CERT_USAGE`   | Enables secure element certificate handling                                |
| `INCLUDE_BREAKPAD`       | Enables Google Breakpad crash handling                                     |
| `FEATURE_SUPPORT_RDKLOG` | Enables RDK Logger initialisation                                          |

---

## Validation

| Check                        | Command                                                                 |
| ---------------------------- | ----------------------------------------------------------------------- |
| Service is active            | `systemctl status RdkInterDeviceManager`                                |
| Startup marker is present    | `ls /tmp/interdevicemanager_initialized`                                |
| Certificate variables loaded | `grep IDM_ /etc/idm/ssl.conf`                                           |

---

## Troubleshooting

| Symptom                                        | Cause in source                                                                              |
| ---------------------------------------------- | -------------------------------------------------------------------------------------------- |
| TCP server thread does not start               | Certificate loading in `load_certificate()` or TLS context creation fails; the thread logs the error and returns |
| Connections are not encrypted                  | Component was built with `IDM_DEBUG`, which skips TLS setup                                  |
| Discovery loop logs "Retry"                    | Local interface details could not be read; the discovery loop retries (`IDM_UpdateLocalDeviceData()`) |
| Discovery loop logs "Restart triggered"        | Interface details changed (`ANSC_STATUS_DO_IT_AGAIN`); the loop refreshes them                |

---

For architecture details, see [architecture/component-diagram.md](architecture/component-diagram.md). For the component index, see [README.md](README.md).
