/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#define LOG_TAG "TetherController"
#include <cutils/log.h>
#include <cutils/properties.h>

#include <sys/system_properties.h>

#include "TetherController.h"

extern "C" {
  #include "getaddr.h"
  #include "setif.h"
  #include "setroute.h"
}

TetherController::TetherController() {
    mInterfaces = new InterfaceCollection();
    mDnsForwarders = new NetAddressCollection();
    mDaemonFd = -1;
    mDaemonPid = 0;
    mDhcpcdPid = 0;
    mRadvdPid = 0;
    mRadvdInterface = NULL;
}

TetherController::~TetherController() {
    InterfaceCollection::iterator it;

    for (it = mInterfaces->begin(); it != mInterfaces->end(); ++it) {
        free(*it);
    }
    mInterfaces->clear();

    mDnsForwarders->clear();

    if(mRadvdInterface) 
        free(mRadvdInterface);
}

int TetherController::setIpFwdEnabled(bool enable) {

    ALOGD("Setting IP forward enable = %d", enable);

    // In BP tools mode, do not disable IP forwarding
    char bootmode[PROPERTY_VALUE_MAX] = {0};
    property_get("ro.bootmode", bootmode, "unknown");
    if ((enable == false) && (0 == strcmp("bp-tools", bootmode))) {
        return 0;
    }

    int fd = open("/proc/sys/net/ipv4/ip_forward", O_WRONLY);
    if (fd < 0) {
        ALOGE("Failed to open ip_forward (%s)", strerror(errno));
        return -1;
    }

    if (write(fd, (enable ? "1" : "0"), 1) != 1) {
        ALOGE("Failed to write ip_forward (%s)", strerror(errno));
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

bool TetherController::getIpFwdEnabled() {
    int fd = open("/proc/sys/net/ipv4/ip_forward", O_RDONLY);

    if (fd < 0) {
        ALOGE("Failed to open ip_forward (%s)", strerror(errno));
        return false;
    }

    char enabled;
    if (read(fd, &enabled, 1) != 1) {
        ALOGE("Failed to read ip_forward (%s)", strerror(errno));
        close(fd);
        return -1;
    }

    close(fd);
    return (enabled  == '1' ? true : false);
}

int TetherController::startTethering(int num_addrs, struct in_addr* addrs, int lease_time) {
    if (mDaemonPid != 0) {
        ALOGE("Tethering already started");
        errno = EBUSY;
        return -1;
    }

    if (lease_time <= 0) {
        ALOGE("Invalid lease time %d!\n", lease_time);
        return -1;
    }

    ALOGD("Starting tethering services");

    pid_t pid;
    int pipefd[2];

    if (pipe(pipefd) < 0) {
        ALOGE("pipe failed (%s)", strerror(errno));
        return -1;
    }

    /*
     * TODO: Create a monitoring thread to handle and restart
     * the daemon if it exits prematurely
     */
    if ((pid = fork()) < 0) {
        ALOGE("fork failed (%s)", strerror(errno));
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    if (!pid) {
        close(pipefd[1]);
        if (pipefd[0] != STDIN_FILENO) {
            if (dup2(pipefd[0], STDIN_FILENO) != STDIN_FILENO) {
                ALOGE("dup2 failed (%s)", strerror(errno));
                return -1;
            }
            close(pipefd[0]);
        }

        int num_processed_args = 7 + (num_addrs/2) + 1; // 1 null for termination
        char **args = (char **)malloc(sizeof(char *) * num_processed_args);
        args[num_processed_args - 1] = NULL;
        args[0] = (char *)"/system/bin/dnsmasq";
        args[1] = (char *)"--keep-in-foreground";
        args[2] = (char *)"--no-resolv";
        args[3] = (char *)"--no-poll";
        // TODO: pipe through metered status from ConnService
        args[4] = (char *)"--dhcp-option-force=43,ANDROID_METERED";
        args[5] = (char *)"--pid-file";
        args[6] = (char *)"";

        int nextArg = 7;
        for (int addrIndex=0; addrIndex < num_addrs;) {
            char *start = strdup(inet_ntoa(addrs[addrIndex++]));
            char *end = strdup(inet_ntoa(addrs[addrIndex++]));
            asprintf(&(args[nextArg++]),"--dhcp-range=%s,%s,%d", start, end, lease_time);
        }

        if (execv(args[0], args)) {
            ALOGE("execl failed (%s)", strerror(errno));
        }
        ALOGE("Should never get here!");
        free(args);
        return 0;
    } else {
        close(pipefd[0]);
        mDaemonPid = pid;
        mDaemonFd = pipefd[1];
        ALOGD("Tethering services running");
    }

    return 0;
}

int TetherController::stopTethering() {

    if (mDaemonPid == 0) {
        ALOGE("Tethering already stopped");
        return 0;
    }

    ALOGD("Stopping tethering services");

    kill(mDaemonPid, SIGTERM);
    waitpid(mDaemonPid, NULL, 0);
    mDaemonPid = 0;
    close(mDaemonFd);
    mDaemonFd = -1;
    ALOGD("Tethering services stopped");
    return 0;
}

// TODO(BT) remove
int TetherController::startReverseTethering(const char* iface) {
    if (mDhcpcdPid != 0) {
        ALOGE("Reverse tethering already started");
        errno = EBUSY;
        return -1;
    }

    ALOGD("TetherController::startReverseTethering, Starting reverse tethering");

    /*
     * TODO: Create a monitoring thread to handle and restart
     * the daemon if it exits prematurely
     */
    //cleanup the dhcp result
    char dhcp_result_name[64];
    snprintf(dhcp_result_name, sizeof(dhcp_result_name) - 1, "dhcp.%s.result", iface);
    property_set(dhcp_result_name, "");

    pid_t pid;
    if ((pid = fork()) < 0) {
        ALOGE("fork failed (%s)", strerror(errno));
        return -1;
    }

    if (!pid) {

        char *args[10];
        int argc = 0;
        args[argc++] = "/system/bin/dhcpcd";
        char host_name[128];
        if (property_get("net.hostname", host_name, NULL) && (host_name[0] != '\0'))
        {
            args[argc++] = "-h";
            args[argc++] = host_name;
        }
        args[argc++] = (char*)iface;
        args[argc] = NULL;
        if (execv(args[0], args)) {
            ALOGE("startReverseTethering, execv failed (%s)", strerror(errno));
        }
        ALOGE("startReverseTethering, Should never get here!");
        // TODO(BT) inform parent of the failure.
        //          Parent process need wait for child to report error status
        //          before it set mDhcpcdPid and return 0.
        exit(-1);
    } else {
        mDhcpcdPid = pid;
        ALOGD("Reverse Tethering running, pid:%d", pid);
    }
    return 0;
}

// TODO(BT) remove
int TetherController::stopReverseTethering() {

    if (mDhcpcdPid == 0) {
        ALOGE("Tethering already stopped");
        return 0;
    }

    ALOGD("Stopping tethering services");

    kill(mDhcpcdPid, SIGTERM);
    waitpid(mDhcpcdPid, NULL, 0);
    mDhcpcdPid = 0;
    ALOGD("Tethering services stopped");
    return 0;
}
bool TetherController::isTetheringStarted() {
    return (mDaemonPid == 0 ? false : true);
}

#define MAX_CMD_SIZE 1024

int TetherController::setDnsForwarders(char **servers, int numServers) {
    int i;
    char daemonCmd[MAX_CMD_SIZE];

    strcpy(daemonCmd, "update_dns");
    int cmdLen = strlen(daemonCmd);

    mDnsForwarders->clear();
    for (i = 0; i < numServers; i++) {
        ALOGD("setDnsForwarders(%d = '%s')", i, servers[i]);

        struct in_addr a;

        if (!inet_aton(servers[i], &a)) {
            ALOGE("Failed to parse DNS server '%s'", servers[i]);
            mDnsForwarders->clear();
            return -1;
        }

        cmdLen += (strlen(servers[i]) + 1);
        if (cmdLen + 1 >= MAX_CMD_SIZE) {
            ALOGD("Too many DNS servers listed");
            break;
        }

        strcat(daemonCmd, ":");
        strcat(daemonCmd, servers[i]);
        mDnsForwarders->push_back(a);
    }

    if (mDaemonFd != -1) {
        ALOGD("Sending update msg to dnsmasq [%s]", daemonCmd);
        if (write(mDaemonFd, daemonCmd, strlen(daemonCmd) +1) < 0) {
            ALOGE("Failed to send update command to dnsmasq (%s)", strerror(errno));
            mDnsForwarders->clear();
            return -1;
        }
    }
    return 0;
}

NetAddressCollection *TetherController::getDnsForwarders() {
    return mDnsForwarders;
}

int TetherController::startRadvd() {
    if(mRadvdPid != 0) {
        LOGE("radvd already started");
        return -EBUSY;
    }

    pid_t pid;
    union anyip *ip;
    char default_pdp_interface[PROP_VALUE_MAX];
    char prefix[INET6_ADDRSTRLEN];
    FILE *radvd_conf;

    if(!__system_property_get("gsm.defaultpdpcontext.interface",default_pdp_interface)) {
        LOGE("gsm.defaultpdpcontext.interface not set");
        return -1;
    }
    ip = getinterface_ip(default_pdp_interface, AF_INET6);
    if(ip) {
        inet_ntop(AF_INET6, &ip->ip6, prefix, sizeof(prefix));
    } else {
        LOGE("getinterface_ip(%s) failed", default_pdp_interface);
        return -1;
    }

    add_address(mRadvdInterface, AF_INET6, &ip->ip6, 64, NULL);

    radvd_conf = fopen("/data/misc/radvd/radvd.conf","w");
    if(!radvd_conf) {
        LOGE("failed to write /data/misc/radvd/radvd.conf (%s)", strerror(errno));
        return -errno;
    }
    chmod("/data/misc/radvd/radvd.conf", 0644);
    fprintf(radvd_conf,"interface %s\n{\nAdvSendAdvert on;\nMinRtrAdvInterval 30;\nMaxRtrAdvInterval 100;\nprefix %s/64\n{\nAdvOnLink on;\nAdvAutonomous on;\nAdvRouterAddr off;\n};\n};\n",mRadvdInterface, prefix);
    fclose(radvd_conf);
    unlink("/data/misc/radvd/radvd.pid");

    if((pid = fork()) < 0) {
        LOGE("fork failed (%s)", strerror(errno));
        return -errno;
    }

    if (!pid) {
        if (execl("/system/bin/radvd", "radvd", "-C", "/data/misc/radvd/radvd.conf", "-n", "-p", "/data/misc/radvd/radvd.pid", (char *)NULL)) {
            LOGE("execl failed (%s)", strerror(errno));
        }
        LOGE("Should never get here!");
        exit(0);
    } else {
        mRadvdPid = pid;
    }

    return 0;
}

int TetherController::stopRadvd() {
    if(mRadvdInterface == NULL) {
        LOGE("radvd already stopped: no interface");
        return -1;
    }
    if(mRadvdPid == 0) {
        LOGE("radvd already stopped: no pid");
        return -1;
    }
    free(mRadvdInterface);
    mRadvdInterface = NULL;

    kill(mRadvdPid, SIGTERM);
    waitpid(mRadvdPid, NULL, 0);
    mRadvdPid = 0;

    return 0;
}

int TetherController::tetherInterface(const char *interface) {
    mInterfaces->push_back(strdup(interface));
    if(mRadvdPid == 0) {
        mRadvdInterface = strdup(interface);
        this->startRadvd();
    }
    return 0;
}

int TetherController::untetherInterface(const char *interface) {
    InterfaceCollection::iterator it;

    if(mRadvdPid > 0 && !strcmp(interface, mRadvdInterface)) {
        this->stopRadvd();
    }

    for (it = mInterfaces->begin(); it != mInterfaces->end(); ++it) {
        if (!strcmp(interface, *it)) {
            free(*it);
            mInterfaces->erase(it);
            return 0;
        }
    }
    errno = ENOENT;
    return -1;
}

InterfaceCollection *TetherController::getTetheredInterfaceList() {
    return mInterfaces;
}
