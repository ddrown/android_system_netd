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
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>

#define LOG_TAG "V6TetherController"
#include <cutils/log.h>
#include <cutils/properties.h>
#include <netutils/ifc.h>

#include "V6TetherController.h"

V6TetherController::V6TetherController() {
    mRadvdPid = 0;
    mForwardingUsers = 0;
}

V6TetherController::~V6TetherController() {
}

void V6TetherController::enabledForwarding() {
    mForwardingUsers++;
}

void V6TetherController::disabledForwarding() {
    mForwardingUsers--;
}

int V6TetherController::setIPv6FwdEnabled(bool enable) {
    if(enable) {
      this->enabledForwarding();
    } else {
      this->disabledForwarding();
      if(mForwardingUsers > 0) {
          enable = true; // there are still users relying on forwarding
      }
    }

    // In BP tools mode, do not disable IP forwarding
    char bootmode[PROPERTY_VALUE_MAX] = {0};
    property_get("ro.bootmode", bootmode, "unknown");
    if ((enable == false) && (0 == strcmp("bp-tools", bootmode))) {
        return 0;
    }

    int fd = open("/proc/sys/net/ipv6/conf/all/forwarding", O_WRONLY);
    if (fd < 0) {
        ALOGE("Failed to open forwarding (%s)", strerror(errno));
        return -1;
    }

    if (write(fd, (enable ? "1" : "0"), 1) != 1) {
        ALOGE("Failed to write forwarding (%s)", strerror(errno));
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

bool V6TetherController::getIPv6FwdEnabled() {
    int fd = open("/proc/sys/net/ipv6/conf/all/forwarding", O_RDONLY);

    if (fd < 0) {
        ALOGE("Failed to open forwarding (%s)", strerror(errno));
        return false;
    }

    char enabled;
    if (read(fd, &enabled, 1) != 1) {
        ALOGE("Failed to read forwarding (%s)", strerror(errno));
        close(fd);
        return false;
    }

    close(fd);
    return (enabled == '1' ? true : false);
}

int V6TetherController::startV6Tether(char *downstream_interface, char *address) {
    FILE *radvd_conf;
    pid_t pid;
    int status;

    if(mRadvdPid != 0) {
        ALOGE("radvd already running");
        errno = EBUSY;
        return -1;
    }

    status = ifc_add_address(downstream_interface, address, 64);
    if(status < 0) {
        ALOGE("adding address to %s failed: %s", downstream_interface, strerror(errno));
        errno = -status;
        return -1;
    }

    radvd_conf = fopen("/data/misc/radvd/radvd.conf","w");
    if(!radvd_conf) {
        ALOGE("failed to write /data/misc/radvd/radvd.conf (%s)", strerror(errno));
        return -1;
    }
    fprintf(radvd_conf,"interface %s\n{\n", downstream_interface);
    fprintf(radvd_conf,"AdvSendAdvert on;\nMinRtrAdvInterval 30;\nMaxRtrAdvInterval 100;\n");
    fprintf(radvd_conf,"prefix %s/64\n", address);
    fprintf(radvd_conf,"{\nAdvOnLink on;\nAdvAutonomous on;\nAdvRouterAddr off;\n};\n");
    fprintf(radvd_conf,"};\n");
    fclose(radvd_conf);
    unlink("/data/misc/radvd/radvd.pid");

    if ((pid = fork()) < 0) {
        ALOGE("fork failed (%s)", strerror(errno));
        return -1;
    }

    if (!pid) {
        char **args = (char **)malloc(sizeof(char *) * 7);
        args[0] = (char *)"/system/bin/radvd";
        args[1] = (char *)"-C";
        args[2] = (char *)"/data/misc/radvd/radvd.conf";
        args[3] = (char *)"-n";
        args[4] = (char *)"-p";
        args[5] = (char *)"/data/misc/radvd/radvd.pid";
        args[6] = NULL;

        if (execv(args[0], args)) {
            ALOGE("execv failed (%s)", strerror(errno));
        }
        ALOGE("Should never get here!");
        free(args);
        exit(0);
    } else {
        mRadvdPid = pid;
    }

    return 0;
}

int V6TetherController::stopV6Tether() {
    if (mRadvdPid == 0) {
        ALOGE("radvd already stopped");
        return -1;
    }

    kill(mRadvdPid, SIGTERM);
    waitpid(mRadvdPid, NULL, 0);
    mRadvdPid = 0;

    return 0;
}

bool V6TetherController::isV6TetherStarted() {
    return (mRadvdPid == 0 ? false : true);
}
