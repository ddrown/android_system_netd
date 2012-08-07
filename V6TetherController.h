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

#ifndef _V6TETHER_CONTROLLER_H
#define _V6TETHER_CONTROLLER_H

class V6TetherController {
    pid_t mRadvdPid;
    int   mForwardingUsers;

public:
    V6TetherController();
    virtual ~V6TetherController();

    void enabledForwarding();
    void disabledForwarding();

    int setIPv6FwdEnabled(bool enable);
    bool getIPv6FwdEnabled();

    int startV6Tether(char *downstream_interface, char *address);

    int stopV6Tether();
    bool isV6TetherStarted();
};

#endif
