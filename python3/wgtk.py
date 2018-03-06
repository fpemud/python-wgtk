#!/usr/bin/env python3

# wgtk.py - Python binding for Web Gui Toolkit
#
# Copyright (c) 2016-2017 Fpemud <fpemud@sina.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

"""
wgtk

@author: Fpemud
@license: GPLv3 License
@contact: fpemud@sina.com
"""

import os
import re
import time
import fcntl
import errno
import shutil
from passlib import hosts

__author__ = "fpemud@sina.com (Fpemud)"
__version__ = "0.0.1"


MUSER_SET_PASSWORD = 1
MUSER_SET_SHELL = 2
MUSER_JOIN_GROUP = 3
MUSER_LEAVE_GROUP = 4


class PgsFormatError(Exception):
    pass


class PgsLockError(Exception):
    pass


class PgsAddUserError(Exception):
    pass


class PgsAddGroupError(Exception):
    pass


class PgsAddUserToGroupError(Exception):
    pass


class PasswdGroupShadow:

    """Unix account files with special format and rules.
       Including:
           /etc/passwd
           /etc/group
           /etc/shadow
           /etc/gshadow
           /etc/subuid
           /etc/subgid
    """

    class _PwdEntry:

        def __init__(self, *kargs):
            if len(kargs) == 1:
                fields = kargs[0]
                assert len(fields) == 7
                self.pw_name = fields[0]
                self.pw_passwd = fields[1]
                self.pw_uid = int(fields[2])
                self.pw_gid = int(fields[3])
                self.pw_gecos = fields[4]
                self.pw_dir = fields[5]
                self.pw_shell = fields[6]
            elif len(kargs) == 7:
                assert isinstance(kargs[2], int) and isinstance(kargs[3], int)
                self.pw_name = kargs[0]
                self.pw_passwd = kargs[1]
                self.pw_uid = kargs[2]
                self.pw_gid = kargs[3]
                self.pw_gecos = kargs[4]
                self.pw_dir = kargs[5]
                self.pw_shell = kargs[6]
            else:
                assert False

    class _GrpEntry:

        def __init__(self, *kargs):
            if len(kargs) == 1:
                fields = kargs[0]
                assert len(fields) == 4
                self.gr_name = fields[0]
                self.gr_passwd = fields[1]
                self.gr_gid = int(fields[2])
                self.gr_mem = fields[3]
            elif len(kargs) == 4:
                assert isinstance(kargs[2], int)
                self.gr_name = kargs[0]
                self.gr_passwd = kargs[1]
                self.gr_gid = kargs[2]
                self.gr_mem = kargs[3]
            else:
                assert False

    class _ShadowEntry:

        def __init__(self, *kargs):
            if len(kargs) == 1:
                fields = kargs[0]
                assert len(fields) == 9
                self.sh_name = fields[0]
                self.sh_encpwd = fields[1]
            elif len(kargs) == 9:
                self.sh_name = kargs[0]
                self.sh_encpwd = kargs[1]
                assert kargs[2] == ""
                assert kargs[3] == ""
                assert kargs[4] == ""
                assert kargs[5] == ""
                assert kargs[6] == ""
                assert kargs[7] == ""
                assert kargs[8] == ""
            else:
                assert False

    class _SubUidGidEntry:

        def __init__(self, name, start, count):
            self.name = name
            self.start = start
            self.count = count

    _stdSystemUserList = ["root", "nobody"]
    _stdDeprecatedUserList = ["bin", "daemon", "adm", "shutdown", "halt", "operator", "lp"]
    _stdSystemGroupList = ["root", "nobody", "nogroup", "wheel", "users"]
    _stdDeviceGroupList = ["tty", "disk", "lp", "mem", "kmem", "floppy", "console", "audio", "cdrom", "tape", "video", "cdrw", "usb", "plugdev", "input", "kvm"]
    _stdDeprecatedGroupList = ["bin", "daemon", "sys", "adm"]

    def __init__(self, dirPrefix="/", readOnly=True, msrc="strict_pgs"):
        self.valid = True
        self.dirPrefix = dirPrefix
        self.readOnly = readOnly
        self.manageFlag = "# manged by %s" % (msrc)

        self.loginDefFile = os.path.join(dirPrefix, "etc", "login.defs")
        self.passwdFile = os.path.join(dirPrefix, "etc", "passwd")
        self.groupFile = os.path.join(dirPrefix, "etc", "group")
        self.shadowFile = os.path.join(dirPrefix, "etc", "shadow")
        self.gshadowFile = os.path.join(dirPrefix, "etc", "gshadow")
        self.subuidFile = os.path.join(dirPrefix, "etc", "subuid")
        self.subgidFile = os.path.join(dirPrefix, "etc", "subgid")

        self.lockFile = os.path.join(dirPrefix, "etc", ".pwd.lock")
        self.lockFd = None

        # filled by _parseLoginDef
        self.uidMin = -1
        self.uidMax = -1
        self.gidMin = -1
        self.gidMax = -1
        self.subUidMin = -1
        self.subUidMax = -1
        self.subUidCount = -1
        self.subGidMin = -1
        self.subGidMax = -1
        self.subGidCount = -1

        # filled by _parsePasswd
        self.systemUserList = []
        self.normalUserList = []
        self.softwareUserList = []
        self.deprecatedUserList = []
        self.pwdDict = dict()                   # key: username; value: _PwdEntry

        # filled by _parseGroup
        self.systemGroupList = []
        self.deviceGroupList = []
        self.perUserGroupList = []
        self.standAloneGroupList = []
        self.softwareGroupList = []
        self.deprecatedGroupList = []
        self.secondaryGroupsDict = dict()       # key: username; value: secondary group list of that user
        self.grpDict = dict()                   # key: groupname; value: _GrpEntry

        # filled by _parseShadow
        self.shadowEntryList = []
        self.shDict = dict()                    # key: username; value: _ShadowEntry

        # filled by _parseSubUid
        self.subUidEntryList = []
        self.subUidDict = dict()                # key: username; value: _SubUidGidEntry

        # filled by _parseSubGid
        self.subGidEntryList = []
        self.subGidDict = dict()                # key: username; value: _SubUidGidEntry

        # do parsing
        self._parseLoginDef()
        if not self.readOnly:
            self._lockPwd()
        try:
            self._parsePasswd()
            self._parseGroup(self.normalUserList)
            self._parseShadow()
            self._parseSubUid()
            self._parseSubGid()
        except:
            if not self.readOnly:
                self._unlockPwd()
            raise

        # do verify
        self._verifyStage1()

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    def getSystemUserList(self):
        """returns system user name list"""
        assert self.valid
        return self.systemUserList

    def getNormalUserList(self):
        """returns normal user name list"""
        assert self.valid
        return self.normalUserList

    def getSystemGroupList(self):
        """returns system group name list"""
        assert self.valid
        return self.systemGroupList

    def getStandAloneGroupList(self):
        """returns stand-alone group name list"""
        assert self.valid
        return self.standAloneGroupList

    def getSoftwareGroupList(self):
        """returns software group name list"""
        assert self.valid
        return self.softwareGroupList

    def getSecondaryGroupsOfUser(self, username):
        """returns group name list"""
        assert self.valid
        assert username in self.normalUserList
        return sorted(self.secondaryGroupsDict.get(username, []))

    def verify(self):
        """check account files according to the critiera"""
        assert self.valid
        self._verifyStage1()
        self._verifyStage2()

    def addNormalUser(self, username, password):
        assert self.valid
        assert username not in self.pwdDict
        assert username not in self.grpDict

        # generate user id
        newUid = 1000
        while True:
            if newUid >= 10000:
                raise PgsAddUserError("Can not find a valid user id")
            if newUid in [v.pw_uid for v in self.pwdDict.values()]:
                newUid += 1
                continue
            if newUid in [v.gr_gid for v in self.grpDict.values()]:
                newUid += 1
                continue
            break

        # add user
        self.pwdDict[username] = self._PwdEntry(username, "x", newUid, newUid, "", "/home/%s" % (username), "/bin/bash")
        self.normalUserList.append(username)

        # add group
        self.grpDict[username] = self._GrpEntry(username, "x", newUid, "")
        self.perUserGroupList.append(username)

        # add shadow
        self.shDict[username] = self._ShadowEntry(username, hosts.linux_context.encrypt(password), "", "", "", "", "", "", "")
        self.shadowEntryList.append(username)

        # add subuid
        m = self.subUidMin
        for obj in self.subUidDict.values():
            m = max(obj.start + obj.count, m)
        self.subUidDict[username] = self._SubUidGidEntry(username, m, self.subUidCount)
        self.subUidEntryList.append(username)

        # add subgid
        m = self.subGidMin
        for obj in self.subGidDict.values():
            m = max(obj.start + obj.count, m)
        self.subGidDict[username] = self._SubUidGidEntry(username, m, self.subGidCount)
        self.subGidEntryList.append(username)

    def removeNormalUser(self, username):
        """do nothing if the user doesn't exists"""
        assert self.valid

        if username in self.subGidEntryList:
            self.subGidEntryList.remove(username)
            del self.subGidDict[username]

        if username in self.subUidEntryList:
            self.subUidEntryList.remove(username)
            del self.subUidDict[username]

        if username in self.shadowEntryList:
            self.shadowEntryList.remove(username)
            del self.shDict[username]

        if username in self.secondaryGroupsDict:
            del self.secondaryGroupsDict[username]
        for gname, entry in self.grpDict.items():
            ulist = [x for x in entry.gr_mem.split(",") if x != ""]
            if username in ulist:
                ulist.remove(username)
                self.grpDict[gname].gr_mem = ",".join(ulist)

        if username in self.perUserGroupList:
            self.perUserGroupList.remove(username)
            del self.grpDict[username]

        if username in self.normalUserList:
            self.normalUserList.remove(username)
            del self.pwdDict[username]

    def modifyNormalUser(self, username, op, *kargs):
        assert self.valid
        assert username in self.normalUserList

        if op == MUSER_SET_PASSWORD:
            assert len(kargs) == 1
            password = kargs[0]
            self.shDict[username].sh_encpwd = hosts.linux_context.encrypt(password)
        elif op == MUSER_SET_SHELL:
            assert False
        elif op == MUSER_JOIN_GROUP:
            assert len(kargs) == 1
            groupname = kargs[0]
            assert groupname in self.systemGroupList + self.deviceGroupList + self.standAloneGroupList + self.softwareGroupList
            if username not in self.secondaryGroupsDict:
                self.secondaryGroupsDict[username] = []
            if groupname not in self.secondaryGroupsDict[username]:
                self.secondaryGroupsDict[username].append(groupname)
            ulist = [x for x in self.grpDict[groupname].gr_mem.split(",") if x != ""]
            if username not in ulist:
                ulist.append(username)
                self.grpDict[groupname].gr_mem = ",".join(ulist)
        elif op == MUSER_LEAVE_GROUP:
            assert len(kargs) == 1
            groupname = kargs[0]
            if username in self.secondaryGroupsDict:
                if groupname in self.secondaryGroupsDict[username]:
                    self.secondaryGroupsDict[username].remove(groupname)
            ulist = [x for x in self.grpDict[groupname].gr_mem.split(",") if x != ""]
            if username in ulist:
                ulist.remove(username)
                self.grpDict[groupname].gr_mem = ",".join(ulist)
        else:
            assert False

    def addStandAloneGroup(self, groupname):
        assert self.valid
        assert groupname not in self.grpDict

        # generate group id
        newGid = 5000
        while True:
            if newGid >= 10000:
                raise PgsAddGroupError("Can not find a valid group id")
            if newGid in [v.grp_gid for v in self.grpDict.values()]:
                newGid += 1
                continue
            break

        # add group
        self.grpDict[groupname] = self._GrpEntry(groupname, "x", newGid, "")
        self.standAloneGroupList.append(groupname)

    def removeStandAloneGroup(self, groupname):
        assert self.valid

        for glist in self.secondaryGroupsDict.values():
            if groupname in glist:
                glist.remove(groupname)

        if groupname in self.standAloneGroupList:
            self.standAloneGroupList.remove(groupname)
            del self.grpDict[groupname]

    def close(self):
        assert self.valid

        if not self.readOnly:
            self._fixate()
            self._writePasswd()
            self._writeGroup()
            self._writeShadow()
            self._writeGroupShadow()
            self._writeSubUid()
            self._writeSubGid()
            self._unlockPwd()
        self.valid = False

    def _parseLoginDef(self):
        if not os.path.exists(self.loginDefFile):
            raise PgsFormatError("%s is missing" % (self.loginDefFile))
        buf = self._readFile(self.loginDefFile)

        m = re.search("\\s*UID_MIN\s+([0-9]+)\\s*$", buf, re.M)
        if m is not None:
            self.uidMin = int(m.group(1))
        else:
            raise PgsFormatError("Invalid format of %s, UID_MIN is missing." % (self.loginDefFile))

        m = re.search("\\s*UID_MAX\s+([0-9]+)\\s*$", buf, re.M)
        if m is not None:
            self.uidMax = int(m.group(1))
        else:
            raise PgsFormatError("Invalid format of %s, UID_MAX is missing." % (self.loginDefFile))

        m = re.search("\\s*GID_MIN\s+([0-9]+)\\s*$", buf, re.M)
        if m is not None:
            self.gidMin = int(m.group(1))
        else:
            raise PgsFormatError("Invalid format of %s, GID_MIN is missing." % (self.loginDefFile))

        m = re.search("\\s*GID_MAX\s+([0-9]+)\\s*$", buf, re.M)
        if m is not None:
            self.gidMax = int(m.group(1))
        else:
            raise PgsFormatError("Invalid format of %s, GID_MAX is missing." % (self.loginDefFile))

        m = re.search("\\s*SUB_UID_MIN\s+([0-9]+)\\s*$", buf, re.M)
        if m is not None:
            self.subUidMin = int(m.group(1))
        else:
            raise PgsFormatError("Invalid format of %s, SUB_UID_MIN is missing, shadow version too low?" % (self.loginDefFile))

        m = re.search("\\s*SUB_UID_MAX\s+([0-9]+)\\s*$", buf, re.M)
        if m is not None:
            self.subUidMax = int(m.group(1))
        else:
            raise PgsFormatError("Invalid format of %s, SUB_UID_MAX is missing, shadow version too low?" % (self.loginDefFile))

        m = re.search("\\s*SUB_UID_COUNT\s+([0-9]+)\\s*$", buf, re.M)
        if m is not None:
            self.subUidCount = int(m.group(1))
        else:
            raise PgsFormatError("Invalid format of %s, SUB_UID_COUNT is missing, shadow version too low?" % (self.loginDefFile))

        m = re.search("\\s*SUB_GID_MIN\s+([0-9]+)\\s*$", buf, re.M)
        if m is not None:
            self.subGidMin = int(m.group(1))
        else:
            raise PgsFormatError("Invalid format of %s, SUB_GID_MIN is missing, shadow version too low?" % (self.loginDefFile))

        m = re.search("\\s*SUB_GID_MAX\s+([0-9]+)\\s*$", buf, re.M)
        if m is not None:
            self.subGidMax = int(m.group(1))
        else:
            raise PgsFormatError("Invalid format of %s, SUB_GID_MAX is missing, shadow version too low?" % (self.loginDefFile))

        m = re.search("\\s*SUB_GID_COUNT\s+([0-9]+)\\s*$", buf, re.M)
        if m is not None:
            self.subGidCount = int(m.group(1))
        else:
            raise PgsFormatError("Invalid format of %s, SUB_GID_COUNT is missing, shadow version too low?" % (self.loginDefFile))

        if self.uidMax < self.uidMin:
            raise PgsFormatError("Invalid format of %s, UID_MAX is lesser than UID_MIN." % (self.loginDefFile))

        if self.gidMax < self.gidMin:
            raise PgsFormatError("Invalid format of %s, GID_MAX is lesser than GID_MIN." % (self.loginDefFile))

        if self.subUidMax < self.subUidMin:
            raise PgsFormatError("Invalid format of %s, SUB_UID_MAX is lesser than SUB_UID_MIN." % (self.loginDefFile))
        if (self.subUidMax - self.subUidMin) % self.subUidCount != 0:
            raise PgsFormatError("Invalid format of %s, SUB_UID_MIN, SUB_UID_MAX and SUB_UID_COUNT is not aligned." % (self.loginDefFile))

        if self.subGidMax < self.subGidMin:
            raise PgsFormatError("Invalid format of %s, SUB_UID_MAX is lesser than SUB_UID_MIN." % (self.loginDefFile))
        if (self.subGidMax - self.subGidMin) % self.subGidCount != 0:
            raise PgsFormatError("Invalid format of %s, SUB_GID_MIN, SUB_GID_MAX and SUB_GID_COUNT is not aligned." % (self.loginDefFile))

    def _parsePasswd(self):
        lineList = self._readFile(self.passwdFile).split("\n")
        for line in lineList:
            if line == "" or line.startswith("#"):
                continue

            t = line.split(":")
            if len(t) != 7:
                raise PgsFormatError("Invalid format of passwd file")

            self.pwdDict[t[0]] = self._PwdEntry(t)

            if t[0] in self._stdSystemUserList:
                self.systemUserList.append(t[0])
            elif self.uidMin <= int(t[2]) < self.uidMax:
                self.normalUserList.append(t[0])
            elif t[0] in self._stdDeprecatedUserList:
                self.deprecatedUserList.append(t[0])
            else:
                self.softwareUserList.append(t[0])

    def _parseGroup(self, normalUserList):
        lineList = self._readFile(self.groupFile).split("\n")
        for line in lineList:
            if line == "" or line.startswith("#"):
                continue

            t = line.split(":")
            if len(t) != 4:
                raise PgsFormatError("Invalid format of group file")

            self.grpDict[t[0]] = self._GrpEntry(t)

            if t[0] in self._stdSystemGroupList:
                self.systemGroupList.append(t[0])
            elif t[0] in normalUserList:
                self.perUserGroupList.append(t[0])
            elif t[0] in self._stdDeviceGroupList:
                self.deviceGroupList.append(t[0])
            elif t[0] in self._stdDeprecatedGroupList:
                self.deprecatedGroupList.append(t[0])
            elif self.gidMin <= int(t[2]) < self.gidMax:
                self.standAloneGroupList.append(t[0])
            else:
                self.softwareGroupList.append(t[0])

            for u in t[3].split(","):
                if u == "":
                    continue
                if u not in self.secondaryGroupsDict:
                    self.secondaryGroupsDict[u] = []
                self.secondaryGroupsDict[u].append(t[0])

    def _parseShadow(self):
        for line in self._readFile(self.shadowFile).split("\n"):
            if line == "" or line.startswith("#"):
                continue

            t = line.split(":")
            if len(t) != 9:
                raise PgsFormatError("Invalid format of shadow file")

            self.shDict[t[0]] = self._ShadowEntry(t)
            self.shadowEntryList.append(t[0])

    def _parseSubUid(self):
        if not os.path.exists(self.subuidFile):
            return

        for line in self._readFile(self.subuidFile).split("\n"):
            if line == "" or line.startswith("#"):
                continue

            t = line.split(":")
            if len(t) != 3:
                raise PgsFormatError("Invalid format of subuid file")

            self.subUidDict[t[0]] = self._SubUidGidEntry(t[0], int(t[1]), int(t[2]))
            self.subUidEntryList.append(t[0])

    def _parseSubGid(self):
        if not os.path.exists(self.subgidFile):
            return

        for line in self._readFile(self.subgidFile).split("\n"):
            if line == "" or line.startswith("#"):
                continue

            t = line.split(":")
            if len(t) != 3:
                raise PgsFormatError("Invalid format of subgid file")

            self.subGidDict[t[0]] = self._SubUidGidEntry(t[0], int(t[1]), int(t[2]))
            self.subGidEntryList.append(t[0])

    def _writePasswd(self):
        shutil.copy2(self.passwdFile, self.passwdFile + "-")
        with open(self.passwdFile, "w") as f:
            f.write(self.manageFlag + "\n")
            f.write("\n")
            for uname in self.systemUserList:
                f.write(self._pwd2str(self.pwdDict[uname]))
                f.write("\n")
            f.write("\n")
            for uname in self.normalUserList:
                f.write(self._pwd2str(self.pwdDict[uname]))
                f.write("\n")
            f.write("\n")
            for uname in self.softwareUserList:
                f.write(self._pwd2str(self.pwdDict[uname]))
                f.write("\n")
            f.write("\n")
            for uname in self.deprecatedUserList:
                f.write(self._pwd2str(self.pwdDict[uname]))
                f.write("\n")

    def _writeGroup(self):
        shutil.copy2(self.groupFile, self.groupFile + "-")
        with open(self.groupFile, "w") as f:
            f.write(self.manageFlag + "\n")
            f.write("\n")
            for gname in self.systemGroupList:
                f.write(self._grp2str(self.grpDict[gname]))
                f.write("\n")
            f.write("\n")
            for gname in self.perUserGroupList:
                f.write(self._grp2str(self.grpDict[gname]))
                f.write("\n")
            f.write("\n")
            for gname in self.standAloneGroupList:
                f.write(self._grp2str(self.grpDict[gname]))
                f.write("\n")
            f.write("\n")
            for gname in self.deviceGroupList:
                f.write(self._grp2str(self.grpDict[gname]))
                f.write("\n")
            f.write("\n")
            for gname in self.softwareGroupList:
                f.write(self._grp2str(self.grpDict[gname]))
                f.write("\n")
            f.write("\n")
            for gname in self.deprecatedGroupList:
                f.write(self._grp2str(self.grpDict[gname]))
                f.write("\n")

    def _writeShadow(self):
        shutil.copy2(self.shadowFile, self.shadowFile + "-")
        with open(self.shadowFile, "w") as f:
            f.write(self.manageFlag + "\n")
            f.write("\n")
            for sname in self.shadowEntryList:
                f.write(self._sh2str(self.shDict[sname]))
                f.write("\n")

    def _writeGroupShadow(self):
        shutil.copy2(self.gshadowFile, self.gshadowFile + "-")
        with open(self.gshadowFile, "w") as f:
            f.truncate()

    def _writeSubUid(self):
        if os.path.exists(self.subuidFile):
            shutil.copy2(self.subuidFile, self.subuidFile + "-")
        with open(self.subuidFile, "w") as f:
            f.write(self.manageFlag + "\n")
            f.write("\n")
            for name in self.subUidEntryList:
                f.write(self._subuidgid2str(self.subUidDict[name]))
                f.write("\n")

    def _writeSubGid(self):
        if os.path.exists(self.subgidFile):
            shutil.copy2(self.subgidFile, self.subgidFile + "-")
        with open(self.subgidFile, "w") as f:
            f.write(self.manageFlag + "\n")
            f.write("\n")
            for name in self.subGidEntryList:
                f.write(self._subuidgid2str(self.subGidDict[name]))
                f.write("\n")

    def _pwd2str(self, e):
        return "%s:%s:%d:%d:%s:%s:%s" % (e.pw_name, "x", e.pw_uid, e.pw_gid, e.pw_gecos, e.pw_dir, e.pw_shell)

    def _grp2str(self, e):
        return "%s:%s:%d:%s" % (e.gr_name, "x", e.gr_gid, e.gr_mem)

    def _sh2str(self, e):
        return "%s:%s:::::::" % (e.sh_name, e.sh_encpwd)

    def _subuidgid2str(self, e):
        return "%s:%d:%d" % (e.name, e.start, e.count)

    def _verifyStage1(self):
        """account files are not fixable if stage1 verification fails"""

        # check system user list
        if set(self.systemUserList) != set(self._stdSystemUserList):
            raise PgsFormatError("Invalid system user list")
        for uname in self.systemUserList:
            if uname not in self.shDict:
                raise PgsFormatError("No shadow entry for system user %s" % (uname))

        # check normal user list
        for uname in self.normalUserList:
            if not (self.uidMin <= self.pwdDict[uname].pw_uid < self.uidMax):
                raise PgsFormatError("User ID out of range for normal user %s" % (uname))
            if self.pwdDict[uname].pw_uid != self.grpDict[uname].gr_gid:
                raise PgsFormatError("User ID and group ID not equal for normal user %s" % (uname))
            if len(self.shDict[uname].sh_encpwd) <= 4:
                raise PgsFormatError("No password for normal user %s" % (uname))
            if uname not in self.shDict:
                raise PgsFormatError("No shadow entry for normal user %s" % (uname))

        # check system group list
        if set(self.systemGroupList) != set(self._stdSystemGroupList):
            raise PgsFormatError("Invalid system group list")

        # check per-user group list
        if set(self.perUserGroupList) != set(self.normalUserList):
            raise PgsFormatError("Invalid per-user group list")

        # check stand-alone group list
        for gname in self.standAloneGroupList:
            if not (self.gidMin <= self.grpDict[gname].gr_gid < self.gidMax):
                raise PgsFormatError("Group ID out of range for stand-alone group %s" % (gname))

    def _verifyStage2(self):
        """account files are fixable if stage2 verification fails"""

        # check system user list
        if self.systemUserList != self._stdSystemUserList:
            raise PgsFormatError("Invalid system user order")
        for uname in self.systemUserList:
            if self.pwdDict[uname].pw_gecos != "":
                raise PgsFormatError("No comment is allowed for system user %s" % (uname))

        # check normal user list
        uidList = [self.pwdDict[x].pw_uid for x in self.normalUserList]
        if uidList != sorted(uidList):
            raise PgsFormatError("Invalid normal user order")
        for uname in self.normalUserList:
            if self.pwdDict[uname].pw_gecos != "":
                raise PgsFormatError("No comment is allowed for normal user %s" % (uname))

        # check software user list
        for uname in self.softwareUserList:
            if self.pwdDict[uname].pw_uid >= self.uidMin:
                raise PgsFormatError("User ID out of range for software user %s" % (uname))
            if self.pwdDict[uname].pw_shell != "/sbin/nologin":
                raise PgsFormatError("Invalid shell for software user %s" % (uname))
            if uname in self.shDict:
                raise PgsFormatError("Should not have shadow entry for software user %s" % (uname))

        # check stand-alone group list
        gidList = [self.grpDict[x].gr_gid for x in self.standAloneGroupList]
        if gidList != sorted(gidList):
            raise PgsFormatError("Invalid stand-alone group order")

        # check software group list
        for gname in self.softwareGroupList:
            if self.grpDict[gname].gr_gid >= self.gidMin:
                raise PgsFormatError("Group ID out of range for software group %s" % (gname))

        # check secondary groups for root
        if "root" in self.secondaryGroupsDict:
            raise PgsFormatError("User root should not have any secondary group")

        # check secondary groups dict
        for uname, grpList in self.secondaryGroupsDict.items():
            if uname not in self.systemUserList + self.normalUserList + self.softwareUserList:
                continue
            for gname in grpList:
                if gname in self.deprecatedGroupList:
                    raise PgsFormatError("User %s is a member of deprecated group %s" % (uname, gname))

        # check group member field
        for gname, g in self.grpDict.items():
            ulist = [x for x in g.gr_mem.split(",") if x != ""]
            if g.gr_mem != ",".join(ulist):
                raise PgsFormatError("Member field of group %s has flaws" % (gname))

        # check /etc/shadow
        i = 0
        if self.systemUserList != self.shadowEntryList[i:i + len(self.systemUserList)]:
            raise PgsFormatError("Invalid shadow file entry order")
        i += len(self.systemUserList)
        if self.normalUserList != self.shadowEntryList[i:i + len(self.normalUserList)]:
            raise PgsFormatError("Invalid shadow file entry order")
        i += len(self.normalUserList)
        if i != len(self.shadowEntryList):
            raise PgsFormatError("Redundant shadow file entries")

        # check /etc/gshadow
        if len(self._readFile(self.gshadowFile)) > 0:
            raise PgsFormatError("gshadow file should be empty")

        # check subuid entry list
        i = 0
        if self.normalUserList != self.subUidEntryList[i:i + len(self.normalUserList)]:
            raise PgsFormatError("Invalid subuid file entry order")
        i += len(self.normalUserList)
        if self.softwareUserList != self.subUidEntryList[i:i + len(self.softwareUserList)]:
            raise PgsFormatError("Invalid subuid file entry order")
        i += len(self.softwareUserList)
        if i != len(self.subUidEntryList):
            raise PgsFormatError("Redundant subuid file entries")

        # check subuid value range
        for uname, obj in self.subUidDict.items():
            if not (self.subUidMin <= obj.start < self.subUidMax):
                raise PgsFormatError("Subordinate User ID out of range for user %s" % (uname))
            if (obj.start - self.subUidMin) % self.subUidCount != 0:
                raise PgsFormatError("Subordinate User ID is not aligned for user %s" % (uname))
            if obj.count != self.subUidCount:
                raise PgsFormatError("Subordinate User ID count is different from %s for user %s" % (self.loginDefFile, uname))

        # check subgid entry list
        if self.subUidEntryList != self.subGidEntryList:
            raise PgsFormatError("Invalid subgid file entries")

        # check subgid value range
        for uname, obj in self.subGidDict.items():
            if not (self.subGidMin <= obj.start < self.subGidMax):
                raise PgsFormatError("Subordinate Group ID out of range for user %s" % (uname))
            if (obj.start - self.subGidMin) % self.subGidCount != 0:
                raise PgsFormatError("Subordinate Group ID is not aligned for user %s" % (uname))
            if obj.count != self.subGidCount:
                raise PgsFormatError("Subordinate Group ID count is different from %s for user %s" % (self.loginDefFile, uname))

    def _fixate(self):
        # sort system user list
        assert set(self.systemUserList) == set(self._stdSystemUserList)
        self.systemUserList = self._stdSystemUserList

        # remove comment for system users
        for uname in self.systemUserList:
            self.pwdDict[uname].pw_gecos = ""

        # sort normal user list
        self.normalUserList.sort(key=lambda x: self.pwdDict[x].pw_uid)

        # remove comment for normal users
        for uname in self.normalUserList:
            self.pwdDict[uname].pw_gecos = ""

        # standardize shell for software users
        for uname in self.softwareUserList:
            self.pwdDict[uname].pw_shell = "/sbin/nologin"

        # remove shadow entry for software users
        for uname in self.softwareUserList:
            if uname in self.shDict:
                del self.shDict[uname]

        # sort system group list
        assert set(self.systemGroupList) == set(self._stdSystemGroupList)
        self.systemGroupList = self._stdSystemGroupList

        # sort per-user group list
        assert set(self.perUserGroupList) == set(self.normalUserList)
        self.perUserGroupList = self.normalUserList

        # sort stand-alone group list
        self.standAloneGroupList.sort(key=lambda x: self.grpDict[x].pw_gid)

        # remove root from any secondary group
        if "root" in self.secondaryGroupsDict:
            del self.secondaryGroupsDict["root"]
        for entry in self.grpDict.values():
            ulist = [x for x in entry.gr_mem.split(",") if x != ""]
            if "root" in ulist:
                ulist.remove("root")
                entry.gr_mem = ",".join(ulist)

        # standardize group members
        for g in self.grpDict.values():
            ulist = [x for x in g.gr_mem.split(",") if x != ""]
            g.gr_mem = ",".join(ulist)

        # sort shadow entry list
        assert set(self.shadowEntryList) >= set(self.systemUserList + self.normalUserList)
        self.shadowEntryList = self.systemUserList + self.normalUserList

        # remove redundant shadow entries
        for uname in set(self.shDict.keys()) - set(self.shadowEntryList):
            del self.shDict[uname]

        # sort subuid entry list
        self.subUidEntryList = self.normalUserList + self.softwareUserList

        # remove redundant subuid entries
        for uname in set(self.subUidDict.keys()) - set(self.subUidEntryList):
            del self.subUidDict[uname]

        # add missing subuid entries
        m = self.subUidMin
        for obj in self.subUidDict.values():
            m = max(obj.start + obj.count, m)
        for uname in self.subUidEntryList:
            if uname not in self.subUidDict:
                assert m < self.subUidMax
                self.subUidDict[uname] = self._SubUidGidEntry(uname, m, self.subUidCount)
                m += self.subUidCount

        # sort subgid entry list
        self.subGidEntryList = list(self.subUidEntryList)

        # remove redundant subgid entries
        for uname in set(self.subGidDict.keys()) - set(self.subGidEntryList):
            del self.subGidDict[uname]

        # add missing subgid entries
        m = self.subGidMin
        for obj in self.subGidDict.values():
            m = max(obj.start + obj.count, m)
        for uname in self.subGidEntryList:
            if uname not in self.subGidDict:
                assert m < self.subGidMax
                self.subGidDict[uname] = self._SubUidGidEntry(uname, m, self.subGidCount)
                m += self.subGidCount

    def _nonEmptySplit(theStr, delimiter):
        ret = []
        for i in theStr.split(delimiter):
            if i != "":
                ret.append(i)
        return ret

    def _readFile(self, filename):
        """Read file, returns the whole content"""

        with open(filename, 'r') as f:
            return f.read()

    def _lockPwd(self):
        """Use the same implementation as lckpwdf() in glibc"""

        assert self.lockFd is None
        self.lockFd = os.open(self.lockFile, os.O_WRONLY | os.O_CREAT | os.O_CLOEXEC, 0o600)
        try:
            t = time.clock()
            while time.clock() - t < 15.0:
                try:
                    fcntl.lockf(self.lockFd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    return
                except IOError as e:
                    if e.errno != errno.EACCESS and e.errno != errno.EAGAIN:
                        raise
                time.sleep(1.0)
            raise PgsLockError("Failed to acquire lock")
        except:
            os.close(self.lockFd)
            self.lockFd = None
            raise

    def _unlockPwd(self):
        """Use the same implementation as ulckpwdf() in glibc"""

        assert self.lockFd is not None
        os.close(self.lockFd)
        self.lockFd = None
