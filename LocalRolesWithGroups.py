# Copyright (c) 2002 Nuxeo SARL <http://nuxeo.com>
# Copyright (c) 2002 Préfecture du Bas-Rhin, France
# Author: Florent Guillaume <mailto:fg@nuxeo.com>
# See license info at the end of this file.
# $Id$

"""
  LocalRolesWithGroups
  Patches the local roles support in RoleManager to add groups support.
"""

__version__ = '$Revision$'[11:-2]

import string, re, urllib, os

from zLOG import LOG, INFO
from Globals import DTMLFile
from Acquisition import aq_base
from AccessControl.Permissions import change_permissions
from AccessControl.PermissionRole import PermissionRole

from AccessControl.Role import RoleManager


LOG('NuxUserGroups.LocalRolesWithGroups', INFO, 'Patching RoleManager')


__ac_local_group_roles__ = None
RoleManager.__ac_local_group_roles__ = __ac_local_group_roles__


# override
manage_listLocalRoles=DTMLFile('zmi/listLocalRoles', globals(),
                               management_view='Security',
                               help_topic='Security_Local-Roles.stx',
                               help_product='OFSP')
RoleManager.manage_listLocalRoles = manage_listLocalRoles


# new management page
manage_editLocalGroupRoles=DTMLFile('zmi/editLocalGroupRoles', globals(),
                                    management_view='Security')
RoleManager.manage_editLocalGroupRoles = manage_editLocalGroupRoles
RoleManager.manage_editLocalGroupRoles__roles__ = PermissionRole(change_permissions)


# used by listLocalRoles
def has_local_group_roles(self):
    dict = self.__ac_local_group_roles__ or {}
    return len(dict)
RoleManager.has_local_group_roles = has_local_group_roles
RoleManager.has_local_group_roles__roles__ = PermissionRole(change_permissions)


# used by listLocalRoles
def get_local_group_roles(self):
    dict = self.__ac_local_group_roles__ or {}
    keys = dict.keys()
    keys.sort()
    info = []
    for key in keys:
        value = tuple(dict[key])
        info.append((key, value))
    return tuple(info)

RoleManager.get_local_group_roles = get_local_group_roles
RoleManager.get_local_group_roles__roles__ = PermissionRole(change_permissions)


# XXX: used where ?
def groups_with_local_role(self, role):
    got = {}
    for group, roles in self.get_local_group_roles():
        if role in roles:
            got[group] = None
    return got.keys()

RoleManager.groups_with_local_role = groups_with_local_role
RoleManager.groups_with_local_role__roles__ = PermissionRole(change_permissions)


# used by listLocalRoles
def get_valid_groupids(self):
    item = self
    dict = {'role:Anonymous': None, 'role:Authenticated': None}
    while 1:
        if hasattr(aq_base(item), 'acl_users') and \
           hasattr(item.acl_users, 'getGroupNames'):
            for name in item.acl_users.getGroupNames():
                dict[name] = None
        if not hasattr(item, 'aq_parent'):
            break
        item = item.aq_parent
    keys = dict.keys()
    keys.sort()
    return tuple(keys)

RoleManager.get_valid_groupids = get_valid_groupids
RoleManager.get_valid_groupids__roles__ = PermissionRole(change_permissions)


# used by editLocalGroupRoles
def get_local_roles_for_groupid(self, groupid):
    dict=self.__ac_local_group_roles__ or {}
    return tuple(dict.get(groupid, []))

RoleManager.get_local_roles_for_groupid = get_local_roles_for_groupid
RoleManager.get_local_roles_for_groupid__roles__ = PermissionRole(change_permissions)


def manage_addLocalGroupRoles(self, groupid, roles=[], REQUEST=None):
    """Add local group roles to a user."""
    if not roles:
        raise ValueError, 'One or more roles must be given!'
    dict = self.__ac_local_group_roles__ or {}
    local_group_roles = list(dict.get(groupid, []))
    for r in roles:
        if r not in local_group_roles:
            local_group_roles.append(r)
    dict[groupid] = local_group_roles
    self.__ac_local_group_roles__ = dict
    if REQUEST is not None:
        stat = 'Your changes have been saved.'
        return self.manage_listLocalRoles(self, REQUEST, stat=stat)

RoleManager.manage_addLocalGroupRoles = manage_addLocalGroupRoles
RoleManager.manage_addLocalGroupRoles__roles__ = PermissionRole(change_permissions)


def manage_setLocalGroupRoles(self, groupid, roles=[], REQUEST=None):
    """Set local group roles for a user."""
    if not roles:
        raise ValueError, 'One or more roles must be given!'
    dict = self.__ac_local_group_roles__ or {}
    dict[groupid] = roles
    self.__ac_local_group_roles__ = dict
    if REQUEST is not None:
        stat='Your changes have been saved.'
        return self.manage_listLocalRoles(self, REQUEST, stat=stat)

RoleManager.manage_setLocalGroupRoles = manage_setLocalGroupRoles
RoleManager.manage_setLocalGroupRoles__roles__ = PermissionRole(change_permissions)


def manage_delLocalGroupRoles(self, groupids, REQUEST=None):
    """Remove all local group roles for a user."""
    dict = self.__ac_local_group_roles__ or {}
    for groupid in groupids:
        if dict.has_key(groupid):
            del dict[groupid]
    self.__ac_local_group_roles__ = dict
    if REQUEST is not None:
        stat='Your changes have been saved.'
        return self.manage_listLocalRoles(self, REQUEST, stat=stat)

RoleManager.manage_delLocalGroupRoles = manage_delLocalGroupRoles
RoleManager.manage_delLocalGroupRoles__roles__ = PermissionRole(change_permissions)


# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as published
# by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.
