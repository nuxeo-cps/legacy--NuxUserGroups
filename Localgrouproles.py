# Copyright (c) 2002 Nuxeo SARL <http://nuxeo.com>
# Copyright (c) 2002 Florent Guillaume <mailto:fg@nuxeo.com>
# See licence info at the end of this file.
# $Id$

"""
  Localgrouproles
  This monkey-patches the local roles support
  to add group knowledge.
"""

__version__ = '$Revision$'[11:-2]

import string, re, urllib, os

from zLOG import LOG, INFO
from Globals import InitializeClass, DTMLFile
from Acquisition import aq_base

from AccessControl.Role import RoleManager


__ac_local_group_roles__ = None
RoleManager.__ac_local_group_roles__ = __ac_local_group_roles__


# added
__ac_permissions__ = (
    ('Change permissions',
     ('manage_setLocalGroupRoles', 'manage_addLocalGroupRoles',
      'manage_delLocalGroupRoles',
      )),
    )


# override
manage_listLocalRoles=DTMLFile('zmi/listLocalRoles', globals(),
                               management_view='Security',
                               help_topic='Security_Local-Roles.stx',
                               help_product='OFSP')
RoleManager.manage_listLocalRoles = manage_listLocalRoles


manage_editLocalGroupRoles=DTMLFile('zmi/editLocalGroupRoles', globals(),
                                    management_view='Security')
RoleManager.manage_editLocalGroupRoles = manage_editLocalGroupRoles


# used by listLocalRoles
def has_local_group_roles(self):
    dict=self.__ac_local_group_roles__ or {}
    return len(dict)
RoleManager.has_local_group_roles = has_local_group_roles


# used by listLocalRoles
def get_local_group_roles(self):
    dict=self.__ac_local_group_roles__ or {}
    keys=dict.keys()
    keys.sort()
    info=[]
    for key in keys:
        value=tuple(dict[key])
        info.append((key, value))
    return tuple(info)
RoleManager.get_local_group_roles = get_local_group_roles


# used where ?
def groups_with_local_role(self, role):
    got = {}
    for group, roles in self.get_local_group_roles():
        if role in roles:
            got[group] = 1
    return got.keys()
RoleManager.groups_with_local_role = groups_with_local_role


# used by listLocalRoles
def get_valid_groupids(self):
    item=self
    dict={}
    while 1:
        if hasattr(aq_base(item), 'acl_users') and \
           hasattr(item.acl_users, 'listGroupNames'):
            for name in item.acl_users.listGroupNames():
                dict[name]=1
        if not hasattr(item, 'aq_parent'):
            break
        item = item.aq_parent
    keys=dict.keys()
    keys.sort()
    return tuple(keys)
RoleManager.get_valid_groupids = get_valid_groupids


# used by editLocalGroupRoles
def get_local_roles_for_groupid(self, groupid):
    dict=self.__ac_local_group_roles__ or {}
    return tuple(dict.get(groupid, []))
RoleManager.get_local_roles_for_groupid = get_local_roles_for_groupid


def manage_addLocalGroupRoles(self, groupid, roles=[], REQUEST=None):
    """Add local group roles to a user."""
    if not roles:
        raise ValueError, 'One or more roles must be given!'
    dict=self.__ac_local_group_roles__ or {}
    local_group_roles = list(dict.get(groupid, []))
    for r in roles:
        if r not in local_group_roles:
            local_group_roles.append(r)
    dict[groupid] = local_group_roles
    self.__ac_local_group_roles__=dict
    if REQUEST is not None:
        stat='Your changes have been saved.'
        return self.manage_listLocalRoles(self, REQUEST, stat=stat)
RoleManager.manage_addLocalGroupRoles = manage_addLocalGroupRoles


def manage_setLocalGroupRoles(self, groupid, roles=[], REQUEST=None):
    """Set local group roles for a user."""
    if not roles:
        raise ValueError, 'One or more roles must be given!'
    dict=self.__ac_local_group_roles__ or {}
    dict[groupid]=roles
    self.__ac_local_group_roles__=dict
    if REQUEST is not None:
        stat='Your changes have been saved.'
        return self.manage_listLocalRoles(self, REQUEST, stat=stat)
RoleManager.manage_setLocalGroupRoles = manage_setLocalGroupRoles


def manage_delLocalGroupRoles(self, groupids, REQUEST=None):
    """Remove all local group roles for a user."""
    dict=self.__ac_local_group_roles__ or {}
    for groupid in groupids:
        if dict.has_key(groupid):
            del dict[groupid]
    self.__ac_local_group_roles__=dict
    if REQUEST is not None:
        stat='Your changes have been saved.'
        return self.manage_listLocalRoles(self, REQUEST, stat=stat)
RoleManager.manage_delLocalGroupRoles = manage_delLocalGroupRoles





if getattr(RoleManager, '__patched_by_localgrouproles', 0):
    LOG('Localgrouproles', INFO, 'RoleManager already patched before this refresh')
else:
    RoleManager.__patched_by_localgrouproles = 1
    RoleManager.__ac_permissions__ = __ac_permissions__ + \
                                     RoleManager.__ac_permissions__
    LOG('Localgrouproles', INFO, 'Patching RoleManager')


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
