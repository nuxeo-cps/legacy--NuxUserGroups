# (C) Copyright 2003 Nuxeo SARL <http://nuxeo.com>
# Author: Florent Guillaume <fg@nuxeo.com>
#
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
#
# $Id$
"""
  MembershipToolWithGroups
  Patches CMFCore Membership Tool to add groups support for local roles.
"""

__version__ = '$Revision$'[11:-2]

from zLOG import LOG, INFO, DEBUG
from AccessControl.PermissionRole import PermissionRole

from Products.CMFCore.CMFCorePermissions import View
from Products.CMFCore.MembershipTool import MembershipTool

LOG('NuxUserGroups.MembershipToolWithGroups', INFO, 'Patching MembershipTool')


def setLocalGroupRoles(self, obj, ids, role, reindex=1):
    """Set local group roles on an item."""
    member = self.getAuthenticatedMember()
    my_roles = member.getRolesInContext(obj)
    if 'Manager' in my_roles or role in my_roles:
        for id in ids:
            roles = list(obj.get_local_roles_for_groupid(id))
            if role not in roles:
                roles.append(role)
                obj.manage_setLocalGroupRoles(id, roles)
    if reindex:
        obj.reindexObjectSecurity()

MembershipTool.setLocalGroupRoles = setLocalGroupRoles
MembershipTool.setLocalGroupRoles__roles__ = PermissionRole(View)


def deleteLocalGroupRoles(self, obj, ids, reindex=1):
    """Delete local group roles for members member_ids."""
    member = self.getAuthenticatedMember()
    my_roles = member.getRolesInContext(obj)
    if 'Manager' in my_roles:
        obj.manage_delLocalGroupRoles(ids)
    else:
        # Only remove the roles we have.
        for id in ids:
            roles = obj.get_local_roles_for_groupid(id)
            roles = [r for r in roles if r not in my_roles]
            if roles:
                obj.manage_setLocalGroupRoles(id, roles)
            else:
                obj.manage_delLocalGroupRoles([id])
    if reindex:
        obj.reindexObjectSecurity()

MembershipTool.deleteLocalGroupRoles = deleteLocalGroupRoles
MembershipTool.deleteLocalGroupRoles__roles__ = PermissionRole(View)
