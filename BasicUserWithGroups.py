# (c) 2002 Préfecture du Bas-Rhin, France
# (c) 2002 Nuxeo SARL <http://nuxeo.com>
# (c) 2002 Florent Guillaume <mailto:fg@nuxeo.com>
# See license info at the end of this file.
# $Id$

"""
  BasicUserWithGroups
  Patches the AccessControl.User class for basic groups support.
"""

__version__ = '$Revision$'[11:-2]


from zLOG import LOG, INFO

from Acquisition import aq_base
from Globals import DTMLFile
from AccessControl.User import BasicUser, BasicUserFolder, \
     _remote_user_mode
from AccessControl.PermissionRole import _what_not_even_god_should_do


LOG("NuxUserGroups.BasicUserWithGroups", INFO, "Patching BasicUser")


#
# Patch  BasicUser for basic group support.
# Security is dealt with by BasicUser using
# __allow_access_to_unprotected_subobjects__
#

def getGroups(self):
    """Returns the groups of the user"""
    groups = getattr(self, '_usergroups', [])
    return tuple(groups)
BasicUser.getGroups = getGroups


def _setGroups(self, groupnames):
    self._usergroups = list(groupnames)
BasicUser._setGroups = _setGroups
BasicUser._setGroups__roles__ = () # Private


def _addGroups(self, groupnames):
    groups = list(getattr(self, '_usergroups', []))
    groups.extend(groupnames)
    self._usergroups = groups
BasicUser._addGroups = _addGroups
BasicUser._addGroups__roles__ = () # Private


def _delGroups(self, groupnames):
    groups = list(getattr(self, '_usergroups', []))
    for groupname in groupnames:
        groups.remove(groupname)
    self._usergroups = groups
BasicUser._delGroups = _delGroups
BasicUser._delGroups__roles__ = () # Private

#
# Patch local roles treatment in BasicUser to support groups.
#

def getRolesInContext(self, object):
    """Return the list of roles assigned to the user,
       including local roles assigned in context of
       the passed in object."""
    name=self.getUserName()
    groups=self.getGroups() # groups
    roles=self.getRoles()
    local={}
    object=getattr(object, 'aq_inner', object)
    while 1:
        local_roles = getattr(object, '__ac_local_roles__', None)
        if local_roles:
            if callable(local_roles):
                local_roles=local_roles()
            dict=local_roles or {}
            for r in dict.get(name, []):
                local[r]=1
        # deal with groups
        local_group_roles = getattr(object, '__ac_local_group_roles__', None)
        if local_group_roles:
            if callable(local_group_roles):
                local_group_roles=local_group_roles()
            dict=local_group_roles or {}
            for g in groups:
                for r in dict.get(g, []):
                    local[r]=1
        # end groups
        inner = getattr(object, 'aq_inner', object)
        parent = getattr(inner, 'aq_parent', None)
        if parent is not None:
            object = parent
            continue
        if hasattr(object, 'im_self'):
            object=object.im_self
            object=getattr(object, 'aq_inner', object)
            continue
        break
    roles=list(roles) + local.keys()
    return roles
BasicUser.getRolesInContext = getRolesInContext


def allowed(self, object, object_roles=None):
    """Check whether the user has access to object. The user must
       have one of the roles in object_roles to allow access."""

    if object_roles is _what_not_even_god_should_do: return 0

    # Short-circuit the common case of anonymous access.
    if object_roles is None or 'Anonymous' in object_roles:
        return 1

    # Provide short-cut access if object is protected by 'Authenticated'
    # role and user is not nobody
    if 'Authenticated' in object_roles and (
        self.getUserName() != 'Anonymous User'):
        return 1

    # Check for ancient role data up front, convert if found.
    # This should almost never happen, and should probably be
    # deprecated at some point.
    if 'Shared' in object_roles:
        object_roles = self._shared_roles(object)
        if object_roles is None or 'Anonymous' in object_roles:
            return 1

    # Check for a role match with the normal roles given to
    # the user, then with local roles only if necessary. We
    # want to avoid as much overhead as possible.
    user_roles = self.getRoles()
    for role in object_roles:
        if role in user_roles:
            if self._check_context(object):
                return 1
            return None

    # Still have not found a match, so check local roles. We do
    # this manually rather than call getRolesInContext so that
    # we can incur only the overhead required to find a match.
    inner_obj = getattr(object, 'aq_inner', object)
    user_name = self.getUserName()
    groups = self.getGroups() # groups
    while 1:
        local_roles = getattr(inner_obj, '__ac_local_roles__', None)
        if local_roles:
            if callable(local_roles):
                local_roles = local_roles()
            dict = local_roles or {}
            local_roles = dict.get(user_name, [])
            for role in object_roles:
                if role in local_roles:
                    if self._check_context(object):
                        return 1
                    return 0
        # deal with groups
        local_group_roles = getattr(inner_obj, '__ac_local_group_roles__', None)
        if local_group_roles:
            if callable(local_group_roles):
                local_group_roles = local_group_roles()
            dict = local_group_roles or {}
            for g in groups:
                local_group_roles = dict.get(g, [])
                if local_group_roles:
                    for role in object_roles:
                        if role in local_group_roles:
                            if self._check_context(object):
                                return 1
                            return 0
        # end groups
        inner = getattr(inner_obj, 'aq_inner', inner_obj)
        parent = getattr(inner, 'aq_parent', None)
        if parent is not None:
            inner_obj = parent
            continue
        if hasattr(inner_obj, 'im_self'):
            inner_obj=inner_obj.im_self
            inner_obj=getattr(inner_obj, 'aq_inner', inner_obj)
            continue
        break
    return None
BasicUser.allowed = allowed


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
