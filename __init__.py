# Copyright (c) 2002 Nuxeo SARL <http://nuxeo.com>
# Copyright (c) 2002 Florent Guillaume <mailto:fg@nuxeo.com>
# Copyright (c) 2002 Préfecture du Bas-Rhin, France
# See license info at the end of this file.
# $Id$

from UserFolderWithGroups import UserFolderWithGroups, addUserFolderWithGroups

# Import dynamic patches
import BasicUserWithGroups
import LocalRolesWithGroups
try:
    import MembershipToolWithGroups
except ImportError:
    pass

def initialize(registrar):
    registrar.registerClass(
        UserFolderWithGroups,
        permission='Add User Folders',
        constructors=(addUserFolderWithGroups,),
        icon='UserFolder_icon.gif')


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
