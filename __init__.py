# Copyright (c) 2002 Nuxeo SARL <http://nuxeo.com>
# Copyright (c) 2002 Florent Guillaume <mailto:fg@nuxeo.com>
# See licence info at the end of this file.
# $Id$

#from ZClasses import createZClassForBase

from Userwithgroups import UserwithgroupsFolder, addUserwithgroupsFolder

import Localgrouproles

#createZClassForBase(UserwithgroupsFolder, globals(),
#                    'ZUserwithgroupsFolder', 'Userwithgroups Folder')

def initialize(registrar):
    registrar.registerClass(
        UserwithgroupsFolder,
        permission='Add User Folders',
        constructors=(addUserwithgroupsFolder,),
        icon='UserFolder_icon.gif', # XXX change image ?
        )





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
