# -*- coding: Latin-1 -*-

"""zynamics GmbH IDA to SQL exporter.

This module exports IDA's IDB database information into zynamics's SQL format.

References:

zynamics GmbH:    http://www.zynamics.com/
MySQL:            http://www.mysql.com
IDA:              http://www.datarescue.com/idabase/

Programmed and tested with IDA 5.4-5.7, Python 2.5/2.6 and IDAPython >1.0 on Windows & OSX
by Ero Carrera & the zynamics team (c) zynamics GmbH 2006 - 2010 [ero.carrera@zynamics.com]

Distributed under GPL license [http://opensource.org/licenses/gpl-license.php].
"""

__author__ = 'Ero Carrera'
__license__ = 'GPL'

import os
try:
    import idaapi
except ImportError:
    # This module can sometimes be invoked outside IDA, so
    # don't blow up if that happens
    #
    pass


ida2sql_path = os.environ.get('IDA2SQLPATH', None)

if ida2sql_path:
    print 'Environment variable IDA2SQLPATH found: [%s]' % ida2sql_path
    os.sys.path.append(ida2sql_path)
else:
    print 'Environment variable IDA2SQLPATH not found'
    os.sys.path.append(idaapi.idadir(os.path.join('plugins', 'ida2sql.zip')))

# Import the main module located in the IDA plugins directory
#

import ida_to_sql

import ida_to_sql.common

__version__ = ida_to_sql.common.__version__

# Start the exporter
#
ida_to_sql.ida_to_sql.main()

#import cProfile
#cProfile.run('ida_to_sql.ida_to_sql.main()', 'ida2sql_profiling_stats.txt')
