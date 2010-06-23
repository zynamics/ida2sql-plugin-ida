# -*- coding: Latin-1 -*-

"""Sabre Security IDA to SQL exporter.

This module exports IDA's IDB database information into Sabre-Security's SQL
format.

References:

Sabre-Security GmbH:    http://sabre-security.com/
MySQL:                  http://www.mysql.com
IDA:                    http://www.datarescue.com/idabase/

Programmed and tested with IDA 5.0, Python 2.4.4 and IDAPython 0.8.0 on Windows
by Ero Carrera (c) Sabre-Security 2006	[ero.carrera@sabre-security.com]

Distributed under GPL license [http://opensource.org/licenses/gpl-license.php].
"""

__author__ = 'Ero Carrera'
__license__ = 'GPL'

import ida_to_sql
import common
__version__ = common.__version__
