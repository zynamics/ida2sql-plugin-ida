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

import common
__version__ = common.__version__



class Instrumentation:
    """This class provides an instrumentation interface
    to Dismantler, with it it's possible to receive events
    as the disassemble progresses. Useful applications are
    generation of statistics and exporting data as the
    disassembly progresses."""

    instrument_hooks = (
        'new_instruction', 'new_section',
        'new_function', 'new_operand',
        'new_packet', 'new_entrypoint' )


    def __init__(self, enabled=True):

        self.enabled = enabled

        for hook in self.instrument_hooks:
        
            callable_attr = '__'+hook+'_callable__'
        
            # Create method to set a provided instrumentation
            # function to be called for the specific hooked event
            def set_hook(function, attr=callable_attr):
                setattr(self, attr, function)
                
            # Add function to the attributes of the class
            setattr(self, hook+'_callable', set_hook)
            
            # Create method to call the instrumentation function
            def call_hook(arg, attr=callable_attr):
                if self.enabled and hasattr(self, attr):
                    function = getattr(self, attr)
		    # foo
                    if function:
                        function(arg)
                    
            setattr(self, hook, call_hook)


    def enable(self):
        self.enabled = True
        
    def disable(self):
        self.enabled = False
        
