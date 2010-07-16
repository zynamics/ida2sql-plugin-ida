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

__revision__ = "$LastChangedRevision: 5095 $"
__author__ = 'Ero Carrera'
__version__ = '%d' % int( __revision__[21:-2] )
__license__ = 'GPL'


FATAL_CANNOT_CONNECT_TO_DATABASE    = 0x10
FATAL_MODULE_ALREADY_IN_DATABASE    = 0x11
FATAL_INVALID_SCHEMA_VERSION        = 0x12


BRANCH_TYPE_TRUE =          0
BRANCH_TYPE_FALSE =         1
BRANCH_TYPE_UNCONDITIONAL = 2
BRANCH_TYPE_SWITCH =        3


class DB_ENGINE:
    MYSQL = 'MySQL'
    POSTGRESQL = 'PostgreSQL'
    MYSQLDUMP = 'MySQL File Dump'
    SQLITE = 'SQLite'

class FUNC_TYPE:
    FUNCTION_STANDARD   = 0
    FUNCTION_LIBRARY    = 1
    FUNCTION_IMPORTED   = 2
    FUNCTION_THUNK      = 3

class REF_TYPE:
    CONDITIONAL_BRANCH_TRUE     = BRANCH_TYPE_TRUE       # 0
    CONDITIONAL_BRANCH_FALSE    = BRANCH_TYPE_FALSE     # 1
    UNCONDITIONAL_BRANCH        = BRANCH_TYPE_UNCONDITIONAL # 2
    BRANCH_SWITCH               = BRANCH_TYPE_SWITCH    # 3

    CALL_DIRECT                 = 4
    CALL_INDIRECT               = 5
    CALL_INDIRECT_VIRTUAL       = 6

    DATA                        = 7
    DATA_STRING                 = 8


def log_message(s):
    print 'IDA2SQL> %s' % s

def dbg_message(s):
    print 'IDA2SQL DBG> %s' % s



class Section:
    """Data container to encapsulate segment information."""

    def __init__(self, name, base, start, end, data=None):
    
        self.name = name
        self.base = base
        self.start = start
        self.end = end
        self.data = data
        
        

class DismantlerDataPacket:
    """Data container to encapsulate information sent from workers."""

    def __init__(self):
        self.instructions = dict()
        self.address_references = set()
#        self.code_references = set()
        self.branches = set()
        self.calls = dict()
        self.todo_data_refs = list()
        self.todo_code_refs = list()
        self.disassembly = dict()
        self.comments = list() # list of pairs (address, comment)
    
    # Private methods
    #
    def _add_branch(self, src, dst):
        self.branches.add((src, dst))
    
    def add_todo_data_ref(self, src, dst):
        self.todo_data_refs.append((src, dst))
    
    def _add_todo_code_ref(self, src, dst):
        """Append address to analysis queue."""
        
        self.todo_code_refs.append((src, dst))
    
    def _add_call(self, src, dst):
        self.calls[src] = dst
    
    
    # Public methods
    #
    def add_comment(self, address, comment):
        self.comments.append((address, comment))
        
    
    def add_instruction(self,
        instruction, address, mnemonic,
#        instruction_string, instruction_tree, data):
        operands, operand_trees, data):
        
        self.disassembly[address] = (instruction, data)
        self.instructions[address] = (instruction, mnemonic,
            operands, operand_trees, data)
#            instruction_string, instruction_tree, data)
    
    def add_data_reference(self, src, dst):
#        self.data_references.add((src, dst))
        self.address_references.add((src, dst, REF_TYPE.DATA))
        
#    def add_code_reference(self, src, dst):
#        self.code_references.add((src, dst))
    
    def add_conditional_branch_true(self, src, dst):
        self._add_branch(src, dst)
        self.address_references.add((src, dst, REF_TYPE.CONDITIONAL_BRANCH_TRUE))
    
    def add_conditional_branch_false(self, src, dst):
        self._add_branch(src, dst)
        self.address_references.add((src, dst, REF_TYPE.CONDITIONAL_BRANCH_FALSE))
    
    def add_unconditional_branch(self, src, dst):
        self._add_branch(src, dst)
        self.address_references.add((src, dst, REF_TYPE.UNCONDITIONAL_BRANCH))
    
    def add_direct_call(self, src, dst):
        self._add_call(src, dst)
        self.address_references.add((src, dst, REF_TYPE.CALL_DIRECT))
        self._add_todo_code_ref(src, dst)
    
    def add_indirect_call(self, src, dst):
        self._add_call(src, dst)
        self.address_references.add((src, dst, REF_TYPE.CALL_INDIRECT))
        self._add_todo_code_ref(src, dst)
    
    def add_indirect_virtual_call(self, src, dst):
        """Add a call reference to a function which does not exist.
        
        Any function which does actually exist in the binary at
        dissasembly time but it's known to exist and a later
        stage can be referenced with a virtual reference.
        A case of such references is a call to an imported function.
        
        The reason a specific method is provided is in order to
        differentiate between references to actual code (which can be
        appended to a processing queue) and those to "virtual" code.
        """
        
        self._add_call(src, dst)
        self.address_references.add((src, dst, REF_TYPE.CALL_INDIRECT_VIRTUAL))
    

