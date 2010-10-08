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


"""Generic architecure support for instruction parsing.

All the architecture modules should extend this one and provide the
defined methods.
"""

import idautils
import idaapi
import idc
import re


def ida_hexify(val):
    """Utility function to render hex values as shown in IDA."""
    if val < 10:
        return '%d' % val
    return '%xh' % val



class Instruction:
    def __init__(self, itype, size, ip):
        self.itype = itype
        self.size = size
        self.ip = ip


class ExpressionNamedValue:
    def __init__(self, value, name):
        self.value = value
        self.name = name
        

class Arch:

    NODE_TYPE_OPERATOR_PLUS         = '+'
    NODE_TYPE_OPERATOR_MINUS        = '-'
    NODE_TYPE_OPERATOR_TIMES        = '*'
    #NODE_TYPE_OPERATOR_DEREFERENCE  = '['
    NODE_TYPE_OPERATOR_LIST         = '{'
    NODE_TYPE_OPERATOR_EXCMARK      = '!'
    NODE_TYPE_OPERATOR_COMMA        = ','
    NODE_TYPE_OPERATOR_LSL        = 'LSL'
    NODE_TYPE_OPERATOR_LSR        = 'LSR'
    NODE_TYPE_OPERATOR_ASR        = 'ASR'
    NODE_TYPE_OPERATOR_ROR        = 'ROR'
    NODE_TYPE_OPERATOR_RRX        = 'RRX'
    
    NODE_TYPE_OPERATOR_WIDTH_BYTE_1   = 'b1'    # Byte
    NODE_TYPE_OPERATOR_WIDTH_BYTE_2   = 'b2'    # Word
    NODE_TYPE_OPERATOR_WIDTH_BYTE_3   = 'b3'    #
    NODE_TYPE_OPERATOR_WIDTH_BYTE_4   = 'b4'    # Double-Word
    NODE_TYPE_OPERATOR_WIDTH_BYTE_5   = 'b5'    #
    NODE_TYPE_OPERATOR_WIDTH_BYTE_6   = 'b6'    #
    NODE_TYPE_OPERATOR_WIDTH_BYTE_7   = 'b7'    #
    NODE_TYPE_OPERATOR_WIDTH_BYTE_8   = 'b8'    # Quad-Word
    NODE_TYPE_OPERATOR_WIDTH_BYTE_9   = 'b9'    #
    NODE_TYPE_OPERATOR_WIDTH_BYTE_10  = 'b10'   #
    NODE_TYPE_OPERATOR_WIDTH_BYTE_12  = 'b12'   # Packed Real Format mc68040
    NODE_TYPE_OPERATOR_WIDTH_BYTE_14  = 'b14'   #
    NODE_TYPE_OPERATOR_WIDTH_BYTE_16  = 'b16'   #
    NODE_TYPE_OPERATOR_WIDTH_BYTE_VARIABLE  = 'b_var'   # Variable size
    
    NODE_TYPE_VALUE                 = '#'
    NODE_TYPE_SYMBOL                = '$'
    NODE_TYPE_REGISTER              = 'r'
    NODE_TYPE_SIZE_PREFIX           = 'S'
    NODE_TYPE_DEREFERENCE           = '['
    
    
    OPERATORS = (NODE_TYPE_OPERATOR_PLUS, NODE_TYPE_OPERATOR_MINUS, 
        NODE_TYPE_OPERATOR_TIMES, #NODE_TYPE_OPERATOR_DEREFERENCE,
        NODE_TYPE_OPERATOR_LIST, NODE_TYPE_OPERATOR_EXCMARK,
        NODE_TYPE_OPERATOR_COMMA, NODE_TYPE_OPERATOR_LSL, NODE_TYPE_OPERATOR_LSR,
        NODE_TYPE_OPERATOR_ASR, NODE_TYPE_OPERATOR_ROR, NODE_TYPE_OPERATOR_RRX)
        
    WIDTH_OPERATORS = ( 
        NODE_TYPE_OPERATOR_WIDTH_BYTE_1, NODE_TYPE_OPERATOR_WIDTH_BYTE_2,
        NODE_TYPE_OPERATOR_WIDTH_BYTE_3, NODE_TYPE_OPERATOR_WIDTH_BYTE_4, 
        NODE_TYPE_OPERATOR_WIDTH_BYTE_5, NODE_TYPE_OPERATOR_WIDTH_BYTE_6,
        NODE_TYPE_OPERATOR_WIDTH_BYTE_7, NODE_TYPE_OPERATOR_WIDTH_BYTE_8,
        NODE_TYPE_OPERATOR_WIDTH_BYTE_9, NODE_TYPE_OPERATOR_WIDTH_BYTE_10,
        NODE_TYPE_OPERATOR_WIDTH_BYTE_10, NODE_TYPE_OPERATOR_WIDTH_BYTE_12,
        NODE_TYPE_OPERATOR_WIDTH_BYTE_14,  NODE_TYPE_OPERATOR_WIDTH_BYTE_16,
        NODE_TYPE_OPERATOR_WIDTH_BYTE_VARIABLE)
    
    LEAFS = (NODE_TYPE_SYMBOL, NODE_TYPE_VALUE)
    
    
    def __init__(self):
    
        # To be set by the architecture specific module if specific instructions
        # exist for the purpose
        #
        self.INSTRUCTIONS_CALL = []
        self.INSTRUCTIONS_CONDITIONAL_BRANCH = []
        self.INSTRUCTIONS_UNCONDITIONAL_BRANCH = []
        self.INSTRUCTIONS_RET = []
        self.INSTRUCTIONS_BRANCH = []

        if hasattr( idaapi, 'get_inf_structure' ):
            inf = idaapi.get_inf_structure()
        else:
            inf = idaapi.cvar.inf
    
        # Find the null character of the string (if any)
        #
        null_idx = inf.procName.find(chr(0))
        if null_idx > 0:
            self.processor_name = inf.procName[:null_idx]
        else:
            self.processor_name = inf.procName
        
        self.os_type = inf.ostype
        self.asmtype = inf.asmtype

        # RegExp to parse stack variable names as IDA
        # returns an string containing some sort of reference
        # to their frame.
        #        
        self.stack_name_parse = re.compile(r'.*fr[0-9a-f]+\.([^ ].*)')

        
        self.current_instruction_type = None
        
        # To be filled by the architecture module
        #
        self.arch_name = None
        
    def as_byte_value(self, c):
        """Helper function to deal with the changing type of some byte-size fields.
        
        In older versions of IDAPython those where returned as characters while in newer
        they are returned as ints. This will always return int.
        """
        
        if isinstance(c, str):
            return ord(c)
        
        return c
    
    def get_architecture_name(self):
        """Fetch the name to be used to identify the architecture."""
        
        # Get the addressing mode of the first segment in the IDB and
        # set it to describe the module in the database.
        # This would need to be rethought for the cases where addressing
        # might change withing a module.
        #
        bitness = idc.GetSegmentAttr( list( idautils.Segments() )[0], idc.SEGATTR_BITNESS)
        
        if bitness == 0:
            bitness = 16
        elif bitness == 1:
            bitness = 32
        elif bitness == 2:
            bitness = 64
            
        return '%s-%d' % (self.arch_name, bitness)
        
    
    def get_stack_var_name(self, var):
        """Get the name of a stack variable and return it parsed."""
    
        var_name = idaapi.get_struc_name(var.id)
        if not isinstance(var_name, str):
            return None
            
        res = self.stack_name_parse.match(var_name)
        if res:
            return res.group(1)
        else:
            #raise Exception('Cannot get operand name.')
            #print '*** Cannot get operand name!!! ***'
            return None
    
    
    def get_address_name(self, value):
        """Return the name associated to the address."""
        
        name = idc.Name(value)
        
        if name:
            return name
            
        return None
        
    
    def get_operand_stack_variable_name(self, address, op, idx):
        """Return the name of any variable referenced from this operand."""
    
        if op.addr>2**31:
            addr = -(2**32-op.addr)
        else:
            addr = op.addr
            
        try:
            # In IDA 5.7 get_stkvar takes 2 arguments
            var =  idaapi.get_stkvar(op, addr)
        except TypeError:
            # In earlier versions it takes 3...
            var =  idaapi.get_stkvar(op, addr, None)
            
        if var:
            if isinstance(var, (tuple, list)):
                # get the member_t
                # In IDA 5.7 this returns a tuple: (member_t, actval)
                # so we need to get the actual object from the first
                # item. In previous version that was what was returned
                var = var[0]
        
            func = idaapi.get_func(address)

            stackvar_offset = idaapi.calc_stkvar_struc_offset(
                func, address, idx)
            stackvar_start_offset = var.soff
            stackvar_offset_delta = stackvar_offset-stackvar_start_offset
            
            delta_str = ''
            
            if stackvar_offset_delta != 0:
                delta_str = '+0x%x' % stackvar_offset_delta
            
            
            disp_str = ''
            
            # 4 is the value of the stack pointer register SP/ESP in x86. This
            # should not break other archs but needs to be here or otherwise would
            # need to override the whole method in metapc...
            #
            if op.reg == 4:
                difference_orig_sp_and_current = idaapi.get_spd(func, address)
                disp_str = ida_hexify( -difference_orig_sp_and_current-idc.GetFrameRegsSize(address) ) + '+'
            
            name = self.get_stack_var_name(var)
            
            if name:
                return disp_str + name + delta_str
            
        return None
    

    def is_call(self, instruction=None):
        """Return whether the last instruction processed is a call or not."""
                   
        # If there are instructions defined as being specifically used for "calls"
        # we take those as a unique indentifier for whether the instruction is
        # if fact a call or not
        #
        if self.INSTRUCTIONS_CALL:
            if instruction.itype in self.INSTRUCTIONS_CALL:
                return True
            else:
                return False

        if not instruction.itype in self.INSTRUCTIONS_BRANCH:
            return False
            
        trgt = list( idautils.CodeRefsFrom(instruction.ip, 0) )
        if not trgt:
            trgt = list( idautils.DataRefsFrom(instruction.ip) )
        
        if len(trgt) > 0:
        
            # When getting the name there's a fall back from
            # using GetFunctionName() to Name() as sometimes
            # imported functions are not defined as functions
            # and the former will return an empty string while
            # the later will return the import name.
            #
            trgt_name = idc.GetFunctionName(trgt[0])
            if trgt_name=='':
                 trgt_name = idc.Name(trgt[0])
                 
            trgt_name_prev = idc.GetFunctionName(trgt[0]-1)
            if trgt_name_prev=='':
                trgt_name_prev = idc.Name(trgt[0]-1)
            
            # In order for the reference to be a call the following
            # must hold.
            # -There must be a valid function name
            # -The function name should be different at the target
            # address then the name in the immediately posterior
            # address (i.e. target must point to begging of function)
            # -The function name should be different than the function
            # name of the branch source
            #
            if( trgt_name is not None and
                trgt_name != '' and
                trgt_name != trgt_name_prev and
                idc.GetFunctionName(instruction.ip) != trgt_name ):
                
                return True
                
        return False


    def is_end_of_flow(self, instruction):
        """Return whether the last instruction processed end the flow."""
            
        next_addr = instruction.ip+idc.ItemSize(instruction.ip)
        next_addr_flags = idc.GetFlags(next_addr)
        if idc.isCode(next_addr_flags) and idc.isFlow(next_addr_flags):
            return False

        return True
    

    def is_conditional_branch(self, instruction):
        """Return whether the instruction is a conditional branch"""

        next_addr = instruction.ip+idc.ItemSize(instruction.ip)
        next_addr_flags = idc.GetFlags(next_addr)
        if (
            idc.isCode(next_addr_flags) and
            idc.isFlow(next_addr_flags) and
            (instruction.itype in self.INSTRUCTIONS_BRANCH) ):
            
            return True

        return False


    def is_unconditional_branch(self, instruction):
        """Return whether the instruction is an unconditional branch"""

        next_addr = instruction.ip+idc.ItemSize(instruction.ip)
        next_addr_flags = idc.GetFlags(next_addr)
        
        if ( (instruction.itype in self.INSTRUCTIONS_BRANCH) and
            (not idc.isCode(next_addr_flags)) or
            (not idc.isFlow(next_addr_flags)) ):
            
            return True

        return False

    #
    # Methods to override by implementing classes
    #
    
    def check_arch(self):
        """Test whether this module can process the current architecture."""
        pass

    def process_instruction(self, packet, addr):
        """Architecture specific instruction processing.
        
        The functions can call 'process_instruction_generic' which
        will do some processing generic to all architectures.
        """
        pass
        #return instruction

    
    def get_mnemonic(self, addr):
        """Return the mnemonic for the current instruction.
        
        Achitecture specific modules can define a new method
        to process mnemonics in different ways.
        """
        
        return idaapi.ua_mnem(addr)
        

    def operands_parser(self, address, operands):
        """Parse operands.
        
        Can be defined in architecture specific modules to
        process the whole list of operands before or after
        parsing, if necessary. In Intel, for instance, is
        used to post process operands where the target is
        also used as source but included only once, that
        happens for instance with the IMUL instruction.
        """

        op_list = []
        
        for op, idx in operands:
            current_operand = self.single_operand_parser(address, op, idx)

            if not current_operand:
                continue

            if isinstance(current_operand[0], (list, tuple)):
                op_list.extend( current_operand )
            else:
                op_list.append( current_operand )
                
        operands = op_list
        
        return op_list


    #def process_instruction_generic(self, addr, operand_parser):
    def process_instruction_generic(self, addr):
        """Architecture agnostic instruction parsing."""
        
        # Retrieve the instruction mnemonic
        #
        i_mnemonic = self.get_mnemonic(addr)
        if not i_mnemonic:
            return None, None, None, None, None
            
        # Set the current location to the instruction to disassemble
        #
        #idaapi.jumpto(addr)
        #idaapi.ua_ana0(addr)

        # Up to IDA 5.7 it was called ua_code...
        if hasattr(idaapi, 'ua_code'):
            # Gergely told me of using ua_code() and idaapi.cvar.cmd
            # instead of jumpto() and get_current_instruction(). The latter
            # where always making IDA to reposition the cursor and refresh
            # the GUI, which was quite painful
            #
            idaapi.ua_code(addr)
            # Retrieve the current instruction's structure and
            # set its type
            ida_instruction = idaapi.cvar.cmd
        else:
            # now it's called decode_insn()
            idaapi.decode_insn(addr)
            # Retrieve the current instruction's structure and
            # set its type
            ida_instruction = idaapi.cmd


        instruction = Instruction(
            ida_instruction.itype, ida_instruction.size, ida_instruction.ip)
        self.current_instruction_type = instruction.itype
        
        
        # Try to process as many operands as IDA supports
        #
        # Up to IDA 5.7 it was called ua_code... so we use it to check for 5.7
        if hasattr(idaapi, 'ua_code'):
            operands = self.operands_parser( addr, [(
                idaapi.get_instruction_operand(ida_instruction, idx),
                idx ) for idx in range(6)] )
        else:
            operands = self.operands_parser( addr, [(
                ida_instruction.Operands[idx],
                idx ) for idx in range(6)] )
                
        # Retrieve the operand strings
        #
        operand_strings = [
            idc.GetOpnd(addr, idx) for idx in range(len(operands))]
        
        # Get the instruction data
        #
        data = ''.join(
            [chr(idaapi.get_byte(addr+i)) for i in range(idc.ItemSize(addr))])
        
        # Return the mnemonic and the operand AST
        #
        return instruction, i_mnemonic, operands, operand_strings, data
            
