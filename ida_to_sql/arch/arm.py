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


import arch
import idc
import idaapi


# IDA's operand types
#
OPERAND_TYPE_NO_OPERAND     = 0
OPERAND_TYPE_REGISTER       = 1
OPERAND_TYPE_MEMORY         = 2
OPERAND_TYPE_PHRASE         = 3
OPERAND_TYPE_DISPLACEMENT   = 4
OPERAND_TYPE_IMMEDIATE      = 5
OPERAND_TYPE_FAR            = 6
OPERAND_TYPE_NEAR           = 7
OPERAND_TYPE_IDPSPEC0       = 8
OPERAND_TYPE_IDPSPEC1       = 9
OPERAND_TYPE_IDPSPEC2       = 10
OPERAND_TYPE_IDPSPEC3       = 11
OPERAND_TYPE_IDPSPEC4       = 12    # MMX register
OPERAND_TYPE_IDPSPEC5       = 13    # XMM register



class Arch(arch.Arch):
    """Architecture specific processing for 'ARM'"""
    
    
    INSTRUCTIONS = [ 'ARM_null', 'ARM_ret', 'ARM_nop', 'ARM_b', 'ARM_bl', 'ARM_asr', 'ARM_lsl', 'ARM_lsr', 'ARM_ror', 'ARM_neg', 'ARM_and', 'ARM_eor', 'ARM_sub', 'ARM_rsb', 'ARM_add', 'ARM_adc', 'ARM_sbc', 'ARM_rsc', 'ARM_tst', 'ARM_teq', 'ARM_cmp', 'ARM_cmn', 'ARM_orr', 'ARM_mov', 'ARM_bic', 'ARM_mvn', 'ARM_mrs', 'ARM_msr', 'ARM_mul', 'ARM_mla', 'ARM_ldr', 'ARM_ldrpc', 'ARM_str', 'ARM_ldm', 'ARM_stm', 'ARM_swp', 'ARM_swi', 'ARM_smull', 'ARM_smlal', 'ARM_umull', 'ARM_umlal', 'ARM_bx', 'ARM_pop', 'ARM_push', 'ARM_adr', 'ARM_bkpt', 'ARM_blx1', 'ARM_blx2', 'ARM_clz', 'ARM_ldrd', 'ARM_pld', 'ARM_qadd', 'ARM_qdadd', 'ARM_qdsub', 'ARM_qsub', 'ARM_smlabb', 'ARM_smlatb', 'ARM_smlabt', 'ARM_smlatt', 'ARM_smlalbb', 'ARM_smlaltb', 'ARM_smlalbt', 'ARM_smlaltt', 'ARM_smlawb', 'ARM_smulwb', 'ARM_smlawt', 'ARM_smulwt', 'ARM_smulbb', 'ARM_smultb', 'ARM_smulbt', 'ARM_smultt', 'ARM_strd', 'xScale_mia', 'xScale_miaph', 'xScale_miabb', 'xScale_miabt', 'xScale_miatb', 'xScale_miatt', 'xScale_mar', 'xScale_mra', 'ARM_movl', 'ARM_swbkpt', 'ARM_cdp', 'ARM_cdp2', 'ARM_ldc', 'ARM_ldc2', 'ARM_stc', 'ARM_stc2', 'ARM_mrc', 'ARM_mrc2', 'ARM_mcr', 'ARM_mcr2', 'ARM_mcrr', 'ARM_mrrc', 'ARM_last']
    
    
    # With IDA 5.5 D0-DX registers appeared with op.ref ranging in the 61-7X range. Don't know if there
    # are other registers defined earlier
    REGISTERS = ['R%d' % i for i in range(32)] + [None for i in range(32, 61)] + ['D%d' % (i-61) for i in range(61, 93)] + ['S%d' % (i-93) for i in range(93, 125)]
    REGISTERS[13] = 'SP'
    REGISTERS[14] = 'LR'
    REGISTERS[15] = 'PC'
    
    OPERATORS = arch.Arch.OPERATORS
    
    
    OPERAND_WIDTH = [
        arch.Arch.NODE_TYPE_OPERATOR_WIDTH_BYTE_1, 
        arch.Arch.NODE_TYPE_OPERATOR_WIDTH_BYTE_2,
        arch.Arch.NODE_TYPE_OPERATOR_WIDTH_BYTE_4,
        arch.Arch.NODE_TYPE_OPERATOR_WIDTH_BYTE_4,
        arch.Arch.NODE_TYPE_OPERATOR_WIDTH_BYTE_8, 
        arch.Arch.NODE_TYPE_OPERATOR_WIDTH_BYTE_VARIABLE,
        arch.Arch.NODE_TYPE_OPERATOR_WIDTH_BYTE_12,
        arch.Arch.NODE_TYPE_OPERATOR_WIDTH_BYTE_8,
        arch.Arch.NODE_TYPE_OPERATOR_WIDTH_BYTE_16,
        arch.Arch.NODE_TYPE_OPERATOR_WIDTH_BYTE_2, None,
        arch.Arch.NODE_TYPE_OPERATOR_WIDTH_BYTE_6,
        None, None,
        None, None]
    
    def __get_instruction_index(self, insn_list):
        """Retrieve the indices of the given instructions into the instruction table.
        
        Those indices are used to indicate the type of an instruction.
        """
        
        return [self.INSTRUCTIONS.index(i) for i in insn_list]
        
    
    def __init__(self):
        arch.Arch.__init__(self)
        
        #self.INSTRUCTIONS_CALL = self.__get_instruction_index(('ARM_bl',))
        self.INSTRUCTIONS_CONDITIONAL_BRANCH = self.__get_instruction_index(
            ( ))
        self.INSTRUCTIONS_UNCONDITIONAL_BRANCH = self.__get_instruction_index(
            ( ))
        #self.INSTRUCTIONS_RET = self.__get_instruction_index((,))
        
        self.INSTRUCTIONS_BRANCH = self.__get_instruction_index(
            ( 'ARM_b', 'ARM_blx1', 'ARM_blx2', 'ARM_b', 'ARM_bl', 'ARM_bx', 'ARM_blx1', 'ARM_blx2' ))
            
        self.arch_name = 'ARM'
        
    def generate_shift_tree(self, shift_value, first_value, second_value):
        shifts = ['LSL', 'LSR', 'ASR', 'ROR', 'RRX']
        shift_types = [self.NODE_TYPE_OPERATOR_LSL, self.NODE_TYPE_OPERATOR_LSR, self.NODE_TYPE_OPERATOR_ASR, self.NODE_TYPE_OPERATOR_ROR, self.NODE_TYPE_OPERATOR_RRX]
        
        shift_type = shift_types[shift_value]
        
        if shift_type == self.NODE_TYPE_OPERATOR_RRX:
            return [shift_type, [self.NODE_TYPE_REGISTER, first_value, 0]]
        elif isinstance(second_value, int):
            return [shift_type, [self.NODE_TYPE_REGISTER, first_value, 0],[self.NODE_TYPE_VALUE, second_value, 1]]
        else:
            return [shift_type, [self.NODE_TYPE_REGISTER, first_value, 0],[self.NODE_TYPE_REGISTER, second_value, 1]]
    
    def check_arch(self):
        
        if self.processor_name == 'ARM':
            return True
            
        return False
    
    def is_s_instruction(self, mnemonic):
    	return mnemonic.endswith("S") and mnemonic[0:3] in ["MOV", "AND", "BIC", "EOR", "MVN", "ORR", "TEQ", "TST"]
    
    def get_mnemonic(self, addr):
        """
        Return the mnemonic for the current instruction.
        """
        disasm_line = idc.GetDisasm(addr) 
        if disasm_line is None:
            # This behavior has been exhibited by IDA5.4 with an IDB of "libSystem.B.dylib"
            # at address 0x3293210e ( "08 BB    CBNZ R0, loc_32932154" )
            # Never IDA versions show the instruction above while IDA 5.4
            # returns None. We will skip the instruction in such a case returning 'invalid'
            # as the mnemonic
            #
            print '%08x: idc.GetDisasm() returned None for address: %08x' % (addr, addr)
            return 'invalid'
        disasm_line_tokenized = disasm_line.split()
        mnem = disasm_line_tokenized[0]
        return mnem
    
    def single_operand_parser(self, address, op, idx):
        """Parse a ARM operand."""
        
        def constraint_value(value):
            if value>2**16:
                return -(2**32-value)
            return value
        
        
        def parse_register_list(bitfield, bit_field_width=32):
            """Parse operand representing a list of registers."""
            operand = [self.NODE_TYPE_OPERATOR_LIST]
            i = 0
            for idx in range(32):
                if bitfield&(2**idx):
                    operand.extend([[self.NODE_TYPE_REGISTER, self.REGISTERS[idx], i]])
                    i=i+1
                        
            return operand
        
        
        def parse_register_list_floating_point(register, count):
            """Parse operand representing a list of registers."""
            
            operand = [self.NODE_TYPE_OPERATOR_LIST]
            for idx in range(register, register+count):
                operand.extend([[self.NODE_TYPE_REGISTER, 'D%d' % idx , 0]])
            
            return operand
        
        ### Operand parsing ###
        
        if op.type == OPERAND_TYPE_NO_OPERAND:
            return None
        
        segment = idaapi.getseg(address)
        addressing_mode = segment.bitness
        
        # Start creating the AST, the root entry is always the width of the operand
        
        operand = [self.OPERAND_WIDTH[self.as_byte_value(op.dtyp)]]
        
        
        # Compose the rest of the AST
        
        if op.type == OPERAND_TYPE_DISPLACEMENT:
        
            # At this point we have to parse specific bits of the instruction
            # ourselves because IDA does not provide all the required data.
        
            val = idc.Dword(address)
            p = (val >> 24) & 1
            w = (val >> 21) & 1
            value = constraint_value(op.addr)
            
            phrase = [self.NODE_TYPE_OPERATOR_COMMA, [ self.NODE_TYPE_REGISTER, self.REGISTERS[op.reg], 0]]
                            
            if idc.GetMnem(address) in ["LDR", "STR"] and idc.ItemSize(address) > 2:
                if p == 0 and w == 0: # Situation: [ ... ], VALUE
                    operand.extend( [ [ 
                        self.NODE_TYPE_OPERATOR_COMMA, 
                            [ self.NODE_TYPE_DEREFERENCE, [ 
                                self.NODE_TYPE_REGISTER, self.REGISTERS[op.reg], 0] , ], 
                            [ self.NODE_TYPE_VALUE, value, 1 ] ] ])
                            
                else: # Situation: [ ... ] or [ ... ]!
                    
                    # We want to avoid [R1 + 0]! situations, so we explicitly
                    # remove the +0 phrase if it exists.
                    
                    if value != 0:
                        inner = [self.NODE_TYPE_DEREFERENCE,phrase+[ [self.NODE_TYPE_VALUE, value, 1]] ]
                    else:
                        inner = [self.NODE_TYPE_DEREFERENCE,[self.NODE_TYPE_REGISTER, self.REGISTERS[op.reg], 0]]
                    if p == 1 and w == 1:
                        operand.extend([[self.NODE_TYPE_OPERATOR_EXCMARK, inner]])
                    else:
                        operand.extend([inner])
            else:
                
                if value != 0:
                    operand.extend([[self.NODE_TYPE_DEREFERENCE,phrase+[ [self.NODE_TYPE_VALUE, value, 1]]]])
                else:
                    operand.extend([[self.NODE_TYPE_DEREFERENCE,[self.NODE_TYPE_REGISTER, self.REGISTERS[op.reg], 0]]])

        elif op.type == OPERAND_TYPE_REGISTER:
        
            if idc.GetMnem(address) in ["STM", "LDM"]:
            
                val = idc.Dword(address)
                w = (val >> 21) & 1
            
                if w == 1:
                    operand.extend([[self.NODE_TYPE_OPERATOR_EXCMARK,[self.NODE_TYPE_REGISTER, self.REGISTERS[op.reg], 0]]])
                else:
                    operand.extend([[self.NODE_TYPE_REGISTER, self.REGISTERS[op.reg], 0]])
            
            else:
                try:
                    operand.extend([[self.NODE_TYPE_REGISTER, self.REGISTERS[op.reg], 0]])
                except Exception, excp:
                    print '%08x: UNSUPPORTED OPERAND REGISTER at %08x: idx: %d' % (address, address, op.reg)
        
        elif op.type == OPERAND_TYPE_MEMORY:
            
            addr_name = self.get_address_name(op.addr)
            
            if addr_name:
                value = arch.ExpressionNamedValue(long(op.addr), addr_name)
            else:
                value = op.addr
                
            operand.extend([
                [self.NODE_TYPE_DEREFERENCE,
                    [self.NODE_TYPE_VALUE, value, 0]] ])
            
        elif op.type == OPERAND_TYPE_IMMEDIATE:
        
            mnemonic = self.get_mnemonic(address)
            
            if ( self.is_s_instruction(mnemonic) and idc.ItemSize(address) >= 4):
                val = idc.Dword(address)
                rotate_imm = 2 * (((val >> 8) & 1) | ((val >> 8) & 2) | ((val >> 8) & 4) | ((val >> 8) & 8))
                immed_8 = val & 0xFF
                
                if rotate_imm == 0:
                    operand.extend([[self.NODE_TYPE_VALUE, op.value, 0]])
                else:
                    operand.extend([[self.NODE_TYPE_OPERATOR_ROR,[self.NODE_TYPE_VALUE, immed_8, 0],[self.NODE_TYPE_VALUE, rotate_imm, 1]]])
            else:
                operand.extend([[self.NODE_TYPE_VALUE, op.value, 0]])
            
        elif op.type in (OPERAND_TYPE_NEAR, OPERAND_TYPE_FAR):

            addr_name = self.get_address_name(op.addr)
            
            if addr_name:
                value = arch.ExpressionNamedValue(long(op.addr), addr_name)
            else:
                value = op.addr
            operand.extend([[self.NODE_TYPE_VALUE, value, 0]])
        
        elif op.type == OPERAND_TYPE_PHRASE:
            if ( idc.ItemSize(address) <= 2 ):
                operand.extend( [ [
                    self.NODE_TYPE_DEREFERENCE, 
                        [ self.NODE_TYPE_OPERATOR_COMMA, 
                            [ self.NODE_TYPE_REGISTER, self.REGISTERS[op.reg], 0 ],
                            [ self.NODE_TYPE_REGISTER, self.REGISTERS[ self.as_byte_value(op.specflag1) ], 1 ] ], ] ])
            else:
                val = idc.Dword(address)
                p = (val >> 24) & 1
                w = (val >> 21) & 1
                needs_shift = ((val >> 25) & 1) & (((val >> 11) & 1) | ((val >> 10) & 1) | ((val >> 9) & 1) | ((val >> 8) & 1) | ((val >> 7) & 1))
                
                if needs_shift:
                    tree = self.generate_shift_tree(self.as_byte_value(op.specflag2), self.REGISTERS[self.as_byte_value(op.specflag1)], op.value)
                    if p == 0 and w == 0:
                        operand.extend( [ [
                            self.NODE_TYPE_OPERATOR_COMMA, 
                                [ self.NODE_TYPE_DEREFERENCE, 
                                    [ self.NODE_TYPE_REGISTER, self.REGISTERS[op.reg], 0],],tree + [1] ] ])
                    elif p == 1 and w == 1:
                        operand.extend( [ [ 
                            self.NODE_TYPE_OPERATOR_EXCMARK, 
                                [ self.NODE_TYPE_DEREFERENCE, 
                                    [ self.NODE_TYPE_OPERATOR_COMMA, 
                                        [ self.NODE_TYPE_REGISTER, self.REGISTERS[op.reg], 0 ], tree + [1] ], ] ] ] )
                    else:
                        operand.extend( [ [ 
                            self.NODE_TYPE_DEREFERENCE, 
                                [ self.NODE_TYPE_OPERATOR_COMMA, 
                                    [ self.NODE_TYPE_REGISTER, self.REGISTERS[op.reg], 0 ], tree + [1] ], ] ] )
                else:
                    if op.value: # Optional Integer value
                        if p == 0 and w == 0:
                            operand.extend( [ [ 
                                self.NODE_TYPE_DEREFERENCE, 
                                    [ self.NODE_TYPE_OPERATOR_COMMA, 
                                        [ self.NODE_TYPE_REGISTER, self.REGISTERS[op.reg], 0 ], 
                                        [ self.NODE_TYPE_OPERATOR_LSL,
                                            [ self.NODE_TYPE_REGISTER, self.REGISTERS[ self.as_byte_value(op.specflag1) ], 0 ],
                                            [ self.NODE_TYPE_VALUE, op.value, 1], 1 ] ] ] ])
                                    
                        elif p == 1 and w == 1:
                            operand.extend( [ [ 
                                self.NODE_TYPE_OPERATOR_EXCMARK, 
                                    [ self.NODE_TYPE_DEREFERENCE, 
                                        [ self.NODE_TYPE_OPERATOR_COMMA, 
                                            [ self.NODE_TYPE_REGISTER, self.REGISTERS[op.reg], 0 ], 
                                            [self.NODE_TYPE_VALUE, op.value, 1 ] ], ] ] ] )
                        else:
                            operand.extend( [ [ 
                                self.NODE_TYPE_DEREFERENCE, 
                                    [ self.NODE_TYPE_OPERATOR_COMMA, 
                                        [ self.NODE_TYPE_REGISTER, self.REGISTERS[op.reg], 0 ],
                                        [ self.NODE_TYPE_VALUE, op.value, 1 ] ], ] ])
                                        
                    else: # Optional Register value
                        if p == 0 and w == 0:
                            operand.extend( [ [
                                self.NODE_TYPE_DEREFERENCE, 
                                    [ self.NODE_TYPE_OPERATOR_COMMA, 
                                        [ self.NODE_TYPE_REGISTER, self.REGISTERS[op.reg], 0 ],
                                        [ self.NODE_TYPE_REGISTER, self.REGISTERS[ self.as_byte_value(op.specflag1) ], 1 ] ] ] ] )
                                    
                        elif p == 1 and w == 1: # set exclamation mark if write back is indicated
                            operand.extend( [ [ 
                                self.NODE_TYPE_OPERATOR_EXCMARK, 
                                    [ self.NODE_TYPE_DEREFERENCE,
                                        [ self.NODE_TYPE_OPERATOR_COMMA, 
                                            [ self.NODE_TYPE_REGISTER, self.REGISTERS[op.reg], 0 ],
                                            [ self.NODE_TYPE_REGISTER, self.REGISTERS[self.as_byte_value(op.specflag1)], 1] ] ] ] ] )
                        else:
                            operand.extend( [ [ 
                                self.NODE_TYPE_DEREFERENCE,
                                    [ self.NODE_TYPE_OPERATOR_COMMA, 
                                        [ self.NODE_TYPE_REGISTER, self.REGISTERS[op.reg], 0 ],
                                        [ self.NODE_TYPE_REGISTER, self.REGISTERS[self.as_byte_value(op.specflag1)], 1 ] ] ] ] )

        elif op.type == OPERAND_TYPE_IDPSPEC0:
                if op.value: # Optional Integer value
                    operand.extend( [ self.generate_shift_tree(self.as_byte_value(op.specflag2), self.REGISTERS[op.reg], op.value) ] )
                else: # Optional Register value
                    operand.extend( [
                        self.generate_shift_tree(
                            self.as_byte_value(op.specflag2), 
                            self.REGISTERS[op.reg], 
                            self.REGISTERS[ self.as_byte_value(op.specflag1) ] ) ] )
                    
        elif op.type == OPERAND_TYPE_IDPSPEC1:
            operand.extend([parse_register_list(op.specval, bit_field_width=16)])
        
        elif op.type == OPERAND_TYPE_IDPSPEC2:
            operand.extend([parse_register_list(op.specval, bit_field_width=32)])
        
        elif op.type == OPERAND_TYPE_IDPSPEC3:
            print '***Don\'t know how to parse OPERAND_TYPE_IDPSPEC3'
            operand.extend([[self.NODE_TYPE_SYMBOL, 'UNK_IDPSPEC3(val:%d, reg:%d, type:%d)' % ( op.value, op.reg, op.type), 0]])
        
        elif op.type == OPERAND_TYPE_IDPSPEC4:
            operand.extend([
                [self.NODE_TYPE_REGISTER, 'D%d' % op.reg, 0]])
        
        elif op.type == OPERAND_TYPE_IDPSPEC5:
            operand.extend([parse_register_list_floating_point(op.reg, op.value)])
        
        return operand
    
    def process_instruction(self, packet, addr):
        """Architecture specific instruction processing"""
        
        # Call the generic part with the architecture specific operand
        # handling
        
        (instruction,
        i_mnemonic,
        operands,
        operand_strings,
        data) = self.process_instruction_generic(addr)
        
        packet.add_instruction(instruction, addr, i_mnemonic,
            operand_strings, operands, data)
        
        return instruction
