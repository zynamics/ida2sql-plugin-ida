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
OPERAND_TYPE_IDPSPEC4       = 12
OPERAND_TYPE_IDPSPEC5       = 13



class Arch(arch.Arch):
    """Architecture specific processing for 'PPC'"""
     
     
    INSTRUCTIONS = [ 'PPC_null', 'PPC_add', 'PPC_addc', 'PPC_adde', 'PPC_addi', 'PPC_addic', 'PPC_addis', 'PPC_addme', 'PPC_addze', 'PPC_and', 'PPC_andc', 'PPC_andi', 'PPC_andis', 'PPC_b', 'PPC_bc', 'PPC_bcctr', 'PPC_bclr', 'PPC_cmp', 'PPC_cmpi', 'PPC_cmpl', 'PPC_cmpli', 'PPC_cntlzd', 'PPC_cntlzw', 'PPC_crand', 'PPC_crandc', 'PPC_creqv', 'PPC_crnand', 'PPC_crnor', 'PPC_cror', 'PPC_crorc', 'PPC_crxor', 'PPC_dcba', 'PPC_dcbf', 'PPC_dcbi', 'PPC_dcbst', 'PPC_dcbt', 'PPC_dcbtst', 'PPC_dcbz', 'PPC_divd', 'PPC_divdu', 'PPC_divw', 'PPC_divwu', 'PPC_eciwx', 'PPC_ecowx', 'PPC_eieio', 'PPC_eqv', 'PPC_extsb', 'PPC_extsh', 'PPC_extsw', 'PPC_fabs', 'PPC_fadd', 'PPC_fadds', 'PPC_fcfid', 'PPC_fcmpo', 'PPC_fcmpu', 'PPC_fctid', 'PPC_fctidz', 'PPC_fctiw', 'PPC_fctiwz', 'PPC_fdiv', 'PPC_fdivs', 'PPC_fmadd', 'PPC_fmadds', 'PPC_fmr', 'PPC_fmsub', 'PPC_fmsubs', 'PPC_fmul', 'PPC_fmuls', 'PPC_fnabs', 'PPC_fneg', 'PPC_fnmadd', 'PPC_fnmadds', 'PPC_fnmsub', 'PPC_fnmsubs', 'PPC_fres', 'PPC_frsp', 'PPC_frsqrte', 'PPC_fsel', 'PPC_fsqrt', 'PPC_fsqrts', 'PPC_fsub', 'PPC_fsubs', 'PPC_icbi', 'PPC_isync', 'PPC_lbz', 'PPC_lbzu', 'PPC_lbzux', 'PPC_lbzx', 'PPC_ld', 'PPC_ldarx', 'PPC_ldu', 'PPC_ldux', 'PPC_ldx', 'PPC_lfd', 'PPC_lfdu', 'PPC_lfdux', 'PPC_lfdx', 'PPC_lfs', 'PPC_lfsu', 'PPC_lfsux', 'PPC_lfsx', 'PPC_lha', 'PPC_lhau', 'PPC_lhaux', 'PPC_lhax', 'PPC_lhbrx', 'PPC_lhz', 'PPC_lhzu', 'PPC_lhzux', 'PPC_lhzx', 'PPC_lmw', 'PPC_lswi', 'PPC_lswx', 'PPC_lwa', 'PPC_lwarx', 'PPC_lwaux', 'PPC_lwax', 'PPC_lwbrx', 'PPC_lwz', 'PPC_lwzu', 'PPC_lwzux', 'PPC_lwzx', 'PPC_mcrf', 'PPC_mcrfs', 'PPC_mcrxr', 'PPC_mfcr', 'PPC_mffs', 'PPC_mfmsr', 'PPC_mfspr', 'PPC_mfsr', 'PPC_mfsrin', 'PPC_mftb', 'PPC_mtcrf', 'PPC_mtfsb0', 'PPC_mtfsb1', 'PPC_mtfsf', 'PPC_mtfsfi', 'PPC_mtmsr', 'PPC_mtmsrd', 'PPC_mtspr', 'PPC_mtsr', 'PPC_mtsrd', 'PPC_mtsrdin', 'PPC_mtsrin', 'PPC_mulhd', 'PPC_mulhdu', 'PPC_mulhw', 'PPC_mulhwu', 'PPC_mulld', 'PPC_mulli', 'PPC_mullw', 'PPC_nand', 'PPC_neg', 'PPC_nor', 'PPC_or', 'PPC_orc', 'PPC_ori', 'PPC_oris', 'PPC_rfi', 'PPC_rfid', 'PPC_rldcl', 'PPC_rldcr', 'PPC_rldic', 'PPC_rldicl', 'PPC_rldicr', 'PPC_rldimi', 'PPC_rlwimi', 'PPC_rlwinm', 'PPC_rlwnm', 'PPC_sc', 'PPC_slbia', 'PPC_slbie', 'PPC_sld', 'PPC_slw', 'PPC_srad', 'PPC_sradi', 'PPC_sraw', 'PPC_srawi', 'PPC_srd', 'PPC_srw', 'PPC_stb', 'PPC_stbu', 'PPC_stbux', 'PPC_stbx', 'PPC_std', 'PPC_stdcx', 'PPC_stdu', 'PPC_stdux', 'PPC_stdx', 'PPC_stfd', 'PPC_stfdu', 'PPC_stfdux', 'PPC_stfdx', 'PPC_stfiwx', 'PPC_stfs', 'PPC_stfsu', 'PPC_stfsux', 'PPC_stfsx', 'PPC_sth', 'PPC_sthbrx', 'PPC_sthu', 'PPC_sthux', 'PPC_sthx', 'PPC_stmw', 'PPC_stswi', 'PPC_stswx', 'PPC_stw', 'PPC_stwbrx', 'PPC_stwcx', 'PPC_stwu', 'PPC_stwux', 'PPC_stwx', 'PPC_subf', 'PPC_subfc', 'PPC_subfe', 'PPC_subfic', 'PPC_subfme', 'PPC_subfze', 'PPC_sync', 'PPC_td', 'PPC_tdi', 'PPC_tlbia', 'PPC_tlbie', 'PPC_tlbsync', 'PPC_tw', 'PPC_twi', 'PPC_xor', 'PPC_xori', 'PPC_xoris', 'PPC_cmpwi', 'PPC_cmpw', 'PPC_cmplwi', 'PPC_cmplw', 'PPC_cmpdi', 'PPC_cmpd', 'PPC_cmpldi', 'PPC_cmpld', 'PPC_trap', 'PPC_trapd', 'PPC_twlgt', 'PPC_twllt', 'PPC_tweq', 'PPC_twlge', 'PPC_twlle', 'PPC_twgt', 'PPC_twge', 'PPC_twlt', 'PPC_twle', 'PPC_twne', 'PPC_twlgti', 'PPC_twllti', 'PPC_tweqi', 'PPC_twlgei', 'PPC_twllei', 'PPC_twgti', 'PPC_twgei', 'PPC_twlti', 'PPC_twlei', 'PPC_twnei', 'PPC_tdlgt', 'PPC_tdllt', 'PPC_tdeq', 'PPC_tdlge', 'PPC_tdlle', 'PPC_tdgt', 'PPC_tdge', 'PPC_tdlt', 'PPC_tdle', 'PPC_tdne', 'PPC_tdlgti', 'PPC_tdllti', 'PPC_tdeqi', 'PPC_tdlgei', 'PPC_tdllei', 'PPC_tdgti', 'PPC_tdgei', 'PPC_tdlti', 'PPC_tdlei', 'PPC_tdnei', 'PPC_nop', 'PPC_not', 'PPC_mr', 'PPC_subi', 'PPC_subic', 'PPC_subis', 'PPC_li', 'PPC_lis', 'PPC_crset', 'PPC_crnot', 'PPC_crmove', 'PPC_crclr', 'PPC_mtxer', 'PPC_mtlr', 'PPC_mtctr', 'PPC_mtdsisr', 'PPC_mtdar', 'PPC_mtdec', 'PPC_mtsrr0', 'PPC_mtsrr1', 'PPC_mtsprg0', 'PPC_mtsprg1', 'PPC_mtsprg2', 'PPC_mtsprg3', 'PPC_mttbl', 'PPC_mttbu', 'PPC_mfxer', 'PPC_mflr', 'PPC_mfctr', 'PPC_mfdsisr', 'PPC_mfdar', 'PPC_mfdec', 'PPC_mfsrr0', 'PPC_mfsrr1', 'PPC_mfsprg0', 'PPC_mfsprg1', 'PPC_mfsprg2', 'PPC_mfsprg3', 'PPC_mftbl', 'PPC_mftbu', 'PPC_mfpvr', 'PPC_balways', 'PPC_bt', 'PPC_bf', 'PPC_bdnz', 'PPC_bdnzt', 'PPC_bdnzf', 'PPC_bdz', 'PPC_bdzt', 'PPC_bdzf', 'PPC_blt', 'PPC_ble', 'PPC_beq', 'PPC_bge', 'PPC_bgt', 'PPC_bne', 'PPC_bso', 'PPC_bns', 'PPC_extlwi', 'PPC_extrwi', 'PPC_inslwi', 'PPC_insrwi', 'PPC_rotlwi', 'PPC_rotrwi', 'PPC_rotlw', 'PPC_slwi', 'PPC_srwi', 'PPC_clrlwi', 'PPC_clrrwi', 'PPC_clrlslwi', 'PPC_dccci', 'PPC_dcread', 'PPC_icbt', 'PPC_iccci', 'PPC_icread', 'PPC_mfdcr', 'PPC_mtdcr', 'PPC_rfci', 'PPC_tlbre', 'PPC_tlbsx', 'PPC_tlbwe', 'PPC_wrtee', 'PPC_wrteei', 'PPC_last']
     
     
    # Special Purpose Registers. Looked up in GDB's source code,
    # IDA and the Freescale's PowerPC MPC823e manual
    #
    SPR_REGISTERS = {
        0: 'mq',
        1: 'xer',
        4: 'rtcu',
        5: 'rtcl',
        8: 'lr',
        9: 'ctr',
        #9: 'cnt',  # IDA defines 9 to be CTR, I looked up
                    # this from GDB's source so I ignore if
                    # CNT being 9 too is an error
        18: 'dsisr',
        19: 'dar',
        22: 'dec',
        25: 'sdr1',
        26: 'srr0',
        27: 'srr1',
        80: 'eie',
        81: 'eid',
        82: 'nri',
        102: 'sp',
        144: 'cmpa',
        145: 'cmpb',
        146: 'cmpc',
        147: 'cmpd',
        148: 'icr',
        149: 'der',
        150: 'counta',
        151: 'countb',
        152: 'cmpe',
        153: 'cmpf',
        154: 'cmpg',
        155: 'cmph',
        156: 'lctrl1',
        157: 'lctrl2',
        158: 'ictrl',
        159: 'bar',
        256: 'vrsave',
        272: 'sprg0',
        273: 'sprg1',
        274: 'sprg2',
        275: 'sprg3',
        280: 'asr',
        282: 'ear',
        268: 'tbl_read',
        269: 'tbu_read',
        284: 'tbl_write',
        285: 'tbu_write',
        287: 'pvr',
        512: 'spefscr',
        528: 'ibat0u',
        529: 'ibat0l',
        530: 'ibat1u',
        531: 'ibat1l',
        532: 'ibat2u',
        533: 'ibat2l',
        534: 'ibat3u',
        535: 'ibat3l',
        536: 'dbat0u',
        537: 'dbat0l',
        538: 'dbat1u',
        539: 'dbat1l',
        540: 'dbat2u',
        541: 'dbat2l',
        542: 'dbat3u',
        543: 'dbat3l',
        560: 'ic_cst',
        561: 'ic_adr',
        562: 'ic_dat',
        568: 'dc_cst',
        569: 'dc_adr',
        570: 'dc_dat',
        630: 'dpdr',
        631: 'dpir',
        638: 'immr',
        784: 'mi_ctr',
        786: 'mi_ap',
        787: 'mi_epn',
        789: 'mi_twc',
        790: 'mi_rpn',
        816: 'mi_cam',
        817: 'mi_ram0',
        818: 'mi_ram1',
        792: 'md_ctr',
        793: 'm_casid',
        794: 'md_ap',
        795: 'md_epn',
        796: 'm_twb',
        797: 'md_twc',
        798: 'md_rpn',
        799: 'm_tw',
        816: 'mi_dbcam',
        817: 'mi_dbram0',
        818: 'mi_dbram1',
        #824: 'md_dbcam',
        824: 'md_cam',
        #825: 'md_dbram0',
        825: 'md_ram0',
        #826: 'md_dbram1',
        826: 'md_ram1',
        936: 'ummcr0',
        937: 'upmc1',
        938: 'upmc2',
        939: 'usia',
        940: 'ummcr1',
        941: 'upmc3',
        942: 'upmc4',
        944: 'zpr',
        945: 'pid',
        952: 'mmcr0',
        953: 'pmc1',
        953: 'sgr',
        954: 'pmc2',
        #954: 'dcwr',
        955: 'sia',
        956: 'mmcr1',
        957: 'pmc3',
        958: 'pmc4',
        959: 'sda',
        972: 'tbhu',
        973: 'tblu',
        976: 'dmiss',
        977: 'dcmp',
        978: 'hash1',
        979: 'hash2',
        #979: 'icdbdr',
        #980: 'imiss',
        980: 'esr',
        981: 'icmp',
        #981: 'dear',
        982: 'rpa',
        982: 'evpr',
        983: 'cdbcr',
        984: 'tsr',
        #984: '602_tcr',
        #986: '403_tcr',
        #986: 'ibr',
        986: 'tcr',
        987: 'pit',
        988: 'esasrr',
        #988: 'tbhi',
        989: 'tblo',
        990: 'srr2',
        #990: 'sebr',
        991: 'srr3',
        #991: 'ser',
        1008: 'hid0',
        #1008: 'dbsr',
        1009: 'hid1',
        1010: 'iabr',
        #1010: 'dbcr',
        1012: 'iac1',
        1013: 'dabr',
        #1013: 'iac2',
        1014: 'dac1',
        1015: 'dac2',
        1017: 'l2cr',
        1018: 'dccr',
        #1019: 'ictc',
        1019: 'iccr',
        #1020: 'thrm1',
        1020: 'pbl1',
        #1021: 'thrm2',
        1021: 'pbu1',
        #1022: 'thrm3',
        1022: 'pbl2',
        #1022: 'fpecr',
        #1022: 'lt',
        1023: 'pir',
        #1023: 'pbu2'
        }
    
    CR_REGISTERS = ['cr%d' % i for i in range(8)]
    REGISTERS = ['%%r%d' % i for i in range(32)]
    REGISTERS.extend(['UNK32', 'UNK33'])
    REGISTERS.extend(['%%fp%d' % i for i in range(32)])
    REGISTERS.extend(['%%sr%d' % i for i in range(16)])
    REGISTERS[1] = '%sp'
    REGISTERS[2] = '%rtoc'
    
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
        
        #self.INSTRUCTIONS_CALL = self.__get_instruction_index((,))
        self.INSTRUCTIONS_CONDITIONAL_BRANCH = self.__get_instruction_index(
            ( 'PPC_bc', 'PPC_bcctr', 'PPC_bclr', 'PPC_bt', 'PPC_bf', 'PPC_bdnz', 'PPC_bdnzt', 'PPC_bdnzf', 'PPC_bdz', 'PPC_bdzt', 'PPC_bdzf', 'PPC_blt', 'PPC_ble', 'PPC_beq', 'PPC_bge', 'PPC_bgt', 'PPC_bne', 'PPC_bso', 'PPC_bns'))
        self.INSTRUCTIONS_UNCONDITIONAL_BRANCH = self.__get_instruction_index(
            ( 'PPC_b', 'PPC_balways'))
        #self.INSTRUCTIONS_RET = self.__get_instruction_index((,))
        
        self.INSTRUCTIONS_BRANCH = self.__get_instruction_index(
            ( 'PPC_bc', 'PPC_bcctr', 'PPC_bclr', 'PPC_bt', 'PPC_bf', 'PPC_bdnz', 'PPC_bdnzt', 'PPC_bdnzf', 'PPC_bdz', 'PPC_bdzt', 'PPC_bdzf', 'PPC_blt', 'PPC_ble', 'PPC_beq', 'PPC_bge', 'PPC_bgt', 'PPC_bne', 'PPC_bso', 'PPC_bns', 'PPC_b', 'PPC_balways'))
        
        self.arch_name = 'PowerPC'
    
    def check_arch(self):
        
        if self.processor_name == 'PPC':
            return True
        
        return False
        
    
    def get_mnemonic(self, addr):
        """Return the mnemonic for the current instruction."""
        
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
        """Parse a PPC operand."""
        
        def constraint_value(value):
            if value>2**16:
                return -(2**32-value)
            return value

        
        # Operand parsing
        #
        
        if op.type == OPERAND_TYPE_NO_OPERAND:
            return None
        
        #print '>>>', hex(address), idx, op.type
        
        segment = idaapi.getseg(address)
        addressing_mode = segment.bitness
        
        # Start creating the AST, the root entry is always the width of the
        # operand
        operand = [self.OPERAND_WIDTH[self.as_byte_value(op.dtyp)]]
        
        
        # Compose the rest of the AST
        #
        
        if op.type == OPERAND_TYPE_DISPLACEMENT:
            
            # A displacement operatior might refer to a variable...
            #
            var_name = None
            
            # Try to get any name that might have been assigned to the
            # variable. It's only done if the register is:
            # sp/esp (4) os bp/ebp (5)
            #
            flags = idc.GetFlags(address)
            if (idx==0 and idc.isStkvar0(flags)) or (
                idx==1 and idc.isStkvar1(flags)):
                
                var_name = self.get_operand_stack_variable_name(address, op, idx)
            
            #if has_sib_byte(op) is True:
                # when SIB byte set, process the SIB indexing
            #    phrase = parse_phrase(op)
            #else:
            phrase = [
                self.NODE_TYPE_OPERATOR_PLUS,
                    [self.NODE_TYPE_REGISTER,
                        self.REGISTERS[self.as_byte_value(op.reg)], 0]]
            
            if var_name:
                value = arch.ExpressionNamedValue(long(op.addr), var_name)
            else:
                value = constraint_value(op.addr)
            
            operand.extend([
                [self.NODE_TYPE_DEREFERENCE,
                    phrase+[ [self.NODE_TYPE_VALUE, value, 1]] ] ])
        
        elif op.type == OPERAND_TYPE_REGISTER:
            operand.extend([
                [self.NODE_TYPE_REGISTER, self.REGISTERS[self.as_byte_value(op.reg)], 1]])
                
        
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
            
            # Keep the value's size
            #
            if self.as_byte_value(op.dtyp) == 0:
                mask = 0xff
            elif self.as_byte_value(op.dtyp) == 1:
                mask = 0xffff
            else:
                mask = 0xffffffff
            
            operand.extend([[self.NODE_TYPE_VALUE, op.value&mask, 0]])
            
        
        elif op.type in (OPERAND_TYPE_NEAR, OPERAND_TYPE_FAR):
            
            addr_name = self.get_address_name(op.addr)
            
            if addr_name:
                value = arch.ExpressionNamedValue(long(op.addr), addr_name)
            else:
                value = op.addr
            
            operand.extend([[self.NODE_TYPE_VALUE, value, 0]])
            
        
        elif op.type == OPERAND_TYPE_PHRASE:
            print '***Dunno how to parse PHRASE'
            operand.extend([[self.NODE_TYPE_SYMBOL,
                'UNK_PHRASE(val:%d, reg:%d, type:%d)' % (
                    op.value, self.as_byte_value(op.reg), op.type), 0]])
        
        elif op.type == OPERAND_TYPE_IDPSPEC0:
            
            # Handle Special Purpose Registers
            #
            register = self.SPR_REGISTERS.get(
                op.value, 'UNKNOWN_REGISTER(val:%x)' % op.value)
            
            operand.extend([
                [self.NODE_TYPE_REGISTER, register, 0]])
        
        elif op.type == OPERAND_TYPE_IDPSPEC1:
            #print '***Dunno how to parse OPERAND_TYPE_IDPSPEC1'
            #operand.extend([[self.NODE_TYPE_SYMBOL,
            #    'UNK_IDPSPEC1(val:%d, reg:%d, type:%d)' % (
            #        op.value, op.reg, op.type), 0]])
            operand.extend([
                [self.NODE_TYPE_REGISTER, self.REGISTERS[self.as_byte_value(op.reg)], 1]])
            operand.extend([
                [self.NODE_TYPE_REGISTER, self.REGISTERS[self.as_byte_value(op.specflag1)], 2]])
        
        elif op.type == OPERAND_TYPE_IDPSPEC2:
            # IDSPEC2 is operand type for all rlwinm and rlwnm
            # instructions which are in general op reg, reg, byte, byte, byte
            # or eqivalent. simplified mnemonics sometimes take less than
            # five arguments.
            #
            # Keep the value's size
            #
            if self.as_byte_value(op.dtyp) == 0:
                mask = 0xff
            elif self.as_byte_value(op.dtyp) == 1:
                mask = 0xffff
            else:
                mask = 0xffffffff

            operand_1 = []
            operand_2 = []
            operand_3 = []

            # Get the object representing the instruction's data.
            # It varies between IDA pre-5.7 and 5.7 onwards, the following check
            # will take care of it (for more detail look into the similar 
            # construct in arch.py)
            #
            if hasattr(idaapi, 'cmd' ):
                idaapi.decode_insn(address)
                ida_instruction = idaapi.cmd
            else:
                idaapi.ua_code(address)
                ida_instruction = idaapi.cvar.cmd
            
            if (ida_instruction.auxpref & 0x0020):
                #print "SH"		    
                operand_1 = [self.OPERAND_WIDTH[self.as_byte_value(op.dtyp)]]
                operand_1.extend([[self.NODE_TYPE_VALUE, self.as_byte_value(op.reg)&mask, 0]])
            else:
                operand_1 = [self.OPERAND_WIDTH[self.as_byte_value(op.dtyp)]]
                operand_1.extend([[self.NODE_TYPE_REGISTER, self.REGISTERS[self.as_byte_value(op.reg)], 0]])
            #print operand_1

            if (ida_instruction.auxpref & 0x0040):
                #print "MB"
                operand_2 = [self.OPERAND_WIDTH[self.as_byte_value(op.dtyp)]]
                operand_2.extend([[self.NODE_TYPE_VALUE, self.as_byte_value(op.specflag1)&mask, 0]])
            #print operand_2

            if (ida_instruction.auxpref & 0x0080):
                #print "ME"
                operand_3 = [self.OPERAND_WIDTH[self.as_byte_value(op.dtyp)]]
                operand_3.extend([[self.NODE_TYPE_VALUE, self.as_byte_value(op.specflag2)&mask, 0]])
            #print operand_3

            operand = [operand_1]
            #operand = operand_1

            if (ida_instruction.auxpref & 0x0040): 
                #print "MB2"
                operand.append(operand_2)
            if (ida_instruction.auxpref & 0x0080):
                #print "ME2"
                operand.append(operand_3)	    

            #print operand 
            # operand = operand_1
            #print operand
            #print '>>>', hex(address), idx, op.type, op.reg
            #operand.extend([[self.NODE_TYPE_OPERATOR_COMMA, [self.NODE_TYPE_VALUE, op.reg&mask, 0], [self.NODE_TYPE_VALUE, self.as_byte_value(op.specflag1)&mask, 1], [self.NODE_TYPE_VALUE, self.as_byte_value(op.specflag2)&mask, 2]]])

        elif op.type == OPERAND_TYPE_IDPSPEC3:
            # CR registers
            #
            operand.extend([
                [self.NODE_TYPE_REGISTER, self.CR_REGISTERS[self.as_byte_value(op.reg)], 0]])
        
        elif op.type == OPERAND_TYPE_IDPSPEC4:
            # The bit in the CR to check for
            #
            operand.extend([[self.NODE_TYPE_REGISTER, self.as_byte_value(op.reg), 0]])
            
        
        elif op.type == OPERAND_TYPE_IDPSPEC5:
            # Device Control Register, implementation specific
            operand.extend([[self.NODE_TYPE_REGISTER, 'DCR(%x)' % op.value, 0]])
            
        
        return operand
        
    
    def process_instruction(self, packet, addr):
        """Architecture specific instruction processing"""
        
        # Call the generic part with the architecture specific operand
        # handling
        #
        
        (instruction,
        i_mnemonic,
        operands,
        operand_strings,
        data) = self.process_instruction_generic(addr)

        
        packet.add_instruction(instruction, addr, i_mnemonic,
            operand_strings, operands, data)

        
        return instruction
             
             
