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
    """Architecture specific processing for 'metapc'"""
    
    
    INSTRUCTIONS = ['NN_null', 'NN_aaa', 'NN_aad', 'NN_aam', 'NN_aas', 'NN_adc', 'NN_add', 'NN_and', 'NN_arpl', 'NN_bound', 'NN_bsf', 'NN_bsr', 'NN_bt', 'NN_btc', 'NN_btr', 'NN_bts', 'NN_call', 'NN_callfi', 'NN_callni', 'NN_cbw', 'NN_cwde', 'NN_cdqe', 'NN_clc', 'NN_cld', 'NN_cli', 'NN_clts', 'NN_cmc', 'NN_cmp', 'NN_cmps', 'NN_cwd', 'NN_cdq', 'NN_cqo', 'NN_daa', 'NN_das', 'NN_dec', 'NN_div', 'NN_enterw', 'NN_enter', 'NN_enterd', 'NN_enterq', 'NN_hlt', 'NN_idiv', 'NN_imul', 'NN_in', 'NN_inc', 'NN_ins', 'NN_int', 'NN_into', 'NN_int3', 'NN_iretw', 'NN_iret', 'NN_iretd', 'NN_iretq', 'NN_ja', 'NN_jae', 'NN_jb', 'NN_jbe', 'NN_jc', 'NN_jcxz', 'NN_jecxz', 'NN_jrcxz', 'NN_je', 'NN_jg', 'NN_jge', 'NN_jl', 'NN_jle', 'NN_jna', 'NN_jnae', 'NN_jnb', 'NN_jnbe', 'NN_jnc', 'NN_jne', 'NN_jng', 'NN_jnge', 'NN_jnl', 'NN_jnle', 'NN_jno', 'NN_jnp', 'NN_jns', 'NN_jnz', 'NN_jo', 'NN_jp', 'NN_jpe', 'NN_jpo', 'NN_js', 'NN_jz', 'NN_jmp', 'NN_jmpfi', 'NN_jmpni', 'NN_jmpshort', 'NN_lahf', 'NN_lar', 'NN_lea', 'NN_leavew', 'NN_leave', 'NN_leaved', 'NN_leaveq', 'NN_lgdt', 'NN_lidt', 'NN_lgs', 'NN_lss', 'NN_lds', 'NN_les', 'NN_lfs', 'NN_lldt', 'NN_lmsw', 'NN_lock', 'NN_lods', 'NN_loopw', 'NN_loop', 'NN_loopd', 'NN_loopq', 'NN_loopwe', 'NN_loope', 'NN_loopde', 'NN_loopqe', 'NN_loopwne', 'NN_loopne', 'NN_loopdne', 'NN_loopqne', 'NN_lsl', 'NN_ltr', 'NN_mov', 'NN_movsp', 'NN_movs', 'NN_movsx', 'NN_movzx', 'NN_mul', 'NN_neg', 'NN_nop', 'NN_not', 'NN_or', 'NN_out', 'NN_outs', 'NN_pop', 'NN_popaw', 'NN_popa', 'NN_popad', 'NN_popaq', 'NN_popfw', 'NN_popf', 'NN_popfd', 'NN_popfq', 'NN_push', 'NN_pushaw', 'NN_pusha', 'NN_pushad', 'NN_pushaq', 'NN_pushfw', 'NN_pushf', 'NN_pushfd', 'NN_pushfq', 'NN_rcl', 'NN_rcr', 'NN_rol', 'NN_ror', 'NN_rep', 'NN_repe', 'NN_repne', 'NN_retn', 'NN_retf', 'NN_sahf', 'NN_sal', 'NN_sar', 'NN_shl', 'NN_shr', 'NN_sbb', 'NN_scas', 'NN_seta', 'NN_setae', 'NN_setb', 'NN_setbe', 'NN_setc', 'NN_sete', 'NN_setg', 'NN_setge', 'NN_setl', 'NN_setle', 'NN_setna', 'NN_setnae', 'NN_setnb', 'NN_setnbe', 'NN_setnc', 'NN_setne', 'NN_setng', 'NN_setnge', 'NN_setnl', 'NN_setnle', 'NN_setno', 'NN_setnp', 'NN_setns', 'NN_setnz', 'NN_seto', 'NN_setp', 'NN_setpe', 'NN_setpo', 'NN_sets', 'NN_setz', 'NN_sgdt', 'NN_sidt', 'NN_shld', 'NN_shrd', 'NN_sldt', 'NN_smsw', 'NN_stc', 'NN_std', 'NN_sti', 'NN_stos', 'NN_str', 'NN_sub', 'NN_test', 'NN_verr', 'NN_verw', 'NN_wait', 'NN_xchg', 'NN_xlat', 'NN_xor', 'NN_cmpxchg', 'NN_bswap', 'NN_xadd', 'NN_invd', 'NN_wbinvd', 'NN_invlpg', 'NN_rdmsr', 'NN_wrmsr', 'NN_cpuid', 'NN_cmpxchg8b', 'NN_rdtsc', 'NN_rsm', 'NN_cmova', 'NN_cmovb', 'NN_cmovbe', 'NN_cmovg', 'NN_cmovge', 'NN_cmovl', 'NN_cmovle', 'NN_cmovnb', 'NN_cmovno', 'NN_cmovnp', 'NN_cmovns', 'NN_cmovnz', 'NN_cmovo', 'NN_cmovp', 'NN_cmovs', 'NN_cmovz', 'NN_fcmovb', 'NN_fcmove', 'NN_fcmovbe', 'NN_fcmovu', 'NN_fcmovnb', 'NN_fcmovne', 'NN_fcmovnbe', 'NN_fcmovnu', 'NN_fcomi', 'NN_fucomi', 'NN_fcomip', 'NN_fucomip', 'NN_rdpmc', 'NN_fld', 'NN_fst', 'NN_fstp', 'NN_fxch', 'NN_fild', 'NN_fist', 'NN_fistp', 'NN_fbld', 'NN_fbstp', 'NN_fadd', 'NN_faddp', 'NN_fiadd', 'NN_fsub', 'NN_fsubp', 'NN_fisub', 'NN_fsubr', 'NN_fsubrp', 'NN_fisubr', 'NN_fmul', 'NN_fmulp', 'NN_fimul', 'NN_fdiv', 'NN_fdivp', 'NN_fidiv', 'NN_fdivr', 'NN_fdivrp', 'NN_fidivr', 'NN_fsqrt', 'NN_fscale', 'NN_fprem', 'NN_frndint', 'NN_fxtract', 'NN_fabs', 'NN_fchs', 'NN_fcom', 'NN_fcomp', 'NN_fcompp', 'NN_ficom', 'NN_ficomp', 'NN_ftst', 'NN_fxam', 'NN_fptan', 'NN_fpatan', 'NN_f2xm1', 'NN_fyl2x', 'NN_fyl2xp1', 'NN_fldz', 'NN_fld1', 'NN_fldpi', 'NN_fldl2t', 'NN_fldl2e', 'NN_fldlg2', 'NN_fldln2', 'NN_finit', 'NN_fninit', 'NN_fsetpm', 'NN_fldcw', 'NN_fstcw', 'NN_fnstcw', 'NN_fstsw', 'NN_fnstsw', 'NN_fclex', 'NN_fnclex', 'NN_fstenv', 'NN_fnstenv', 'NN_fldenv', 'NN_fsave', 'NN_fnsave', 'NN_frstor', 'NN_fincstp', 'NN_fdecstp', 'NN_ffree', 'NN_fnop', 'NN_feni', 'NN_fneni', 'NN_fdisi', 'NN_fndisi', 'NN_fprem1', 'NN_fsincos', 'NN_fsin', 'NN_fcos', 'NN_fucom', 'NN_fucomp', 'NN_fucompp', 'NN_setalc', 'NN_svdc', 'NN_rsdc', 'NN_svldt', 'NN_rsldt', 'NN_svts', 'NN_rsts', 'NN_icebp', 'NN_loadall', 'NN_emms', 'NN_movd', 'NN_movq', 'NN_packsswb', 'NN_packssdw', 'NN_packuswb', 'NN_paddb', 'NN_paddw', 'NN_paddd', 'NN_paddsb', 'NN_paddsw', 'NN_paddusb', 'NN_paddusw', 'NN_pand', 'NN_pandn', 'NN_pcmpeqb', 'NN_pcmpeqw', 'NN_pcmpeqd', 'NN_pcmpgtb', 'NN_pcmpgtw', 'NN_pcmpgtd', 'NN_pmaddwd', 'NN_pmulhw', 'NN_pmullw', 'NN_por', 'NN_psllw', 'NN_pslld', 'NN_psllq', 'NN_psraw', 'NN_psrad', 'NN_psrlw', 'NN_psrld', 'NN_psrlq', 'NN_psubb', 'NN_psubw', 'NN_psubd', 'NN_psubsb', 'NN_psubsw', 'NN_psubusb', 'NN_psubusw', 'NN_punpckhbw', 'NN_punpckhwd', 'NN_punpckhdq', 'NN_punpcklbw', 'NN_punpcklwd', 'NN_punpckldq', 'NN_pxor', 'NN_fxsave', 'NN_fxrstor', 'NN_sysenter', 'NN_sysexit', 'NN_pavgusb', 'NN_pfadd', 'NN_pfsub', 'NN_pfsubr', 'NN_pfacc', 'NN_pfcmpge', 'NN_pfcmpgt', 'NN_pfcmpeq', 'NN_pfmin', 'NN_pfmax', 'NN_pi2fd', 'NN_pf2id', 'NN_pfrcp', 'NN_pfrsqrt', 'NN_pfmul', 'NN_pfrcpit1', 'NN_pfrsqit1', 'NN_pfrcpit2', 'NN_pmulhrw', 'NN_femms', 'NN_prefetch', 'NN_prefetchw', 'NN_addps', 'NN_addss', 'NN_andnps', 'NN_andps', 'NN_cmpps', 'NN_cmpss', 'NN_comiss', 'NN_cvtpi2ps', 'NN_cvtps2pi', 'NN_cvtsi2ss', 'NN_cvtss2si', 'NN_cvttps2pi', 'NN_cvttss2si', 'NN_divps', 'NN_divss', 'NN_ldmxcsr', 'NN_maxps', 'NN_maxss', 'NN_minps', 'NN_minss', 'NN_movaps', 'NN_movhlps', 'NN_movhps', 'NN_movlhps', 'NN_movlps', 'NN_movmskps', 'NN_movss', 'NN_movups', 'NN_mulps', 'NN_mulss', 'NN_orps', 'NN_rcpps', 'NN_rcpss', 'NN_rsqrtps', 'NN_rsqrtss', 'NN_shufps', 'NN_sqrtps', 'NN_sqrtss', 'NN_stmxcsr', 'NN_subps', 'NN_subss', 'NN_ucomiss', 'NN_unpckhps', 'NN_unpcklps', 'NN_xorps', 'NN_pavgb', 'NN_pavgw', 'NN_pextrw', 'NN_pinsrw', 'NN_pmaxsw', 'NN_pmaxub', 'NN_pminsw', 'NN_pminub', 'NN_pmovmskb', 'NN_pmulhuw', 'NN_psadbw', 'NN_pshufw', 'NN_maskmovq', 'NN_movntps', 'NN_movntq', 'NN_prefetcht0', 'NN_prefetcht1', 'NN_prefetcht2', 'NN_prefetchnta', 'NN_sfence', 'NN_cmpeqps', 'NN_cmpltps', 'NN_cmpleps', 'NN_cmpunordps', 'NN_cmpneqps', 'NN_cmpnltps', 'NN_cmpnleps', 'NN_cmpordps', 'NN_cmpeqss', 'NN_cmpltss', 'NN_cmpless', 'NN_cmpunordss', 'NN_cmpneqss', 'NN_cmpnltss', 'NN_cmpnless', 'NN_cmpordss', 'NN_pf2iw', 'NN_pfnacc', 'NN_pfpnacc', 'NN_pi2fw', 'NN_pswapd', 'NN_fstp1', 'NN_fcom2', 'NN_fcomp3', 'NN_fxch4', 'NN_fcomp5', 'NN_ffreep', 'NN_fxch7', 'NN_fstp8', 'NN_fstp9',  'NN_addpd', 'NN_addsd', 'NN_andnpd', 'NN_andpd', 'NN_clflush', 'NN_cmppd', 'NN_cmpsd', 'NN_comisd', 'NN_cvtdq2pd', 'NN_cvtdq2ps', 'NN_cvtpd2dq', 'NN_cvtpd2pi', 'NN_cvtpd2ps', 'NN_cvtpi2pd', 'NN_cvtps2dq', 'NN_cvtps2pd', 'NN_cvtsd2si', 'NN_cvtsd2ss', 'NN_cvtsi2sd', 'NN_cvtss2sd', 'NN_cvttpd2dq', 'NN_cvttpd2pi', 'NN_cvttps2dq', 'NN_cvttsd2si', 'NN_divpd', 'NN_divsd', 'NN_lfence', 'NN_maskmovdqu', 'NN_maxpd', 'NN_maxsd', 'NN_mfence', 'NN_minpd', 'NN_minsd', 'NN_movapd', 'NN_movdq2q', 'NN_movdqa', 'NN_movdqu', 'NN_movhpd', 'NN_movlpd', 'NN_movmskpd', 'NN_movntdq', 'NN_movnti', 'NN_movntpd', 'NN_movq2dq', 'NN_movsd', 'NN_movupd', 'NN_mulpd', 'NN_mulsd', 'NN_orpd', 'NN_paddq', 'NN_pause', 'NN_pmuludq', 'NN_pshufd', 'NN_pshufhw', 'NN_pshuflw', 'NN_pslldq', 'NN_psrldq', 'NN_psubq', 'NN_punpckhqdq', 'NN_punpcklqdq', 'NN_shufpd', 'NN_sqrtpd', 'NN_sqrtsd', 'NN_subpd', 'NN_subsd', 'NN_ucomisd', 'NN_unpckhpd', 'NN_unpcklpd', 'NN_xorpd', 'NN_syscall', 'NN_sysret',  'NN_swapgs',  'NN_movddup', 'NN_movshdup', 'NN_movsldup', 'NN_movsxd', 'NN_cmpxchg16b', 'NN_last']
    
    
    # The following table is indexed with the segment's bitness of op.dtyp
    # depending on whether the register is used as an operand value or
    # for addressing.
    #
    # The first two list are identical, the 3rd and 4th are for 32 and 64 bits
    # respectively
    #
    
    REGISTERS    = [
        [   'ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di', 'r8',
            'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'al',
            'cl', 'dl', 'bl', 'ah', 'ch', 'dh', 'bh', 'spl', 'bpl',
            'sil', 'dil', 'ip', 'es', 'cs', 'ss', 'ds', 'fs', 'gs'],
        [   'ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di', 'r8',
            'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'al',
            'cl', 'dl', 'bl', 'ah', 'ch', 'dh', 'bh', 'spl', 'bpl',
            'sil', 'dil', 'ip', 'es', 'cs', 'ss', 'ds', 'fs', 'gs'],
        [   'eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi', 'r8',
            'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'al',
            'cl', 'dl', 'bl', 'ah', 'ch', 'dh', 'bh', 'spl', 'bpl',
            'sil', 'dil', 'eip', 'es', 'cs', 'ss', 'ds', 'fs', 'gs'],
        [   'rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi', 'r8',
            'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'al',
            'cl', 'dl', 'bl', 'ah', 'ch', 'dh', 'bh', 'spl', 'bpl',
            'sil', 'dil', 'rip', 'es', 'cs', 'ss', 'ds', 'fs', 'gs'],
        [],
        [],
        [],
        ['unk_reg_%02d' % i for i in range(56)] + [ 'mm%d' % i for i in range(8) ],
        ['unk_reg_%02d' % i for i in range(64)] + [ 'xmm%d' % i for i in range(8) ] ]
    
    SIB_BASE_REGISTERS = ['eax', 'ecx', 'edx', 'ebx', 'esp', '', 'esi', 'edi']
    SIB_INDEX_REGISTERS = ['eax', 'ecx', 'edx', 'ebx', '', 'ebp', 'esi', 'edi']
    
    # Add the segment registers as operators
    #
    NODE_TYPE_OPERATOR_SEGMENT_ES   = 'es:'
    NODE_TYPE_OPERATOR_SEGMENT_CS   = 'cs:'
    NODE_TYPE_OPERATOR_SEGMENT_SS   = 'ss:'
    NODE_TYPE_OPERATOR_SEGMENT_DS   = 'ds:'
    NODE_TYPE_OPERATOR_SEGMENT_FS   = 'fs:'
    NODE_TYPE_OPERATOR_SEGMENT_GS   = 'gs:'
    NODE_TYPE_OPERATOR_SEGMENT_GEN  = ':'
    
    OPERATORS = arch.Arch.OPERATORS+(
        NODE_TYPE_OPERATOR_SEGMENT_ES, NODE_TYPE_OPERATOR_SEGMENT_CS,
        NODE_TYPE_OPERATOR_SEGMENT_SS, NODE_TYPE_OPERATOR_SEGMENT_DS,
        NODE_TYPE_OPERATOR_SEGMENT_FS, NODE_TYPE_OPERATOR_SEGMENT_GS,
        NODE_TYPE_OPERATOR_SEGMENT_GEN)
    
    
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
        None, None,
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
        
        self.INSTRUCTIONS_CALL = self.__get_instruction_index(
            ('NN_call', 'NN_callfi', 'NN_callni'))
        self.INSTRUCTIONS_CONDITIONAL_BRANCH = self.__get_instruction_index(
            ('NN_ja', 'NN_jae', 'NN_jb', 'NN_jbe', 'NN_jc', 'NN_jcxz', 'NN_jecxz', 'NN_jrcxz', 'NN_je', 'NN_jg', 'NN_jge', 'NN_jl', 'NN_jle', 'NN_jna', 'NN_jnae', 'NN_jnb', 'NN_jnbe', 'NN_jnc', 'NN_jne', 'NN_jng', 'NN_jnge', 'NN_jnl', 'NN_jnle', 'NN_jno', 'NN_jnp', 'NN_jns', 'NN_jnz', 'NN_jo', 'NN_jp', 'NN_jpe', 'NN_jpo', 'NN_js', 'NN_jz'))
        self.INSTRUCTIONS_UNCONDITIONAL_BRANCH = self.__get_instruction_index(
            ('NN_jmp', 'NN_jmpfi', 'NN_jmpni', 'NN_jmpshort'))
        self.INSTRUCTIONS_RET = self.__get_instruction_index(
            ('NN_iretw', 'NN_iret', 'NN_iretd', 'NN_iretq'))
            
        self.INSTRUCTIONS_BRANCH = self.__get_instruction_index(
            ('NN_call', 'NN_callfi', 'NN_callni', 'NN_ja', 'NN_jae', 'NN_jb', 'NN_jbe', 'NN_jc', 'NN_jcxz', 'NN_jecxz', 'NN_jrcxz', 'NN_je', 'NN_jg', 'NN_jge', 'NN_jl', 'NN_jle', 'NN_jna', 'NN_jnae', 'NN_jnb', 'NN_jnbe', 'NN_jnc', 'NN_jne', 'NN_jng', 'NN_jnge', 'NN_jnl', 'NN_jnle', 'NN_jno', 'NN_jnp', 'NN_jns', 'NN_jnz', 'NN_jo', 'NN_jp', 'NN_jpe', 'NN_jpo', 'NN_js', 'NN_jz', 'NN_jmp', 'NN_jmpfi', 'NN_jmpni', 'NN_jmpshort'))
            
        self.no_op_instr = [ "lods", "stos", "scas", "cmps", "movs" ]
        
        self.arch_name = 'x86'
    
    def check_arch(self):
        
        if self.processor_name == 'metapc':
            return True
        
        return False

    def get_mnemonic(self, addr):
        """Return the mnemonic for the current instruction.
        
        """
        
        if idaapi.ua_mnem(addr) in self.no_op_instr:
            return idc.GetDisasm(addr)
        else:
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
        
        if idaapi.ua_mnem(address) in self.no_op_instr:
            return op_list
        
        for op, idx in operands:
            # The following will make sure it's an operand that IDA displays.
            # IDA sometimes encodes implicit operand's information into the
            # structures representing instructions but chooses not to display
            # those operands. We try to reproduce IDAs output
            #
            if idc.GetOpnd(address, idx) != '':
                current_operand = self.single_operand_parser(address, op, idx)
            
                if not current_operand:
                    continue
            
                if isinstance(current_operand[0], (list, tuple)):
                    op_list.extend( current_operand )
                else:
                    op_list.append( current_operand )
            
        operands = op_list
        
        return op_list

    
    def single_operand_parser(self, address, op, idx):
        """Parse a metapc operand."""
        
        # Convenience functions
        #
        def has_sib_byte(op):
            # Does the instruction use the SIB byte?
            return self.as_byte_value(op.specflag1)==1
        
        def get_sib_scale(op):
            return (None, 2, 4, 8)[self.as_byte_value(op.specflag2)>>6]
        
        def get_sib_scaled_index_reg(op):
            return self.SIB_INDEX_REGISTERS[(self.as_byte_value(op.specflag2)>>3)&0x7]
        
        def get_sib_base_reg(op):
            #
            #       [       [7-6]            [5-3]            [2-0] ]
            # MOD/RM = ( (mod_2 << 6) | (reg_opcode_3 << 3) | rm_3 )
            # There's not MOD/RM made available by IDA!?
            #
            #       [     [7-6]             [5-3]       [2-0] ]
            # SIB = ( (scale_2 << 6) | (index_3 << 3) | base )
            # op.specflag2
            #
            # instruction = op + modrm + sib + disp + imm
            #
            
            # If MOD is zero there's no base register, otherwise it's EBP
            # But IDA exposes no MOD/RM.
            # Following a discussion in IDA's forums:
            # http://www.hex-rays.com/forum/viewtopic.php?f=8&t=1424&p=8479&hilit=mod+rm#p8479
            # checking for it can be done in the following manner:
            #
            
            SIB_byte = self.as_byte_value(op.specflag2)
            
            return  self.SIB_BASE_REGISTERS[ SIB_byte & 0x7]
        
        def get_segment_prefix(op):
        
            seg_idx = (op.specval>>16)
            if seg_idx == 0:
                return None
                
            if (op.specval>>16) < len(self.REGISTERS[0]) :
                seg_prefix = self.REGISTERS[0][op.specval>>16] + ':'
            else:
                seg_prefix = op.specval&0xffff
                
            # This must return a string in case a segment register selector is used
            # or and int/long of a descriptor itself.
            #
            return seg_prefix
            
        
        def parse_phrase(op, has_displacement=False):
            """Parse the expression used for indexed memory access.
            
            Returns its AST as a nested list of lists.
            """
            
            # Check the addressing mode using in this segment
            segment = idaapi.getseg(address)
            if segment.bitness != 1:
                raise Exception(
                    'Not yet handling addressing modes other than 32bit!')
            
            
            base_reg = get_sib_base_reg(op)
            scaled_index_reg = get_sib_scaled_index_reg(op)
            scale = get_sib_scale(op)
            
            if scale:
                
                # return nested list for reg+reg*scale
                if base_reg != '':
                    # The last values in each tuple indicate the
                    # preferred display position of each element.
                    # base_reg + (scale_reg * scale)
                    #
                    
                    if scaled_index_reg == '':
                        return [
                            self.NODE_TYPE_OPERATOR_PLUS, 
                                [self.NODE_TYPE_REGISTER, base_reg, 0] ]
                        
                    return [
                        self.NODE_TYPE_OPERATOR_PLUS, 
                            [self.NODE_TYPE_REGISTER, base_reg, 0],
                            [self.NODE_TYPE_OPERATOR_TIMES,
                                [self.NODE_TYPE_REGISTER, scaled_index_reg, 0],
                                [self.NODE_TYPE_VALUE, scale, 1], 1 ] ]
                else:
                    # If there's no base register and
                    # mod == 01 or mod == 10 (=> operand has displacement)
                    # then we need to add EBP
                    if has_displacement:
                        return [
                            self.NODE_TYPE_OPERATOR_PLUS,
                                [ self.NODE_TYPE_REGISTER, 'ebp', 0],
                                [ self.NODE_TYPE_OPERATOR_TIMES,
                                    [self.NODE_TYPE_REGISTER, scaled_index_reg, 0],
                                    [self.NODE_TYPE_VALUE, scale, 1], 1 ] ]
                    return [
                        self.NODE_TYPE_OPERATOR_PLUS,
                            [ self.NODE_TYPE_OPERATOR_TIMES,
                                [self.NODE_TYPE_REGISTER, scaled_index_reg, 0],
                                [self.NODE_TYPE_VALUE, scale, 1], 0 ] ]
            
            else:
                # return nested list for reg+reg
                if base_reg == '':
                    if scaled_index_reg != '':
                        if has_displacement:
                            return [
                                self.NODE_TYPE_OPERATOR_PLUS,
                                    [ self.NODE_TYPE_REGISTER, 'ebp', 0],
                                    [ self.NODE_TYPE_REGISTER, scaled_index_reg, 1 ] ]
                        return [
                            self.NODE_TYPE_OPERATOR_PLUS,
                                [self.NODE_TYPE_REGISTER, scaled_index_reg, 0 ] ]
                    else:
                        if has_displacement:
                            return [self.NODE_TYPE_OPERATOR_PLUS, [self.NODE_TYPE_REGISTER, 'ebp', 0] ]
                        return [ ]
                        
                else:
                    if scaled_index_reg != '':
                        return [
                            self.NODE_TYPE_OPERATOR_PLUS,
                                [self.NODE_TYPE_REGISTER, base_reg, 0],
                                [self.NODE_TYPE_REGISTER, scaled_index_reg, 1 ] ]
                    else:
                        return [
                            self.NODE_TYPE_OPERATOR_PLUS,
                                [self.NODE_TYPE_REGISTER, base_reg, 0] ]
        
        
        # Operand parsing
        #
        
        if op.type == OPERAND_TYPE_NO_OPERAND:
            return None
        
        segment = idaapi.getseg(address)
        addressing_mode = segment.bitness
        
        # Start creating the AST, the root entry is always the width of the
        # operand
        operand = [self.OPERAND_WIDTH[ self.as_byte_value( op.dtyp ) ]]
        
        
        # If the operand indicates a displacement and it does
        # the indexing through the SIB the it might be referring
        # a variable on the stack and an attempt to retrieve it
        # is made.
        #
        
        
        # Compose the rest of the AST
        #
        
        if op.type == OPERAND_TYPE_DISPLACEMENT:
            
            # A displacement operatior might refer to a variable...
            #
            var_name = None
            
            # Try to get any stack name that might have been assigned
            # to the variable. 
            #
            flags = idc.GetFlags(address)
            if (idx==0 and idc.isStkvar0(flags)) or (
                idx==1 and idc.isStkvar1(flags)):
                
                var_name = self.get_operand_stack_variable_name(address, op, idx)
            
            if has_sib_byte(op) is True:
                # when SIB byte set, process the SIB indexing
                phrase = parse_phrase(op, has_displacement=True)
            else:
                phrase = [
                    self.NODE_TYPE_OPERATOR_PLUS, 
                        [self.NODE_TYPE_REGISTER,
                            self.REGISTERS[addressing_mode+1][op.reg], 0] ]
            
            if var_name:
                value = arch.ExpressionNamedValue(long(op.addr), var_name)
            else:
                value = op.addr
                
            # Calculate the index of the value depending on how many components
            # we have in the phrase
            #
            idx_of_value = len( phrase ) - 1
            operand.extend([
                [ get_segment_prefix(op),
                    [self.NODE_TYPE_DEREFERENCE,
                        phrase+[ [self.NODE_TYPE_VALUE, value, idx_of_value] ] ] ] ])
            
        
        elif op.type == OPERAND_TYPE_REGISTER:
            
            operand.extend([
                [self.NODE_TYPE_REGISTER, self.REGISTERS[self.as_byte_value(op.dtyp)][op.reg], 0]])
        
        elif op.type == OPERAND_TYPE_MEMORY:
            
            addr_name = self.get_address_name(op.addr)
            
            if addr_name:
                value = arch.ExpressionNamedValue(long(op.addr), addr_name)
            else:
                value = op.addr
            
            if has_sib_byte(op) is True:
                # when SIB byte set, process the SIB indexing
                phrase = parse_phrase(op)
                
                idx_of_value = len( phrase ) - 1
                operand.extend([
                    [ get_segment_prefix(op),
                        [self.NODE_TYPE_DEREFERENCE,
                            phrase+[[self.NODE_TYPE_VALUE, value, idx_of_value]] ] ] ])
            else:                
                operand.extend([
                    [ get_segment_prefix(op),
                        [self.NODE_TYPE_DEREFERENCE,
                            [self.NODE_TYPE_VALUE, value, 0] ] ] ])
            
            
        
        elif op.type == OPERAND_TYPE_IMMEDIATE:
            
            width = self.OPERAND_WIDTH[self.as_byte_value(op.dtyp)]
            
            if width == arch.Arch.NODE_TYPE_OPERATOR_WIDTH_BYTE_1:
                value = op.value&0xff
            elif width == arch.Arch.NODE_TYPE_OPERATOR_WIDTH_BYTE_2:
                value = op.value&0xffff
            elif width == arch.Arch.NODE_TYPE_OPERATOR_WIDTH_BYTE_4:
                value = op.value&0xffffffff
            else:
                value = op.value
            
            operand.extend([[self.NODE_TYPE_VALUE, value, 0]])
            
        
        elif op.type in (OPERAND_TYPE_NEAR, OPERAND_TYPE_FAR):
            
            addr_name = self.get_address_name(op.addr)
            
            if addr_name:
                value = arch.ExpressionNamedValue(long(op.addr), addr_name)
            else:
                value = op.addr
            
            seg_prefix = get_segment_prefix(op)
            if isinstance(seg_prefix, str):
                operand.extend([
                    [ seg_prefix, [self.NODE_TYPE_VALUE, value, 0] ]])
            elif isinstance(seg_prefix, (int, long)):
                operand.extend([
                    [ self.NODE_TYPE_OPERATOR_SEGMENT_GEN, 
                        [self.NODE_TYPE_VALUE, seg_prefix, 0],
                        [self.NODE_TYPE_VALUE, value, 1] ]] )
            
        
        elif op.type == OPERAND_TYPE_PHRASE:
            if has_sib_byte(op) is True:
                phrase = parse_phrase(op)
                
                # Detect observed cases (in GCC compiled sshd) where GCC's instruction
                # encoding would be parsed into a phrase with an addition of a single
                # register, without any other summands. 
                # In those cases, if there's a name associated to the zero such as
                # a stack variable, we will add a zero to the sum. We do that to have
                # an expression to which alias an expression substitution (in the past
                # we were removing the addition altogether)
                # If there's no name we will remove the redundant 0
                # 
                #
                # This case has been observed for the encoding of [esp] where the tree
                # would be "[" -> "+" -> "esp".
                #
                #
                if phrase[0] == self.NODE_TYPE_OPERATOR_PLUS and len(phrase) == 2:
                    
                    var_name = self.get_operand_stack_variable_name(address, op, idx)
                    if var_name:
                        value = arch.ExpressionNamedValue(0, var_name)
                        phrase.append( [self.NODE_TYPE_VALUE, value, 1] )
                    else:
                        phrase = phrase[1]
                    
                
                operand.extend([
                    [get_segment_prefix(op),
                        [self.NODE_TYPE_DEREFERENCE, phrase] ]] )
                
            else:
                operand.extend([
                    [get_segment_prefix(op),
                        [self.NODE_TYPE_DEREFERENCE,
                            [self.NODE_TYPE_REGISTER,
                                self.REGISTERS[addressing_mode+1][op.phrase], 0] ] ]])
        
        elif op.type == OPERAND_TYPE_IDPSPEC0:
            # The operand refers to the TR* registers
            operand.extend([
                [self.NODE_TYPE_REGISTER, 'tr%d' % op.reg, 0]])
        
        elif op.type == OPERAND_TYPE_IDPSPEC1:
            # The operand refers to the DR* registers
            operand.extend([
                [self.NODE_TYPE_REGISTER, 'dr%d' % op.reg, 0]])
        
        elif op.type == OPERAND_TYPE_IDPSPEC2:
            # The operand refers to the CR* registers
            operand.extend([
                [self.NODE_TYPE_REGISTER, 'cr%d' % op.reg, 0]])
        
        elif op.type == OPERAND_TYPE_IDPSPEC3:
            # The operand refers to the FPU register stack
            operand.extend([
                [self.NODE_TYPE_REGISTER, 'st(%d)' % op.reg, 0]])
        
        elif op.type == OPERAND_TYPE_IDPSPEC4:
            # The operand is a MMX register
            operand.extend([
                [self.NODE_TYPE_REGISTER, 'mm%d' % op.reg, 0]])
        
        elif op.type == OPERAND_TYPE_IDPSPEC5:
            # The operand is a MMX register
            operand.extend([
                [self.NODE_TYPE_REGISTER, 'xmm%d' % op.reg, 0]])
        
        # If no other thing that a width, i.e. ['b2'] is retrieved
        # we assume there was no operand... this is a hack but I've seen
        # IDA pretend there's a first operand like this:
        #
        # fld ['b2'], ['b4', ['ds', ['[', ['+', ['$', 'edx'], [...]]]]]
        #
        # So, in these cases I want no first operand...
        #if len(operand)==1:
        #    return None

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
        
        if i_mnemonic is None:
            return None

        if idaapi.get_byte(addr) == 0xf0:
            prefix = 'lock '
        else:
            prefix = ''
                    
        packet.add_instruction(instruction, addr, prefix+i_mnemonic,
            operand_strings, operands, data)
        
        return instruction
    

            
