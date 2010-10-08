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

from sets import Set


class FunctionalUnit:
    
    # def __init__(self, start, end):
    def __init__(self, start):
        
        # Start and end addresses of the function.
        #
        # If the function consists of multiple
        # non-sequential chunks, 'end' should be
        # the last address of the first chunk
        # (where the function's entry point lays)
        
        self.start = start
        # self.end = end
        
        # Function's name
        self.name =  None
        
        # If the module belongs to a DLL its name will be stored
        # in this variable
        #
        self.module = None
        
        # Source and target addresses of the branches
        self.branch_sources = set()
        self.branch_targets = set()
        
        # Data references made.
        # {src: [dst,]}
        self.data_references = dict()
        
        # Basic blocks composing the function.
        # It's a list of (start, end) address pairs.
        self.blocks = list()
        
        # Set of pairs (source, target) address for
        # all branches.
        self.branches = set()
        
        # Kinds of all branches. The keys are the elements
        # of self.branches and the values the kind of branch
        #
        # common.BRANCH_TYPE_TRUE =          0
        # common.BRANCH_TYPE_FALSE =         1
        # common.BRANCH_TYPE_UNCONDITIONAL = 2
        # common.BRANCH_TYPE_SWITCH =        3
        
        self.branch_kinds = dict()
        
        # List of pairs (source, target) of indexes
        # into the basic blocks 'blocks' list.
        self.cfg_block_paths = list()
        
        # List of instruction addresses for all addresses
        # belonging to the function
        self.instructions = list()
        
        # Dictionary containing all the instruction sizes.
        # Keys are the addresses of the instructions.
        self.instruction_sizes = dict()
        
        # Information about the normal flow from instruction
        # to instruction. Refer to 'is_flow' for more info.
        self.instruction_flow = dict()
        
        # Pairs of (source, target) for calls made from within the
        # function. 'source' is always in the function's body.
        self.calls = list()
        
        # Function chunks are discovered as we process the
        # functions's flow. For a conventional function
        # existing sequentically in memory this will be a
        # unique block.
        #
        self.function_chunks = list()
        
        
        # Kind of function
        self.kind = None
        
    
    def add_instructions(self, instructions):
        """Add instructions information.
        
        The argument is a list of pairs (adress, instruction_length).
        """
        
        self.instruction_sizes.update(dict(instructions))
        self.instructions.extend([i[0] for i in instructions])
        self.instructions.sort()
        
    
    def insn_size(self, addr):
        """Return the size of the instruction at the given address.
        
        Returns none if no instruction is known to exist at such
        location.
        """
        
        return self.instruction_sizes.get(addr, None)
        
    
    def has_instruction_at(self, address):
        """Query whether an instruction at the given address exists."""
        
        return address in self.instructions
        
    
    def set_instruction_flow(self, flows):
        """Set flow information for the instructions given.
        
        'flows' is a list of pairs (address, boolean) indicating
        whether the instruction at 'address' is reachable by
        normal flow, that is, if flow can go from the previous
        instruction to the one at 'address'.
        Cases where it will be False are, for instance. Start of
        the function, start of function chunks separated from the
        main body of the function, start of basic blocks starting
        after unconditional jumps or rets.
        """
        
        self.instruction_flow.update(dict(flows))
        
    
    def is_flow(self, addr):
        """Returns whether normal execution can flow from the previous instruction to this one.
        
        See 'set_instruction_flow' for more info."""
        
        if not self.has_instruction_at(addr):
            return None
        
        return self.instruction_flow.get(addr, False)
        
    
    def instructions_in_range(self, start, end):
        """Return the instructions in the given range."""
        
        return [i for i in self.instructions if i>=start and i<=end]
        
    
    def add_data_reference(self, ref):
        """Add data reference
        
        'ref' is of the form (source, target)
        """
        
        if ref[0] in self.data_references:
            self.data_references[ ref[0] ].append( ref[1] )
        else:
            self.data_references[ ref[0] ] = [ ref[1] ]
    
    
    def add_branch(self, branch):
        """Add branch information.
        
        'branch' is of the form (source, target)
        """
        
        self.branches.add(branch)
        self.branch_sources.add(branch[0])
        self.branch_targets.add(branch[1])
        
    
    def get_block_by_address(self, address):
        """Returns basic block containing the given address."""
        
        for b in self.blocks:
            if address>=b[0] and address<=b[1]:
                return b
        
        return None
        
    
    def get_prev_address(self, ea):
        """Get the previous address to the given one.
        
        This takes into account the instruction flow. If it exists
        an instruction in the immediately preceeding address but
        the execution flow can't reach the given one None is returned.
        """
        
        if self.is_flow(ea)==False or ea not in self.instructions:
            return None
        
        idx = self.instructions.index(ea)
        if idx==0:
            return None
        else:
            return self.instructions[idx-1]
        
    
    def get_next_address(self, ea):
        """Get the following address to the given one.
        
        This takes into account the instruction flow. If it exists
        an instruction in the immediately following address but
        the execution flow from the given one can't reach it None
        is returned.
        """
        
        idx = self.instructions.index(ea)
        
        if idx+1 == len(self.instructions) or   \
            self.is_flow(self.instructions[idx+1])==False:
                
            return None
            
        else:
            return self.instructions[idx+1]
        
    
    def build_main_blocks(self):
        """Compose main function blocks.
        
        Scan sequentially all the instructions in the function and
        group them into blocks where all instruction sequentailly
        follow each other.
        """
        
        # Function chunks can be located before the start of the
        # function, so we just get the lowest address belonging to
        # the function.
        b_start = min(self.instructions) # == self.instructions[0]
        for idx, ea in enumerate(self.instructions):
            
            if idx+1 == len(self.instructions):
                next_ea = None
            else:
                next_ea = self.instructions[idx+1]
            
            if ea+self.insn_size(ea) != next_ea or not self.is_flow(next_ea):
                self.blocks.append([b_start, ea])
                if not next_ea:
                    break
                b_start = next_ea
        
    
    def split_blocks_by_target_branches(self):
        """Split the function blocks at all target locations of a branch."""
        
        for ref in self.branch_targets:
            b = self.get_block_by_address(ref)
            if not b:
                continue
            
            # If the reference already points to a block's start
            # there's nothing to do.
            if b[0] == ref:
                continue
                
            end = b[1]
            if end>=ref:
                prev_ea = self.get_prev_address(ref)
                if prev_ea:
                    b[1] = prev_ea
                    self.blocks.append([ref, end])
                    self.branches.add((prev_ea, ref))
            
    
    def split_blocks_by_source_branches(self):
        """Split the function blocks at all source locations of a branch."""
        
        for ref in self.branch_sources:
            b = self.get_block_by_address(ref)
            if not b:
                continue
            end = b[1]
            next_ea = self.get_next_address(ref)
            
            if next_ea and end >= next_ea:
                b[1] = ref
                self.blocks.append([next_ea, end])
            
    
    def find_cfg_paths(self):
        """Generate control flow graph paths.
        
        Goes through all branches and get all the destination and
        target blocks generating a list of paths where the contents
        are the block's index into the basic blocks list of the
        function.
        """
        
        self.blocks.sort()
        
        for ref in self.branches:
            b_from = self.get_block_by_address(ref[0])
            b_to = self.get_block_by_address(ref[1])
            if self.blocks and b_from in self.blocks and b_to in self.blocks:
                self.cfg_block_paths.append(
                    (self.blocks.index(b_from), self.blocks.index(b_to)))
            self.cfg_block_paths.sort()
        
    
    def find_branch_types(self):
        
        branch_dict = dict()
        for b in self.branches:
            trgt_set = branch_dict.get(b[0], set())
            trgt_set.add(b[1])
            branch_dict[b[0]] = trgt_set
        
        
        for src, trgt_set in branch_dict.items():
            
            # Take a look whether a data references is also
            # made from this address, that might help identify
            # switches
            #
            # NOTE: according to intel all conditional jumps
            # have relative addresses as operands. Only
            # unconditional jumps can make memory dereferences
            #
            src_has_data_ref = False
            if src in self.data_references:
                src_has_data_ref = True
            
            # if 'src' only has one outgoing edge it's unconditional
            if len(trgt_set) == 1:
                self.branch_kinds[
                    (src, list(trgt_set)[0])] = common.BRANCH_TYPE_UNCONDITIONAL
                continue
            
            if len(trgt_set) == 2 and src_has_data_ref is False:
            
                # if one of the edges follows immediatelly
                # then it'll be a conditional jump
                
                next_insn = src+self.instruction_sizes[src]
                trgt_set = list(trgt_set)
                
                if next_insn in trgt_set:
                    if next_insn == trgt_set[0]:
                        self.branch_kinds[
                            (src, trgt_set[0])] = common.BRANCH_TYPE_FALSE
                        self.branch_kinds[
                            (src, trgt_set[1])] = common.BRANCH_TYPE_TRUE
                    else:
                        self.branch_kinds[
                            (src, trgt_set[0])] = common.BRANCH_TYPE_TRUE
                        self.branch_kinds[
                            (src, trgt_set[1])] = common.BRANCH_TYPE_FALSE
                    continue

            # If it was not an unconditional jump and all the tests for a
            # conditional one failed, it's got to be a switch...
            #
            # We could do a test like "if src_has_data_ref is True:"
            # but would fail when the address is not avaiable, like in
            # the case of a switch like [eax+ebx*4], hence we don't
            # explicitly check for it and assume it's going to be a switch
            #
            for trgt in trgt_set:
                self.branch_kinds[
                    (src, trgt)] = common.BRANCH_TYPE_SWITCH
            
                
    
    def analyze(self):
        """Main analysis function.
        
        It will:
            -Compose the main blocks of the function.
            -Split them according to all the branching information.
            -Generate function's internal connectivity information.
        """
        
        self.build_main_blocks()
                
        self.split_blocks_by_target_branches()
        
        self.split_blocks_by_source_branches()
        
        self.find_branch_types()
        
        self.find_cfg_paths()
    


class ImportedFunction(FunctionalUnit):
    """Class representing an imported function."""

    def __init__(self, start, name, module):
        FunctionalUnit.__init__(self, start)
        self.name = name
        self.module = module
        self.kind = common.FUNC_TYPE.FUNCTION_IMPORTED

        # An nonexistent instruction is added in order to be able
        # to find the function by address.
        self.instructions.append(start)
        self.instruction_sizes[start] = 0

        self.analyze()

