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
import re
import time
import ConfigParser
import functional_unit
import idc
import idaapi
import idautils
import sys
from sql_exporter import SQLExporter
from instrumentation import Instrumentation
from common import *

if 'MEMORY_PROFILE' in os.environ:
    print 'MEMORY_PROFILE environment variable set. Will show memory usage statistics'
    
    import memory_info
    def mem_info():
        memory = memory_info.memory()
        resident = memory_info.resident()
        try:
            print 'Memory usage[ %d bytes = %.2f KiB = %.2f MiB ] Resident[ %d bytes = %.2f KiB = %.2f MiB ]' % (
                memory, memory/2**10, memory/2**20, resident, resident/2**10, resident/2**20 )
        except TypeError:
            print 'TypeError while attemping to print memory info: ', memory, type(memory), resident, type(resident)
    

CONFIG_FILE_NAME = os.environ.get('IDA2SQLCFG', None)

USE_NEW_SCHEMA = True
use_old_schema = os.environ.get('IDA2SQL_USE_OLD_SCHEMA', None)
if use_old_schema:
    USE_NEW_SCHEMA = False

# Gobal variable to keep track of time
#
tm_start = 0

class FunctionAnalyzer(functional_unit.FunctionalUnit):
    "Class representing an analyzed function."
    
    
    def __init__(self, arch, start_ava, packet):
        
        functional_unit.FunctionalUnit.__init__(self, start_ava)
        
        # Architecure handling class
        #
        self.arch = arch
        
        # Add all the calls referring to this function
        #
        self.calls.extend(
            [call for call in packet.calls.items() if call[1]])
            
        # Add all the branches with their target within the function
        #
        [self.add_branch(branch) for branch in packet.branches if
            packet.disassembly.has_key(branch[1])]

        [self.add_data_reference(ref[:2]) for ref in packet.address_references ]
        
        self.reconstruct_flow(start_ava, packet)
        if not self.function_chunks:
            raise FunctionException(None)
        
        self.name = idc.GetFunctionName(start_ava)
        
        # Now the function's end can be set.
        # End is set to the last instruction of the first
        # continuous sequence of code from the beginning of
        # the function.
        #
        self.end = self.function_chunks[0][-1]
        
        flags = idc.GetFunctionFlags(start_ava)
        
        if flags&idaapi.FUNC_LIB == idaapi.FUNC_LIB:
            self.kind = FUNC_TYPE.FUNCTION_LIBRARY
        elif flags&idaapi.FUNC_THUNK == idaapi.FUNC_THUNK:
            self.kind = FUNC_TYPE.FUNCTION_THUNK
        else:
            self.kind = FUNC_TYPE.FUNCTION_STANDARD
        
        
        # Each chunk is a list of addresses of instructions
        # within the chunk.
        instruction_addresses = list()
        chunk_starting_addresses = list()
        chunk_remaining_addresses = list()
        for chunk in self.function_chunks:
            # The first instruction in a chunk can't have normal
            # flow into it. Only unconditional branches or code
            # after end-of-flow instructions lead to new
            # chunks.
            instruction_addresses.extend(chunk)
            chunk_starting_addresses.append(chunk[0])
            chunk_remaining_addresses.extend(chunk[1:])
        
        self.set_instruction_flow(
            zip( chunk_remaining_addresses,
                (True,)*len(chunk_remaining_addresses)))
        
        self.set_instruction_flow(
            zip( chunk_starting_addresses,
                (False,)*len(chunk_starting_addresses)))
        
        instruction_sizes = [i[0].size for i in
            (packet.disassembly[addr] for addr in instruction_addresses)]
        
        self.add_instructions(
            zip(instruction_addresses, instruction_sizes) )
        
        # Call the FunctionalUnit's analyze function
        self.analyze()
    
    def reconstruct_flow(self, function_start, packet):
        
        disassembly = packet.disassembly
        instructions_queue = set(disassembly.keys())
        
        visited = set()
        branches_to_do = list([function_start]+
            list(b[1] for b in packet.branches))
        
        # Walk all the function code.
        #
        while branches_to_do:
            addr = branches_to_do.pop()
            if addr in visited:
                continue
            chunk = list()
            
            while True:
                if addr in visited:
                    # If the address has been visited the blocks need
                    # to be merged, as there's normal flow from one
                    # to another.
                    old_chunk = [c for c in self.function_chunks if
                        addr in c][0]
                    chunk.extend(old_chunk)
                    self.function_chunks.remove(old_chunk)
                    break
                
                i, i_data = disassembly.get(addr, (None, None))
                if not i:
                    break
                
                visited.add(addr)
                instructions_queue.remove(addr)
                chunk.append(addr)
                
                if self.arch.is_end_of_flow(i):
                    break
                
                addr += i.size
                
            if chunk:
                self.function_chunks.append(chunk)
            
        # If there are instruction left after the previous analysis
        # those must be disconnected from the rest, either dead code
        # or referenced at runtime.
        if instructions_queue:
            instructions_queue = list(instructions_queue)
            instructions_queue.sort()
            chunk = [instructions_queue.pop(0)]
            while True:
                if not instructions_queue:
                    break
                curr_i = disassembly[chunk[-1]][0]
                next = instructions_queue.pop(0)
                
                if (not (self.arch.is_end_of_flow(curr_i) ) and
                    chunk[-1]+curr_i.size == next):
                    
                    chunk.append(next)
                else:
                    self.function_chunks.append(chunk)
                    chunk = [next]
            
            if chunk:
                self.function_chunks.append(chunk)
            
    

def get_chunks(ea):
    
    function_chunks = []
    
    #Get the tail iterator
    func_iter = idaapi.func_tail_iterator_t(idaapi.get_func(ea))
    
    # While the iterator's status is valid
    status = func_iter.main()
    while status:
        # Get the chunk
        chunk = func_iter.chunk()
        # Store its start and ending address as a tuple
        function_chunks.append((chunk.startEA, chunk.endEA))
        
        # Get the last status
        status = func_iter.next()
    
    return function_chunks

def address_in_chunks(address, chunk_list):
    
    for chunk_start, chunk_end in chunk_list:
        if chunk_start <= address < chunk_end:
            return True
    
    return False
    

def get_flow_code_from_address(address):
    """Get a sequence of instructions starting at a given address.
    
    This function is used to collect basic blocks marked as chunks in IDA
    but not as belonging to the function being examined. IDA can only
    assign a chunk to a function, not to multiple.
    This helps getting around that limitation.
    """
    
    if idc.isCode(idc.GetFlags(address)):
        code = [address]
    else:
        return None
    
    while True:
    
        # Get the address of the following element
        address = address+idc.ItemSize(address)
        
        flags = idc.GetFlags(address)
        
        # If the element is an instruction and "flow" goes into it
        if idc.isCode(flags) and idc.isFlow(flags):
            code.append(address)
        else:
            break    
        
    # Return the code chunk just obtained
    # Note: if we get down here there'll be at least one instruction so we are cool
    # Node: the +1 is so the last instruction can be retrieved through a call to
    #   "Heads(start, end)". As end is a non-inclusive limit we need to move the 
    #   pointer ahead so the instruction at that address is retrieved.
    return (min(code), max(code)+1)
    

def process_function(arch, func_ea):
    
    func_end = idc.FindFuncEnd(func_ea)
    
    packet = DismantlerDataPacket()
    
    ida_chunks = get_chunks(func_ea)
    chunks = set()
    
    # Add to the chunks only the main block, containing the
    # function entry point
    #
    chunk = get_flow_code_from_address(func_ea)
    if chunk:
        chunks.add( chunk )
    
    # Make "ida_chunks" a set for faster searches  within
    ida_chunks = set(ida_chunks)
    ida_chunks_idx = dict(zip([c[0] for c in ida_chunks], ida_chunks))
    
    func = idaapi.get_func(func_ea)
    comments = [idaapi.get_func_cmt(func, 0), idaapi.get_func_cmt(func, 1)]
    
    # Copy the list of chunks into a queue to process
    #
    chunks_todo = [c for c in chunks]
    
    while True:
        
        # If no chunks left in the queue, exit
        if not chunks_todo:
        
            if ida_chunks:
                chunks_todo.extend(ida_chunks)
            else:   
               break
        
        chunk_start, chunk_end = chunks_todo.pop()
        if ida_chunks_idx.has_key(chunk_start):
            ida_chunks.remove(ida_chunks_idx[chunk_start])
            del ida_chunks_idx[chunk_start]
        
        for head in idautils.Heads(chunk_start, chunk_end):
        
            comments.extend( (idaapi.get_cmt(head, 0), idaapi.get_cmt(head, 1)) )
            comment = '\n'.join([c for c in comments if c is not None])
            comment = comment.strip()
            if comment:
                packet.add_comment(head, comment)
            comments = list()
            
            if idc.isCode(idc.GetFlags(head)):
                
                instruction = arch.process_instruction(packet, head)
                
                # if there are other references than
                # flow add them all.
                if list( idautils.CodeRefsFrom(head, 0) ):
                    
                    # for each reference, including flow ones
                    for ref_idx, ref in enumerate(idautils.CodeRefsFrom(head, 1)):
                        
                        if arch.is_call(instruction):
                            
                            # This two conditions must remain separated, it's
                            # necessary to enter the enclosing "if" whenever
                            # the instruction is a call, otherwise it will be
                            # added as an uncoditional jump in the last else
                            #
                            if ref in list( idautils.CodeRefsFrom(head, 0) ):
                                packet.add_direct_call(head, ref)
                        
                        elif ref_idx>0 and arch.is_conditional_branch(instruction):
                            # The ref_idx is > 0 in order to avoid processing the
                            # normal flow reference which would effectively imply
                            # that the conditional branch is processed twice.
                            # It's done this way instead of changing the loop's head
                            # from CodeRefsFrom(head, 1) to CodeRefsFrom(head, 0) in
                            # order to avoid altering the behavior of other conditions
                            # which rely on it being so.
                            
                            # FIXME
                            # I don't seem to check for the reference here
                            # to point to valid, defined code. I suspect
                            # this could lead to a failure when exporting
                            # if such situation appears. I should test if
                            # it's a likely scenario and probably just add
                            # an isHead() or isCode() to address it.
                            
                            packet.add_conditional_branch_true(head, ref)
                            packet.add_conditional_branch_false(
                                head, idaapi.next_head(head, chunk_end))
                                
                            # If the target is not in our chunk list
                            if not address_in_chunks(ref, chunks):
                                new_chunk = get_flow_code_from_address(ref)
                                # Add the chunk to the chunks to process
                                # and to the set containing all visited
                                # chunks
                                if new_chunk is not None:
                                    chunks_todo.append(new_chunk)
                                    chunks.add(new_chunk)
                                    
                        elif arch.is_unconditional_branch(instruction):
                            packet.add_unconditional_branch(head, ref)
                            
                            # If the target is not in our chunk list
                            if not address_in_chunks(ref, chunks):
                                new_chunk = get_flow_code_from_address(ref)
                                # Add the chunk to the chunks to process
                                # and to the set containing all visited
                                # chunks
                                if new_chunk is not None:
                                    chunks_todo.append(new_chunk)
                                    chunks.add(new_chunk)
                                
                        #skip = False
                
                for ref in idautils.DataRefsFrom(head):
                    packet.add_data_reference(head, ref)
                    
                    # Get a data reference from the current reference's
                    # location. For instance, if 'ref' points to a valid
                    # address and such address contains a data reference
                    # to code.
                    target = list( idautils.DataRefsFrom(ref) )
                    if target:
                        target = target[0]
                    else:
                        target = None
                    
                    if target is None and arch.is_call(instruction):
                        imp_name = idc.Name(ref)

                        imp_module = get_import_module_name(ref)

                        imported_functions.add((ref, imp_name, imp_module))
                        packet.add_indirect_virtual_call(head, ref)
                    
                    elif target is not None and idc.isHead(target):
                        # for calls "routed" through this reference
                        if arch.is_call(instruction):
                            packet.add_indirect_call(head, target)
                            
                        # for unconditional jumps "routed" through this reference
                        elif arch.is_unconditional_branch(instruction):
                            packet.add_unconditional_branch(head, target)
                        
                        # for conditional "routed" through this reference
                        elif arch.is_conditional_branch(instruction):
                            packet.add_conditional_branch_true(head, target)
                            packet.add_conditional_branch_false(
                                head, idaapi.next_head(head, chunk_end))
    
    
    f = FunctionAnalyzer(arch, func_ea, packet)
    
    instrumentation.new_packet(packet)
    instrumentation.new_function(f)


idata_seg_start = 0
idata_seg_end = 0
# Will contain a list of tuples of the form:
# ((range_start, range_end), name_for_the_range_of_addresses)
# The name is valid for the range of addresses it covers in the
# .idata segment, once a new name is defined, a new range starts
#
module_names = None


def get_import_module_name(address):
    
    global module_names
    global idata_seg_start
    global idata_seg_end
    
    segment_eas = list( idautils.Segments() )
    
    # This hasn't been initialized yet...
    #
    if module_names is None:
        
        module_names = list()
        for idata_seg_start in segment_eas:
            print "Going through segment %08X" % idata_seg_start
            segment = idaapi.getseg(idata_seg_start)
            if segment.type != idaapi.SEG_XTRN:
                continue
            print "Found idata segment"
        
            idata_seg_end = idc.SegEnd(idata_seg_start)
            
            parse = re.compile('.*Imports\s+from\s+([\w\d]+\.[\w\d]+).*', re.IGNORECASE)
            
            # save the address/module name combinations we discover
            #
            modules = list()
            
            # Scan the .idata segment looking for the imports from
            # string and get the address ranges where it applies
            #
            for head in idautils.Heads(idata_seg_start, idata_seg_end):
                for line_id in range(100):
                    line = idc.LineA(head, line_id)
                    if line and 'imports from' in line.lower():
                        res = parse.match(line)
                        if res:
                            print 'Found import line [%s][%s]' % (line, res.group(1))
                            modules.append( (head, res.group(1).lower()) )
                
            modules.append( (idata_seg_end, None) )
            for idx in range(len(modules)-1):
                mod = modules[idx]
                module_names.append( ( (mod[0], modules[idx+1][0]), mod[1] ) )
                
    
    for addr_range, module_name in module_names:
        if addr_range[0] <= address < addr_range[1]:
            return module_name
            
    return None

def load_function_set():
    
    function_addresses = set()
    
    dataf_path = idaapi.idadir('function_set.txt')
    if os.path.exists(dataf_path) and os.path.isfile(dataf_path):
    
        dataf = file(dataf_path, 'rt')
        while True:
        
            line = dataf.readline()
            if not line:
                break
            try:
                function_addresses.add(int(line, 16))
            except ValueError:
                pass
            
        dataf.close()
            
    return function_addresses

def process_section_data(arch, section, section_end):
    
    log_message('Fetching data for section...')
    
    section_data = list()
    for addr in range(section, section_end):
        if idaapi.isLoaded(addr):
            section_data.append( chr(idc.Byte(addr)) )
        else:
            # If there's undefined data in the middle
            # of a section, nothing after that point
            # is exported
            break
            
    section_data = ''.join(section_data)
    sect = Section(idc.SegName(section), 0, section, section_end, section_data)
    
    log_message('Inserting section data (%d bytes)...' % (len(section_data)))
    instrumentation.new_section(sect)
    
def workaround_Functions(start=idaapi.cvar.inf.minEA, end=idaapi.cvar.inf.maxEA):
    """
    Get a list of functions

    @param start: start address (default: inf.minEA)
    @param end:   end address (default: inf.maxEA)

    @return: list of heads between start and end

    @note: The last function that starts before 'end' is included even
    if it extends beyond 'end'.
    """
    func = idaapi.get_func(start)
    if not func:
        func = idaapi.get_next_func(start)
    while func and func.startEA < end:
        startea = func.startEA
        yield startea
        func = idaapi.get_next_func(startea)
        addr = startea
        while func and startea == func.startEA:
            addr = idaapi.next_head(addr, end)
            func = idaapi.get_next_func(addr)
        

def process_binary(arch, process_sections, iteration, already_imported):
    
    global imported_functions
    
    total_function_count = 0
    
    imported_functions = set()
    
    functions_to_export = load_function_set()
    
    FUNCTIONS_PER_RUN = 5000
    
    if iteration == -1:
        firstFunction = 0
        lastFunction = 0x7FFFFFFF
    else:
        firstFunction = iteration * FUNCTIONS_PER_RUN
        lastFunction = firstFunction + FUNCTIONS_PER_RUN - 1
        
    segment_list = list( idautils.Segments() )
    
    if 'MEMORY_PROFILE' in os.environ:
        #h = hp.heap()
        mem_info()
        
    segment_count = 1
    incomplete = False
    for seg_ea in segment_list:
    
        seg_end = idc.SegEnd(seg_ea)
        
        if process_sections:
            process_section_data(arch, seg_ea, seg_end)

        function_list = set(f for f in workaround_Functions(seg_ea, seg_end) if idc.SegStart(f)==seg_ea)
        function_count = 1
        
        if functions_to_export:
            log_message('Only exporting %d functions: %s' % (
                len(functions_to_export),
                str([hex(ea) for ea in functions_to_export])) )
            
            function_list = filter(lambda x:x in function_list, functions_to_export)

        if not function_list:
            log_message('Processing: Segment[%d/%d]. No Functions' % (
                segment_count, len(segment_list)) )
        
        for func_ea in function_list:
            
            if total_function_count < firstFunction:
                total_function_count += 1
                continue
                
            if total_function_count > lastFunction:
                incomplete = True
                break
        
            total_function_count += 1
            
            log_message(
                'Processing: Segment[%d/%d]. Function[%d/%d] at [%x]. Time elapsed: %s. Avg time per function: %s' % (
                segment_count, len(segment_list),
                function_count, len(function_list), func_ea, 
                get_time_delta_string(), get_avg_time_string(total_function_count) ) )
                
            process_function(arch, func_ea)
            
            function_count +=1 
                                    
        segment_count += 1
        
        if incomplete:
            break
    
    for imp_addr, imp_name, imp_module in imported_functions:
    
        if iteration != -1 and imp_addr in already_imported:
            continue
        
        packet = DismantlerDataPacket()
        packet.add_instruction(None, imp_addr, None, [], [], '')
        instrumentation.new_packet(packet)
        
        f = functional_unit.ImportedFunction(imp_addr, imp_name, imp_module)
        instrumentation.new_function(f)
        
    if 'MEMORY_PROFILE' in os.environ:
        mem_info()
        
    return incomplete

def query_configuration():
    
    # Set the default values to None
    db_engine, db_host, db_name, db_user, db_password = (None,)*5
    
    class ExportChoose(idaapi.Choose):
        def __init__(self, engines = []):
            idaapi.Choose.__init__(self, engines, 'Select Database Type', 1)
            self.width = 30
            
        def sizer(self):
            return len(self.list)-1
            
    engines = [
        DB_ENGINE.MYSQL, DB_ENGINE.POSTGRESQL,
        DB_ENGINE.MYSQLDUMP, 'Export Method']
    dlg = ExportChoose(engines)
    
    chosen_one = dlg.choose()
    if chosen_one>0:
        db_engine = engines[chosen_one-1]
    
        if db_engine == DB_ENGINE.MYSQLDUMP:
            # If a SQL dump is going to be generated, no DB
            # parameters are needed
            #
            return db_engine, '', '', '' ,''
    
        db_host = idc.AskStr('localhost', '[1/4] Enter database host:')
        if not db_host is None:
            db_name = idc.AskStr('db_name', '[2/4] Enter database(schema) name:')
            if not db_name is None:
                db_user = idc.AskStr('root', '[3/4] Enter database user:')
                if not db_user is None:
                    db_password = idc.AskStr('', '[4/4] Enter password for user:')
    
    return db_engine, db_host, db_name, db_user, db_password

def get_time_delta_string():
    global tm_start
    
    tm_delta = time.time() - tm_start
    
    tm_delta_tup = [t-z for (t,z) in zip( time.localtime(tm_delta), time.localtime(0) )]
    
    tm_delta_str = '%02d:%02d:%02d.%03d' % (
        tm_delta_tup[3], tm_delta_tup[4],
        tm_delta_tup[5], 1000*(tm_delta-long(tm_delta)))
    
    return tm_delta_str

def get_avg_time_string(items):
    global tm_start
    
    tm_delta = time.time() - tm_start
    tm_delta = float(tm_delta) / items
    
    tm_delta_tup = [t-z for (t,z) in zip( time.localtime(tm_delta), time.localtime(0) )]
    
    tm_delta_str = '%02d:%02d:%02d.%03d' % (
        tm_delta_tup[3], tm_delta_tup[4],
        tm_delta_tup[5], 1000*(tm_delta-long(tm_delta)))
    
    return tm_delta_str

def main():
    
    global tm_start
    
    for mod in ('metapc', 'ppc', 'arm'):
        arch_mod = __import__('arch.%s' % mod, globals(), locals(), ['*'])
        arch = arch_mod.Arch()
        if arch:
            if arch.check_arch():
                # This is a valid module for the current architecure
                # so the search has finished
                log_message('Using architecture module [%s]' % mod)
                break
    else:
        log_message('No module found to process the current architecure [%s]. Exiting.' % (arch.processor_name))
        return
        
    global instrumentation
    
    log_message('Initialization sucessful.')
    
    db_engine, db_host, db_name, db_user, db_password = (None,)*5
    batch_mode = False
    module_comment = ''
    process_sections = False
    
    
    # If the configuration filename has been fetched from the
    # environment variables, then use that.
    #
    if CONFIG_FILE_NAME:
        config_file_path = CONFIG_FILE_NAME
        
    # Otherwise fallback into the one expected in the IDA directory
    #
    else:
        config_file_path = os.path.join(idaapi.idadir(''), 'ida2sql.cfg')
     
    
    if os.path.exists(config_file_path):
        cfg = ConfigParser.ConfigParser()
        cfg.read(config_file_path)
        
        if cfg.has_section('database'):
            if cfg.has_option('database', 'engine'):
                db_engine = getattr(DB_ENGINE, cfg.get('database', 'engine'))
            
            if cfg.has_option('database', 'host'):
                db_host = cfg.get('database', 'host')
            
            if cfg.has_option('database', 'schema'):
                db_name = cfg.get('database', 'schema')
            
            if cfg.has_option('database', 'user'):
                db_user = cfg.get('database', 'user')
            
            if cfg.has_option('database', 'password'):
                db_password = cfg.get('database', 'password')
            
            if cfg.has_option('importing', 'mode'):
                batch_mode = cfg.get('importing', 'mode')
                
                if batch_mode.lower() in ('batch', 'auto'):
                    batch_mode = True
            
            if cfg.has_option('importing', 'comment'):
                module_comment = cfg.get('importing', 'comment')
            
            if cfg.has_option('importing', 'process_sections'):
                process_sections = cfg.get('importing', 'process_sections')
                
                if process_sections.lower() in ('no', 'false'):
                    process_sections = False
                else:
                    process_sections = True
                
    
    if None in (db_engine, db_host, db_name, db_user, db_password):
    
        (db_engine, db_host, 
        db_name, db_user, 
        db_password) = query_configuration()    
        
        if None in (db_engine, db_host, db_name, db_user, db_password):
            log_message('User cancelled the exporting.')
            return
            
    failed = False
    try:
        sqlexporter = SQLExporter(arch, db_engine, db=db_name,
                user=db_user, passwd=db_password, host=db_host, use_new_schema=USE_NEW_SCHEMA)
    except ImportError:
        print "Error connecting to the database, error importing required module: %s" % sys.exc_info()[0]
        failed = True
    except Exception:
        print "Error connecting to the database, Reason: %s" % sys.exc_info()[0]
        failed = True

    if failed:
        # Can't connect to the database, indicate that to BinNavi
        if batch_mode is True:
            idc.Exit(FATAL_CANNOT_CONNECT_TO_DATABASE)
        else:
            return
    
    if not sqlexporter.is_database_ready():
        
        if batch_mode is False:
            result = idc.AskYN(1, 'Database has not been initialized yet. Do you want to create now the basic tables? (This step is performed only once)')
        else:
            result = 1
            
        if result == 1:
            sqlexporter.init_database()
        else:
            log_message('User requested abort.')
            return
    
    iteration = os.environ.get('EXPORT_ITERATION', None)
    module_id = os.environ.get('MODULE_ID', None)
        
    if iteration is None and module_id == None:
        # Export manually
        print "Exporting manually ..."
        iteration = -1
        sqlexporter.set_callgraph_only(False)
        sqlexporter.set_exporting_manually(True)
        status = sqlexporter.new_module(
            idc.GetInputFilePath(), arch.get_architecture_name(), idaapi.get_imagebase(), module_comment, batch_mode)
            
    elif iteration is not None and module_id is not None:
        
        # Export the next k functions or the call graph
        sqlexporter.set_exporting_manually(False)
        sqlexporter.set_callgraph_only(int(iteration) == -1)
        sqlexporter.set_module_id(int(module_id))
        status = True
        
    else:
        
        sqlexporter.set_exporting_manually(False)
        status = sqlexporter.new_module(
            idc.GetInputFilePath(), arch.get_architecture_name(), idaapi.get_imagebase(), module_comment, batch_mode)
        sqlexporter.set_callgraph_only(False)
        
    if status is False:
        log_message('Export aborted')
        return
    elif status is None:
        log_message('The database appears to contain data exported with different schemas, exporting not allowed.')
        if batch_mode:
            idc.Exit(FATAL_INVALID_SCHEMA_VERSION)
    
    instrumentation = Instrumentation()
    
    instrumentation.new_function_callable(sqlexporter.process_function)
    instrumentation.new_packet_callable(sqlexporter.process_packet)
    instrumentation.new_section_callable(sqlexporter.process_section)
    
    
    tm_start = time.time()
    
    already_imported = sqlexporter.db.get_already_imported()

    incomplete = process_binary(arch, process_sections, int(iteration), already_imported)
    
    sqlexporter.finish()
    
    log_message('Results: %d functions, %d instructions, %d basic blocks, %d address references' % (
        len(sqlexporter.exported_functions), len(sqlexporter.exported_instructions),
        sqlexporter.basic_blocks_next_id-1, sqlexporter.address_references_values_count ))
        
    log_message('Results: %d expression substitutions, %d operand expressions, %d operand tuples' % (
        sqlexporter.expression_substitutions_values_count, sqlexporter.operand_expressions_values_count,
        sqlexporter.operand_tuples___operands_values_count ) )
        
        
    log_message('Exporting completed in %s' % get_time_delta_string())
    
    # If running in batch mode, exit when done
    if batch_mode:
        if incomplete:
            shiftedModule = (sqlexporter.db.module_id << 0x10) | 0xFF
        
            idc.Exit(shiftedModule)
        elif not sqlexporter.callgraph_only:
            shiftedModule = (sqlexporter.db.module_id << 0x10) | 0xFE
    
            idc.Exit(shiftedModule)
        else:
            idc.Exit(0)
