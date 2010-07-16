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
import md5
import sha
import re
import idc
import idaapi
import idautils
import db_statements
import db_statements_v2
import tempfile
import cPickle
from common import *
import common
import arch.arch


NODE_TYPE_MNEMONIC_ID =         0
NODE_TYPE_SYMBOL_ID =           1
NODE_TYPE_IMMEDIATE_INT_ID =    2
NODE_TYPE_IMMEDIATE_FLOAT_ID =  3
NODE_TYPE_OPERATOR_ID =         4
NODE_TYPE_REGISTER_ID =         5
NODE_TYPE_SIZE_PREFIX_ID =      6
NODE_TYPE_DEREFERENCE_ID =      7


NODE_TYPE_VALUE                 = '#'
NODE_TYPE_SYMBOL                = '$'
NODE_TYPE_REGISTER              = 'r'
NODE_TYPE_SIZE_PREFIX           = 'S'
NODE_TYPE_DEREFERENCE           = '['


LEAFS = (NODE_TYPE_SYMBOL, NODE_TYPE_VALUE, NODE_TYPE_REGISTER)



def get_idb_data_for_hash():
    """Return joined data from the segments in the IDB.
    
    The segments will be cut down to a maximum of 1MiB in order
    to avoid getting caught up reading too large segments. The
    data will be used to generate a unique hash for the IDB, so it's
    not critical to get all the data.
    """
    
    section_data = list()
    
    for seg_ea in idautils.Segments():
    
        seg_end = idc.SegEnd(seg_ea)
        
        # For each of the sections, get a maximum of a megabyte of each.
        # Some section could be way too large and we don't wanna hang
        # forever. This data will be used to generate a, hopefully, unique
        # hash for the IDB
        #
        for addr in range(seg_ea, min(seg_end, seg_ea + 2**20)):
            if idaapi.isLoaded(addr):
                section_data.append( chr(idc.Byte(addr)) )
            else:
                # If there's undefined data in the middle
                # of a section, nothing after that point
                # is exported
                break
                
    return ''.join(section_data)



class DummyCursor:
    def __init__(self):
        
        path, filename = os.path.split(idc.GetIdbPath())
        
        # If the path does not exists (moved IDB) the export
        # is created in IDA's base directory
        if not os.path.exists(path):
            path = idaapi.idadir('')
        filename, ext = os.path.splitext(filename)
        
        dump_filename = os.path.join(path, '%s.sql' % filename)
        
        self.dump_f = file(dump_filename, 'wt')
    
    def execute(self, stmt):
        self.dump_f.write(stmt)
        self.dump_f.write(';\n')
        
    def close(self):
        self.dump_f.close()
        self.dump_f = None
    


class DummyConnection:
    def commit(self):
        pass
    def close(self):
        pass
        
    
"""The executemany method was lifted straight from the 
MySQLdb/python-mysql project fitted with checks for maximum
query length.

http://mysql-python.svn.sourceforge.net/viewvc/mysql-python/trunk/MySQLdb/MySQLdb/cursors.py?revision=530&view=markup
"""

import re
INSERT_VALUES = re.compile(
   r"^(.+\svalues\s*)(\(((?<!\\)'.*?\).*(?<!\\)?'|.)+?\))(.*)$",
   re.IGNORECASE)

def executemany(self, query, args, 

    #### START OF MODIFIED CODE ####
    maximum_query_byte_length = 2**20
    ####  END OF MODIFIED CODE  ####
    
    ):
    """Execute a multi-row query.
    
    query
    
        string, query to execute on server
    
    args
    
        Sequence of sequences or mappings, parameters to use with
        query.
    
    Returns long integer rows affected, if any.
    
    This method improves performance on multiple-row INSERT and
    REPLACE. Otherwise it is equivalent to looping over args with
    execute().
    
    """
    del self.messages[:]
    db = self._get_db()
    if not args:
        return
    charset = self.connection.character_set_name()
    if isinstance(query, unicode):
        query = query.encode(charset)
    matched = INSERT_VALUES.match(query)
    if not matched:
        self.rowcount = sum([ self.execute(query, arg) for arg in args ])
        return self.rowcount
    
    start = matched.group( 1 ) #'start')
    end = matched.group( 4 ) #'end')
    values = matched.group( 2 ) #'values')
    
    try:
        sql_params = [ values % self.connection.literal(arg) for arg in args ]
    except TypeError, msg:
        if msg.args[0] in ("not enough arguments for format string",
                           "not all arguments converted"):
            self.messages.append((self.ProgrammingError, msg.args[0]))
            self.errorhandler(self, self.ProgrammingError, msg.args[0])
        else:
            self.messages.append((TypeError, msg))
            self.errorhandler(self, TypeError, msg)
    except:
        from sys import exc_info
        exc, value, traceback = exc_info()
        del traceback
        self.errorhandler(self, exc, value)
        
    base_length = ( 
        2 + # two newlines
        len(start) + len(end) )
        
    last_idx = 0
    self.rowcount = 0
    total_length = base_length
    for idx, sql_param in enumerate(sql_params):
        
        # Add the current parameters' length
        #
        total_length += len(sql_param) + 2 # length(',\n')
        
        # If the total string length goes over the limit
        # push the stuff to the database and record the position
        #
        if total_length >= maximum_query_byte_length:
            
            query_str = '\n'.join([start, ',\n'.join(sql_params[last_idx:idx]), end, ])
            
            #print 'Query went over the size limit, throwing %d bytes of query into the database.' % len(query_str)
            
            self.rowcount += int(self._query( query_str ))
            last_idx = idx
            total_length = base_length + len(sql_params[idx]) + 2 # length(',\n')
            
    if last_idx < len( sql_params ):
        
        query_str = '\n'.join([start, ',\n'.join(sql_params[last_idx:]), end, ])
        
        self.rowcount += int(self._query( query_str ))
        
    # Some versions of the Python MySQL module seem not to have the _defer_warnings attribute set
    try:
        if not self._defer_warnings:
            self._warning_check()
    except AttributeError:
        
        self._warning_check()
        
    return self.rowcount




class DBWrap:
    
    def __init__(self, dbengine, **kwargs):
        
        use_new_schema = kwargs.get('use_new_schema', None)
        if use_new_schema is not None:
            del kwargs['use_new_schema']
        if use_new_schema is True:
            self.schema = db_statements_v2
        else:
            self.schema = db_statements
            
        # This indicates whether the DB to use is
        # MySQL, PostgreSQL or others
        self.db = dbengine
        
        # We need to declare this attribute here otherwise
        # if there's a problem connecting the __del__ will
        # not find it an fail
        #
        self.db_con = None 
        
        # The current module being processed
        self.module_id = None
        
        # Module of the SQL engine in use
        self.sql_engine = None
        
        if self.db == DB_ENGINE.SQLITE:
            import pysqlite2.dbapi2 as sqlite
            self.sql_engine = sqlite
            self.db_con = sqlite.connect(**kwargs)
            self.cursor = self.db_con.cursor()
        
        elif self.db == DB_ENGINE.MYSQL:
            import MySQLdb
            self.sql_engine = MySQLdb
            print "Connecting to the database"
            self.db_con = MySQLdb.connect(**kwargs)
            self.cursor = self.db_con.cursor()
            
            # Overwrite the default's execute many with ours
            #
            self.cursor.executemany = executemany
        
        elif self.db == DB_ENGINE.POSTGRESQL:
            import pgdb
            self.sql_engine = pgdb
            self.db_con = pgdb.connect(
                user=kwargs['user'], password=kwargs['passwd'],
                host=kwargs['host'], database=kwargs['db'])
            self.cursor = self.db_con.cursor()
        
        elif self.db == DB_ENGINE.MYSQLDUMP:
            self.db_con = DummyConnection()
            self.cursor = DummyCursor()
            self.last_ids = dict()
            self.module_id = 1
            
        self.COLSEP = ', '
        
    
    
    def close(self):
        self.cursor.close()
        
    
    def verify_database_version(self):
        
        # If there are not tables yet created then
        # there's no version to check and it's all good
        #
        if not self.is_database_ready():
            return True
        
        # Make sure that there's only one version number for the
        # database schema in the modules table
        #
        stmt = 'SELECT MAX( version ) - MIN( version ) FROM modules'
        
        self.cursor.execute(stmt)
        rows = self.cursor.fetchall()
        if not rows:
            # We should never arrive here. If there is a modules
            # table we should get a row as a result
            # If there are not rows it must indicate some problem
            # with the database
            #
            return None
            
        # The result of the statement should be 0 indicating all
        # entries have the same version number
        #
        # It can be none if the database is empty
        #
        if rows[0][0] != 0 and rows[0][0] is not None:
            return False
        
        # Now that the database is verified to be homogeneous, check
        # that the current version of the exporter 
        # db_statements.MYSQL_SCHEMA_VERSION
        # matches the one in the database
        #
        stmt = 'SELECT version FROM modules LIMIT 1'
        
        self.cursor.execute(stmt)
        rows = self.cursor.fetchall()
        if not rows:
            return True
        if rows[0][0] == self.schema.MYSQL_SCHEMA_VERSION:
            return True
            
        return False
    
    
    def set_module_id(self, module_id):
        self.module_id = module_id
    
    def new_module(self, name, architecture, base_address, module_comment, batch_mode):
        
        if self.verify_database_version() is not True:
            return None
        
        if not os.path.exists(name):
        
            # If in "batch mode" don't ask the user to pick
            # any file
            #
            if not batch_mode:
                name = idc.AskFile(1, '*.*',
                    'Input file not found, please locate it')
            if name is None:
                print 'Input file not found'
                return False
        
        data = get_idb_data_for_hash()
        
        print 'Calculating hashes of %d bytes of data.' % len(data)
        
        # Try to get IDA's hash of the original file
        # (this is only available in recent versions of IDA, hance the check
        # for the method)
        #
        md5_hash = None
        if hasattr(idautils, 'GetInputFileMD5'):
            md5_hash = idautils.GetInputFileMD5()
         
        # If the method didn't exist or if it returned None (can happen if the
        # IDB does not contain an MD5) calculate it over the data.
        #   
        if md5_hash is None:
            md5_hash = md5.new(data).hexdigest()
        sha_hash = sha.new(data).hexdigest()
        
        if self.db in (DB_ENGINE.MYSQL, DB_ENGINE.MYSQLDUMP, DB_ENGINE.POSTGRESQL):
            cols = ('name', 'architecture', 'base_address', 'md5', 'sha1', 'comment', 'exporter', 'version')
            values = [ os.path.basename(name), architecture,
                base_address, md5_hash, sha_hash, module_comment,
                'Zynamics GmbH ida2sql IDA Exporter (%s)' % common.__version__,
                self.schema.MYSQL_SCHEMA_VERSION ]
            
            # if dumping the module can't already be in the database
            # hence the following test is not needed
            #                
            if self.db not in (DB_ENGINE.MYSQLDUMP,):
                id = self.select_id('modules', cols, values)
                if id is not None:
                    print "Module already in database. Storing with a different name"
                    
                    # Check if the name already ends with a number in parenthesis (X)
                    parse_count = re.compile('(.*) \((\d+)\)$')
                    
                    name = values[0]
                    
                    
                    for tries in xrange(10000):
                        res = parse_count.match( name )

                        # If the name ends with a number in parenthesis (X), get it. Otherwise start from 2...
                        if res is not None:
                            count = int(res.group(2))
                            # And assign a new name
                            name = '%s (%d)' % (res.group(1), count + 1)
                        else:
                            count = 1
                            name = '%s (%d)' % (name, count + 1)
                        
                        values[0] = name
                        id = self.select_id('modules', cols, values)
                        if id is None:
                            break
                    
                    if id is not None:
                        print "Module already in database and attempt to store it with a different name failed"
                        if batch_mode == True:
                            idc.Exit(FATAL_MODULE_ALREADY_IN_DATABASE)
                        return False
                
            self.module_id = self.insert_get_last_id('modules', cols, values)
            self.create_schema(self.module_id)
            
        
        return True
        
    
    def is_database_ready(self):
        """Check if the database has all the required tables.
        
        If the database does not contain the basic tables needed
        this will indicate so.
        """
        
        # If the output is a dump there's no database to be 'ready'
        # but 'init_database' is called to issue the statemets setting
        # up all needed tables. True is returned so the user is not
        # prompted whether he want's to initialize the dabase.
        #
        if self.db == DB_ENGINE.MYSQLDUMP:
            return True
            
        elif self.db == DB_ENGINE.MYSQL:
            self.cursor.execute('show tables;')
            
        elif self.db == DB_ENGINE.POSTGRESQL:
            self.cursor.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_name LIKE 'modules'")
        
        rows = self.cursor.fetchall()
        
        table_names = [rows[idx][0] for idx in range(len(rows))]
        if 'modules' in table_names:
            return True
        
        return False
        
    
    def init_database(self):
        """Create the basic table set in a database."""
        
        if self.db in (DB_ENGINE.MYSQL, DB_ENGINE.MYSQLDUMP):
            schema = self.schema.mysql_new_db_statements
        
        elif self.db == DB_ENGINE.POSTGRESQL:
            schema = self.schema.postgresql_new_db_statements
        
        elif self.db == DB_ENGINE.SQLITE:
            raise Exception('Schema for SQLite not present. (SQLite is not currenly supported)')
        
        # Create tables
        for stmt in schema.split(';'):
            stmt = stmt.strip()
            if stmt:
                self.cursor.execute(stmt)
        
        self.db_con.commit()
        
    
    def create_schema(self, module_id):
        """Create the tables needed for the new module."""
        
        if self.db in (DB_ENGINE.MYSQL, DB_ENGINE.MYSQLDUMP):
            schema = self.schema.mysql_new_module_statements
        
        elif self.db == DB_ENGINE.POSTGRESQL:
            schema = self.schema.postgresql_new_module_statements
        
        # Prepare tables for current module
        parse = re.compile('\{MODULE_ID\}')
        schema = parse.sub('%d' % module_id, schema)
        
        # Create tables
        for stmt in schema.split(';'):
            stmt = stmt.strip()
            if stmt:
                self.cursor.execute(stmt)
        
        self.db_con.commit()
        
    
    def get_already_imported(self):
        stmt = 'SELECT address FROM ex_%d_functions' % self.module_id
        
        self.cursor.execute(stmt)
        
        rows = self.cursor.fetchall()
        
        addresses = [rows[idx][0] for idx in range(len(rows))]

        return set(addresses)
        
    def insert_get_last_id(self, *args):
        
        self.insert(*args)
        id = self.select_last_id(args[0])
        
        if self.db == DB_ENGINE.MYSQLDUMP:
            return id
        
        if id==0:
            return int(self.select_id(*args))
        
        return int(id)
        
    
    def escape_string(self, s):
        """Escape a string to be included in a statement.
        
        This method is only to be used in dumping mode. DB engines
        should provide with escaping themselves.
        """
        
        escaped = str(s).replace("\\","\\\\")
        escaped = escaped.replace("'","''")
        escaped = escaped.replace("\0", "\\0")
        
        return "%s" % escaped
    
    def exec_query(self, query_string):
        
        try:
            self.cursor.execute(query_string)
        except self.sql_engine.IntegrityError, error:
            # Raise an exception if the duplicate entry error ER_DUP_ENTRY
            # is raised
            #
            if error[0] == 1062:
                raise
        except Exception, e:
            #dbg_message('ERROR EXECUTING STATEMENT: %s' % str(args))
            dbg_message('Error Executing Statement')
            dbg_message(str(e))
            dbg_message(query_string)

    
    def insert(self, table, columns, values):
        
        if self.db == DB_ENGINE.SQLITE:
            stmt = (
                ('INSERT IGNORE INTO %s(' % table) +
                self.COLSEP.join(columns) + ') ' +
                'values('+ self.COLSEP.join(['?']*len(columns)) + ')' )
            args = [stmt, values]
        
        elif self.db == DB_ENGINE.MYSQL:
            stmt = (
                ('INSERT INTO %s(' % table) +
                self.COLSEP.join(columns) + ') ' +
                'values('+ self.COLSEP.join(['%s']*len(columns)) + ')' )
            args = [stmt, values]
        
        elif self.db == DB_ENGINE.POSTGRESQL:
            
            vals = []
            for value in values:
                if isinstance(value, str):
                    vals.append(self.sql_engine.escape_bytea(value))
                else:
                    vals.append(value)
            values = vals
            
            stmt = (
                ('INSERT INTO %s(' % table) +
                self.COLSEP.join(columns) + ') ' +
                'values('+ self.COLSEP.join(['%s']*len(columns)) + ')' )
            args = [stmt, values]
            
        elif self.db == DB_ENGINE.MYSQLDUMP:
            escaped_values = list()
            for val in values:
                if isinstance(val, int) or isinstance(val, long):
                    escaped_values.append(str(val))
                elif val is None:
                    escaped_values.append('null')
                else:
                    escaped_values.append("'%s'" % self.escape_string(val))
            
            stmt = (
                ('INSERT INTO %s(' % table) +
                self.COLSEP.join(columns) + ') ' +
                'values('+ self.COLSEP.join(escaped_values) + ')' )
            
            args = [stmt]
        
        try:
            self.cursor.execute(*args)
        except self.sql_engine.IntegrityError, error:
            # Raise an exception if the duplicate entry error ER_DUP_ENTRY
            # is raised
            #
            if error[0] == 1062:
                raise
        except Exception, e:
            dbg_message('Error Executing Statement')
            dbg_message('Table: %s' % str(table))
            dbg_message('Column: values')
            for col, val in zip(columns, values):
                if isinstance(val, (str, unicode, list, tuple, set)):
                     
                    if len(val)>10:
                        val = repr(val[:10])+'...'
                    else:
                        val = repr(val)
                        
                print col,": ", val
            dbg_message(str(e))
            #raise Exception('Terminated')
            
    
    def select_last_id(self, table_name=None):
        
        if self.db == DB_ENGINE.MYSQLDUMP and table_name is not None:
            
            last_id = self.last_ids.get(table_name, 0)+1
            self.last_ids[table_name] = last_id
            
            return last_id
        
        if self.db == DB_ENGINE.MYSQL:
            stmt = 'SELECT LAST_INSERT_ID()'
            
            self.cursor.execute(stmt)
        
        elif self.db == DB_ENGINE.POSTGRESQL:
            stmt = "SELECT CURRVAL('%s_id_seq')" % table_name
            
            try:
                self.cursor.execute(stmt)
            except self.sql_engine.DatabaseError, dberr:
                # The sequence does not yet exist, i.e. it's a
                # fresh database
                
                return 1
        
        rows = self.cursor.fetchall()
        
        return rows[0][0]
        
    
    def select_id(self, table, columns, values):
        
        if self.db == DB_ENGINE.SQLITE:
            pass
        
        elif self.db in (DB_ENGINE.MYSQL, DB_ENGINE.POSTGRESQL):
            stmt = ('SELECT id FROM %s WHERE ' % (table)) + \
                ' and '.join(['%s=%%s' % col for col in columns])
        
        self.cursor.execute(stmt, values)
        rows = self.cursor.fetchall()
        
        # If an empty result set is returned, return None
        #
        if not rows:
            return None
        
        
        return rows[0][0]
        
    
    def get_module_id(self):
        return self.module_id
        
    
    def commit(self):
        
        self.db_con.commit()
        
    
    def __del__(self):
        
        # Only commit and close if there's an open connection
        #
        if self.db_con is not None:
            self.db_con.commit()
            self.db_con.close()
    

class SQLExporter:
    
    
    def __init__(self, arch, dbengine, use_new_schema=True, **db_args):
        
        self.arch = arch
        self.use_new_schema = use_new_schema
        
        # Keep track of function names, we don't want any repetitions
        # 
        self.function_names = set()
        
        self.exported_instructions = set()
        self.exported_functions = set()
        self.functions = list()
        self.basic_blocks = list()
        
        self.control_flow_graph = list()
        
        # Next basic block ID to be assigned
        self.block_ids = dict()
        
        
        # Global dictionary containing information about the expressions, operands and values
        # and the address in which they occur in order to fill appropriately the
        # address_refenreces table
        #
        self.address_references_information = dict()
        
        # This dictionary will keep additional information to the 'trace' argument used by 'compose_operand_tree()'
        #
        self.trace_information_store = dict()
        
        # The keys in this dictionary will be the columns and the values the
        # list of rows to insert for each column set
        self.expression_row_data = dict()
        self.expression_row_data_ids = dict()
        
        
        # Data storage for batch inserts
        #
        
        self.operand_strings__expression_trees_tmp_file = tempfile.TemporaryFile()
        
        self.instructions_values_tmp_file = tempfile.TemporaryFile()
        self.operand_tuples___operands_values_count = 0
        self.operand_tuples___operands_values_tmp_file = tempfile.TemporaryFile()

        self.address_references_values = set()
        self.address_references_values_count = 0
        self.address_comments_values = list()
        
        # We don't want repeated entries here hence the set()'s
        #
        self.expression_substitutions_values = set()
        self.expression_substitutions_values_count = 0
        
        self.operand_expressions_values_dict = dict()
        self.operand_expressions_values_count = 0
        
        self.last_packet = None
        self.operand_tree = ['root']
        
        self.db = DBWrap(dbengine, use_new_schema=self.use_new_schema, **db_args)
        
        # calltree_information will contain calltree edges which have
        # to be inserted after all function have as there's a constraint
        # on the calltree table, making the address refer to the functions
        # table
        
        # List of (source function, source basic block id, destination address, source address) 
        #
        self.calltree_information = list()
        
    
    def is_database_ready(self):
        return self.db.is_database_ready()
        
    
    def init_database(self):
        return self.db.init_database()
        
    def set_module_id(self, module_id):
        self.db.set_module_id(module_id)
        
        if self.callgraph_only:
            self.basic_blocks_next_id = 1
        else:
            stmt = 'SELECT MAX(basic_block_id) FROM ex_%d_instructions' % module_id
            
            self.db.cursor.execute(stmt)
            
            rows = self.db.cursor.fetchall()
            
            self.basic_blocks_next_id = 1 + rows[0][0]
            
        if self.use_new_schema is True:
            stmt = 'SELECT MAX(id) FROM ex_%d_expression_nodes' % module_id
        else:
            stmt = 'SELECT MAX(id) FROM ex_%d_expression_tree' % module_id
        self.db.cursor.execute(stmt)
        
        rows = self.db.cursor.fetchall()
        
        self.expression_current_id = rows[0][0]
        
        if self.use_new_schema is True:
            stmt = 'SELECT MAX(id) FROM ex_%d_expression_trees' % module_id
        else:
            stmt = 'SELECT MAX(id) FROM ex_%d_operand_strings' % module_id
        self.db.cursor.execute(stmt)
        
        rows = self.db.cursor.fetchall()
        
        self.operand_strings__expression_trees_id = rows[0][0]

    
    def new_module(self, path, architecture, base_address, module_comment, batch_mode):
        
        # We want to pass back the exact return value
        #
        status = self.db.new_module(path, architecture, base_address, module_comment, batch_mode)
        if not status:
            return status
        
        # The following has been added by request from Soeren:
        #
        # It's a dummy entry for the callgraph as a function - I need it so my
        # foreign key constraints won't fail. Callgraphs have address 0 by my
        # convention.

        self.basic_blocks_next_id = 1
        # Store expression data for mass insertion into the database
        self.expression_current_id = 0
        self.operand_strings__expression_trees_id = 0
        
        return True
    
    def process_packet(self, packet):
        self.last_packet = packet
        
    
    def process_instruction(self, packet, address):
        """Fetch an instruction at a given address from the data packet.
        
        Returns a tuple with information about the instruction and its
        operands.
        """
        
        mnemonic = packet.instructions[address][1]
        operands = packet.instructions[address][2]
        operand_trees = packet.instructions[address][3]
        data = packet.instructions[address][4]
        
        return mnemonic, operands, operand_trees, data
        
    
    def process_expression(self, node_type, value, parent_id, position=0):
        """Process expressions from an operand tree.
        
        The expression is inserted and the new ID returned.
        """
        
        expr_type = None
        if self.use_new_schema:
            expression_type_column_name = '`type`'
        else:
            expression_type_column_name = 'expr_type'
        
        if node_type == self.arch.NODE_TYPE_REGISTER:
            columns = ('id', 'parent_id', 'position', expression_type_column_name, 'symbol')
            expr_type = NODE_TYPE_REGISTER_ID
            
        elif node_type == self.arch.NODE_TYPE_DEREFERENCE:
            columns = ('id', 'parent_id', 'position', expression_type_column_name, 'symbol')
            expr_type = NODE_TYPE_DEREFERENCE_ID
            
        elif node_type in self.arch.OPERATORS:
            columns = ('id', 'parent_id', 'position', expression_type_column_name, 'symbol')
            expr_type = NODE_TYPE_OPERATOR_ID
            
        elif node_type in self.arch.WIDTH_OPERATORS:
            columns = ('id', 'parent_id', 'position', expression_type_column_name, 'symbol')
            expr_type = NODE_TYPE_SIZE_PREFIX_ID
            
        elif node_type == self.arch.NODE_TYPE_SYMBOL:
            columns = ('id', 'parent_id', 'position', expression_type_column_name, 'symbol')
            expr_type = NODE_TYPE_SYMBOL_ID
            
        elif node_type == self.arch.NODE_TYPE_VALUE:
            # There's never going to be a float/double as value, at
            # least on Intel
            #
            if isinstance(value, float):
                columns = ('id', 'parent_id', 'position', expression_type_column_name, 'symbol')
                expr_type = NODE_TYPE_IMMEDIATE_FLOAT_ID
                value = str(value)
            elif isinstance(value, long) or isinstance(value, int):
                columns = ('id', 'parent_id', 'position', expression_type_column_name, 'immediate')
                expr_type = NODE_TYPE_IMMEDIATE_INT_ID
        
        if expr_type is None:
            if isinstance(value, arch.arch.ExpressionNamedValue):
                
                return self.process_expression(
                    node_type, value.value, parent_id, position=position)
            else:
                dbg_message('Unknown type: %s value: %s (node_type: %s)' % (str(type(value)), str(value), str(node_type)))
                
                dbg_message('Operator list: %s' % (str(self.arch.OPERATORS)))
        
        # 'columns' has to be a tuple so it's hashable
        #
        if not self.expression_row_data.has_key(columns):
            self.expression_row_data[columns] = list()
            self.expression_row_data_ids[columns] = dict()
            
        
        # The basic information for an expression
        #
        entry = ( parent_id, position, expr_type, value )
        
        # Check if we have already seen an identical one
        #
        if not self.expression_row_data_ids[columns].has_key(entry):
            
            # Get a new ID and store the new expression infromation
            
            self.expression_current_id += 1
            
            return_id = self.expression_current_id
            
            self.expression_row_data[columns].append( (self.expression_current_id, ) + entry )
            self.expression_row_data_ids[columns][entry] = self.expression_current_id
        else:
            
            # get the ID for the already-seen expression
            #
            return_id = self.expression_row_data_ids[columns][entry]
        
        return return_id
    
    def operand_tree_assimilate(
        self,
        tree, parent_id=None,
        trace=None, op_idx=None, expr_subst=None):
        
        """Walk the tree and return it with the IDs corresponding to each expression.
        
        This method is called when the tree needs to be inserted in the database.
        """
        
        tree_copy = [ [tree[0], None] ]
        
        if tree[0] in LEAFS:
            
            id = self.process_expression(tree[0], tree[1], parent_id, position=tree[-1])
            
            tree_copy.append( { tree[1] : id} )
            
            # The ExpressionNamedValue objects is used whenever
            # a value has a name, like in the case of a stack
            # variable.
            # If so, the value and name are stored in the object
            # and the object is stored in the tree. Otherwise, 
            # just the value is in the tree.
            #
            if isinstance(tree[1], arch.arch.ExpressionNamedValue):
                
                expr_name = tree[1].name
                value = tree[1].value
                
                if expr_name is not None:
                    expr_subst[(op_idx, id)] = expr_name
            
            else:
                value = tree[1]
                expr_name = None
            
            #process_expression_substitution
            trace.append( id )
            if not self.trace_information_store.has_key( id ) and value is not None:
                self.trace_information_store[ id ] = value
            
        else:
            
            # Check whether a position within the expression has been specified for this tree
            # and if so, fetch it and revome it from the list for easier subsequent processing
            #
            position = 0
            if isinstance( tree[-1], (int, long) ):
                position = tree[-1]
                tree = tree[:-1]
                
            id = self.process_expression(tree[0], tree[0], parent_id, position = position)
            tree_copy.extend(
                [self.operand_tree_assimilate(
                    subtree, id, trace, op_idx, expr_subst) for
                        subtree in tree[1:]])
            
            
            tree_copy[0][1] = id
        
        trace.append( id, )
        
        return tree_copy
        
    
    def compose_operand_tree(
        self, address, op_idx, tree,
        operand_tree = None, trace=None,
        parent_id=None, expr_subst=None):
        
        if operand_tree is None:
            operand_tree = self.operand_tree
        
        found = False
        
        for sup_root in operand_tree:
            
            if sup_root[0][0] not in LEAFS and tree[0] not in LEAFS:
                
                if sup_root[0][0]==tree[0]:
                
                    for root in tree[1:]:
                        
                        # Check whether a position has been specified for this expression part
                        # and if so skip it. This loop handles only expression parts
                        #                        
                        if isinstance(root, (int, long)):
                            continue
                        
                        sup_root[1:] = self.compose_operand_tree(address,
                            op_idx, root, sup_root[1:],
                            trace, sup_root[0][1],
                            expr_subst=expr_subst)
                            
                    trace.append( sup_root[0][1] )
                    
                    found = True
                    break
                    
            elif sup_root[0][0] in LEAFS and tree[0] in LEAFS:
                
                value = None
                
                if sup_root[0][0] == tree[0]:
                    
                    if not sup_root[1].has_key(tree[1]):
                        
                        # The ExpressionNamedValue objects is used whenever
                        # a value has a name, like in the case of a stack
                        # variable.
                        # If so, the value and name are stored in the object
                        # and the object is stored in the tree. Otherwise, 
                        # just the value is in the tree.
                        #
                        if isinstance(tree[1], arch.arch.ExpressionNamedValue):
                            value = tree[1].value
                            expr_name = tree[1].name
                        else:
                            value = tree[1]
                            expr_name = None
                            
                        id = self.process_expression(
                            tree[0], value, parent_id, position=tree[-1] ) #position)
                        #position += 1
                        sup_root[1][tree[1]] = id
                            
                        # If there is an expression name we add it
                        # to a list of expressions to process.
                        #
                        if expr_name is not None:
                            expr_subst[(op_idx, id)] = expr_name
                            
                        #process_expression_substitution
                        trace.append( sup_root[1][tree[1]] )
                        if not self.trace_information_store.has_key( sup_root[1][tree[1]] ) and value is not None:
                            self.trace_information_store[ sup_root[1][tree[1]] ] = value
                        
                    found = True
                    break
                    
            
        # We need to assimilate the tree so the corresponding tree is
        # generated and returned. The calling function will accept 'trace'
        # to be filled with the tree data for the corresponding operand and
        # that happens in this next call
        #
        assimilated = self.operand_tree_assimilate(tree, parent_id,
            trace, op_idx, expr_subst)
            
        # We only need to add it to the main operand tree though, if it
        # has not been found there already
        #
        if not found:


            # Append a copy of the tree, this is needed otherwise
            # references to deeper parts of the tree will be shared
            # with single operand expression trees and that gives
            # bad karma
            
            operand_tree.append(assimilated)
        
        return operand_tree
        
    
    def process_basic_block(self, function, packet, block):
        
        instruction_addresses = function.instructions_in_range(*block)
        
        instructions = list()
        
        for address in instruction_addresses:
            
            instruction_info = self.process_instruction(packet, address)
            
            instructions.append(instruction_info)
            
        
        # Turn the call (src, dst) tuples into a dict for faster
        # lookup
        calls_info = dict(function.calls)
        
        # The calltree information is processed here, regardless of whether this basic
        # block is included in multiple functions. Precisely for that reason we want it
        # processed here, as we want callgraph connectivity information for every function
        # where this basic block is included
        # Immediately after this comes a check that will return if the basic block has
        # already been processed, as we don't want the repeated instructions.
        #
        for address in instruction_addresses:
            
            # Linking information for the instruction
            if calls_info.has_key(address):
                self.calltree_information.append(
                    (function.start,
                        (function.start, block[0], block[1]),
                        calls_info[address], address) )
            
        self.basic_blocks.append( (
            self.basic_blocks_next_id, block[0], function.start) )
            
        basic_block_id = self.basic_blocks_next_id
        
        self.basic_blocks_next_id += 1
        
        if not self.callgraph_only:
            for idx, address, info in zip(
                range(len(instructions)), instruction_addresses, instructions):
                
                if not self.callgraph_only:
                    mnemonic, data = info[0], info[3]
                    operands, operand_trees = info[1], info[2]
            
                    cPickle.dump( (address, mnemonic, basic_block_id, idx, data), self.instructions_values_tmp_file )
            
                # If the basic block is included from more than one function
                # the instructions can't be added again. Therefore they
                # are skipped.
                if not address in self.exported_instructions:
                    
                    self.exported_instructions.add(address)
                
                    operand_cols = ['op%d' % (i+1) for i in range(len(operands))]
                
                    operand_ids = [ self.add_operand_string(op_str)
                        for op_str in operands ]
                
                    # create a list containing the lists to be filled with IDs
                    # represeting all expressions in the tree.
                    operand_expr_ids = [ list() for tree in operand_trees]
                
                    # Fill this with any information about expression substitutions.
                    expression_substitution = dict()
                
                    # fill the list
                    [self.compose_operand_tree(address,
                        i, operand_trees[i],
                        trace=operand_expr_ids[i],
                        expr_subst=expression_substitution) for
                            i in range(len(operand_trees))]
                
                    for i, operand_id in enumerate(operand_ids):
                        
                        for expr_id in operand_expr_ids[i]:
                        
                            expr = self.trace_information_store.get(expr_id, None)
                            if expr is not None:
                                # Store (operand index, operand ID, expression ID, expr) in a
                                # dictionary with the associated key "address"
                                # This information will be used to recover the corresponding operand ID
                                # and expression ID to a "address reference" to be filled later
                                #
                                info = self.address_references_information.get(address, None)
                                if info is None:
                                    info = set()
                                info.add( (i, operand_id, expr_id, expr) )
                                self.address_references_information[address] = info
                                
                            # Get and insert the expression name, if any
                            expr_name = expression_substitution.get(
                                (i, expr_id), None)
                            
                            if expr_name is not None:
                                if self.use_new_schema is True:
                                    # address, expression_tree_id, position
                                    self.expression_substitutions_values.add( (address, expr_id, i, expr_name) )
                                else:
                                    self.expression_substitutions_values.add( (address, operand_id, expr_id, expr_name) )
                            
                            if operand_id in self.operand_expressions_values_dict:
                                if expr_id not in self.operand_expressions_values_dict[ operand_id ]:
                                    self.operand_expressions_values_count += 1
                                    self.operand_expressions_values_dict[ operand_id ].append( expr_id )
                            else:
                                self.operand_expressions_values_dict[ operand_id ] = [ expr_id ]
                                self.operand_expressions_values_count += 1
                        
                        cPickle.dump( (address, operand_id, i), self.operand_tuples___operands_values_tmp_file )
                            
                        self.operand_tuples___operands_values_count += 1
        
        return basic_block_id
        
    
    def add_operand_string(self, op_str):
        
        self.operand_strings__expression_trees_id += 1
        
        if self.use_new_schema is True:
            cPickle.dump( (self.operand_strings__expression_trees_id,), self.operand_strings__expression_trees_tmp_file )
        else:
            cPickle.dump( (op_str, self.operand_strings__expression_trees_id), self.operand_strings__expression_trees_tmp_file )
        
        return self.operand_strings__expression_trees_id
        
    def process_section(self, section):
        
        self.db.insert('ex_%d_sections' % self.db.get_module_id(),
            ('name', 'base',  'start_address',  'end_address',
            'length', 'data'),
            (section.name, section.base, section.start, section.end,
            len(section.data), section.data) )
            
    
    def process_function(self, function):
        
        function_name = function.name
        
        if function_name is None:
           function_name = 'sub_%x' % function.start
           
        count = 1
        while function_name in self.function_names:
            function_name = function.name+(' (%d)' % count)
            count += 1
            
        self.function_names.add(function_name)
        self.exported_functions.add(function.start)
            
        real_name = True
        if function_name.startswith('sub_'):
            real_name = False
        
        if not self.callgraph_only:
            self.functions.append( (function.start, function_name, function.module, function.kind, real_name) )
        
        # Create an empty dictionary to store the
        # local mapping of address to basic block ID
        # for this function
        #
        destination_blocks_ids = dict()
        
        for idx, block in enumerate(function.blocks):
            
            basic_block_id = self.process_basic_block(
                function, self.last_packet, block)
            
            self.block_ids[
                (function.start, block[0], block[1])] = basic_block_id
                
            destination_blocks_ids[block[0]] = basic_block_id
            
        
        for branch in function.branches:
            # First element of the branch is the source of a jump,
            # that is, the end address of a basic block.
            # Therefore the block's inital address is fetched
            block = function.get_block_by_address(branch[0])
            if not block:
                continue
            src_block = self.block_ids[
                (function.start, block[0], block[1])]
            
            
            # The target of the branch already is a start address of
            # block, nothing to do.
            dst_block = destination_blocks_ids[branch[1]]
            
            if not function.branch_kinds.has_key(branch):
                # TODO: Invalid reference, invalid code in the database
                dbg_message('Branch kind not found, probably invalid code in the database at address(es): 0x%x, 0x%x' % branch)
            else:
                if not self.callgraph_only:
                    self.control_flow_graph.append( (function.start, src_block, dst_block,
                        function.branch_kinds[branch]) )
            
        
        for addr_ref in self.last_packet.address_references:
            
            info = self.address_references_information.get(addr_ref[0], None)
            operand_id, expression_id, position = None, None, 0
            all_operand_ids = set()

            if info:
                # Go through the info for each operand
                # contents: (operand index, operand ID, expression ID, value)
                #
                for itm in info:
                    # If the operand's value equals the target address, then use
                    # the operand and expression IDs that we stored
                    #
                    all_operand_ids.add( itm[1] )
                    
                    if isinstance(itm[3], (int, long)) and itm[3] == addr_ref[1]:
                        operand_id = itm[1]
                        expression_id = itm[2]
                        position = itm[0]
                        
                # If nothing was found
                if operand_id is None and expression_id is None:
                    # But there's only one operand, assign the reference to that operand
                    if len(all_operand_ids) == 1:
                        operand_id, expression_id = list(info)[0][1:3]
                        position = 0
                        
            if self.use_new_schema is True:
                values = (addr_ref[0], addr_ref[1], addr_ref[2], expression_id, position)
            else:
                values = (addr_ref[0], addr_ref[1], addr_ref[2], operand_id, expression_id)
            
            self.address_references_values.add( values )
        
        if not self.callgraph_only:
            self.address_comments_values.extend( list(self.last_packet.comments) )
        
    
    def set_callgraph_only(self, callgraph_only):
        self.callgraph_only = callgraph_only
    
    def set_exporting_manually(self, exporting_manually):
        self.exporting_manually = exporting_manually
        
    def finish(self):
        
        if not self.callgraph_only or self.exporting_manually:
            # Inserting the expressions left to insert
            #
            for cols, vals in self.expression_row_data.items():
                
                if self.use_new_schema is True:
                    self.db.cursor.executemany( self.db.cursor,
                        ('INSERT IGNORE INTO ex_%d_expression_nodes(%s) ' % (
                        self.db.get_module_id(), ','.join(cols)) ) + 
                            ('VALUES(%s)' % ','.join( ['%s']*len(vals[0]) )),
                        vals )
                else:
                    self.db.cursor.executemany( self.db.cursor,
                        ('INSERT IGNORE INTO ex_%d_expression_tree(%s) ' % (
                        self.db.get_module_id(), ','.join(cols)) ) + 
                            ('VALUES(%s)' % ','.join( ['%s']*len(vals[0]) )),
                        vals )
                self.db.commit()

                    
            # Huge performance gains
            self.db.cursor.execute('set unique_checks=0')
            self.db.cursor.execute('set foreign_key_checks=0')
        
            if self.use_new_schema is True:
                self.db.cursor.executemany( self.db.cursor,
                    ('INSERT IGNORE INTO ex_%d_functions(address, name, module_name, `type`,  has_real_name) ' %
                    self.db.get_module_id() ) + 'VALUES(%s, %s, %s, %s, %s)', self.functions )
            else:
                self.db.cursor.executemany( self.db.cursor,
                    ('INSERT IGNORE INTO ex_%d_functions(address, name, module_name, function_type,  real_name) ' %
                    self.db.get_module_id() ) + 'VALUES(%s, %s, %s, %s, %s)', self.functions )
            self.db.commit()
            del self.functions
        
            self.db.cursor.executemany( self.db.cursor,
                ('INSERT IGNORE INTO ex_%d_basic_blocks(id, address, parent_function) ' %
                self.db.get_module_id() ) + 'VALUES(%s, %s, %s)', self.basic_blocks )
            self.db.commit()
            del self.basic_blocks
        
            if self.use_new_schema is True:
                self.db.cursor.executemany( self.db.cursor,
                    ('INSERT IGNORE INTO ex_%d_control_flow_graphs(parent_function, source, destination, `type`) ' %
                    self.db.get_module_id() ) + 'VALUES(%s, %s, %s, %s)', self.control_flow_graph )
            else:
                self.db.cursor.executemany( self.db.cursor,
                    ('INSERT IGNORE INTO ex_%d_control_flow_graph(parent_function, src, dst, kind) ' %
                    self.db.get_module_id() ) + 'VALUES(%s, %s, %s, %s)', self.control_flow_graph )
            self.db.commit()
            del self.control_flow_graph
        
            print 'Opening TEMP file for [operand_strings__expression_trees] size [%d]' % ( os.fstat( self.operand_strings__expression_trees_tmp_file.fileno() ).st_size )
            done = False
            total_inserted = 0
            self.operand_strings__expression_trees_tmp_file.seek(0)
            while not done:
                operand_strings__expression_trees = list()
                try:
                    for i in range(50000):
                        operand_strings__expression_trees.append( cPickle.load( self.operand_strings__expression_trees_tmp_file ) )
                except EOFError:
                    done = True
                total_inserted += len(operand_strings__expression_trees)
                if self.use_new_schema is True:
                    self.db.cursor.executemany( self.db.cursor,
                        ('INSERT IGNORE INTO ex_%d_expression_trees(id) ' %
                        self.db.get_module_id() ) + 'VALUES(%s)', operand_strings__expression_trees )
                else:
                    self.db.cursor.executemany( self.db.cursor,
                        ('INSERT IGNORE INTO ex_%d_operand_strings(str, id) ' %
                        self.db.get_module_id() ) + 'VALUES(%s, %s)', operand_strings__expression_trees )
                self.db.commit()
                print 'Inserted %d rows total' % (total_inserted)
            del operand_strings__expression_trees
            
            
            print 'Opening TEMP file for [instructions_values] size [%d]' % ( os.fstat( self.instructions_values_tmp_file.fileno() ).st_size )
            done = False
            total_inserted = 0
            self.instructions_values_tmp_file.seek(0)
            while not done:
                instructions_values = list()
                try:
                    for i in range(50000):
                        instructions_values.append( cPickle.load( self.instructions_values_tmp_file ) )
                except EOFError:
                    done = True
                total_inserted += len(instructions_values)
                self.db.cursor.executemany( self.db.cursor,
                    ('INSERT IGNORE INTO ex_%d_instructions(address, mnemonic, basic_block_id, sequence, data) ' %
                    self.db.get_module_id() ) + 'VALUES(%s, %s, %s, %s, %s)', instructions_values )
                self.db.commit()
                print 'Inserted %d rows total' % (total_inserted)
            del instructions_values
            
            self.expression_substitutions_values_count = len(self.expression_substitutions_values)
            if self.use_new_schema is True:
                self.db.cursor.executemany( self.db.cursor,
                    ('INSERT IGNORE INTO ex_%d_expression_substitutions(address, expression_node_id, position, replacement) ' %
                    self.db.get_module_id() ) + 'VALUES(%s, %s, %s, %s)', list(self.expression_substitutions_values) )
            else:
                self.db.cursor.executemany( self.db.cursor,
                    ('INSERT IGNORE INTO ex_%d_expression_substitutions(address, operand_id, expr_id, replacement) ' %
                    self.db.get_module_id() ) + 'VALUES(%s, %s, %s, %s)', list(self.expression_substitutions_values) )
            self.db.commit()
            del self.expression_substitutions_values
            
            while True:
                data = list()
                # retrieve a bunch of operand ID's, get their expressions and insert them.
                # Trying to be careful using memory
                for operand_count in range(10000):
                    try:
                        operand_id = self.operand_expressions_values_dict.iterkeys().next()
                    except StopIteration:
                        break
                    data.extend( [ (operand_id, expr_id) for expr_id in self.operand_expressions_values_dict[operand_id] ] )
                    del self.operand_expressions_values_dict[operand_id]
                    
                if not data:
                    break
                    
                if self.use_new_schema is True:
                    self.db.cursor.executemany( self.db.cursor,
                        ('INSERT IGNORE INTO ex_%d_expression_tree_nodes(expression_tree_id, expression_node_id) ' %
                        self.db.get_module_id() ) + 'VALUES(%s, %s)', data )
                else:
                    self.db.cursor.executemany( self.db.cursor,
                        ('INSERT IGNORE INTO ex_%d_operand_expressions(operand_id, expr_id) ' %
                        self.db.get_module_id() ) + 'VALUES(%s, %s)', data )
                self.db.commit()
        
            print 'Opening TEMP file for [operand_tuples___operands_values] size [%d]' % ( os.fstat( self.operand_tuples___operands_values_tmp_file.fileno() ).st_size )
            done = False
            total_inserted = 0
            self.operand_tuples___operands_values_tmp_file.seek(0)
            while not done:
                operand_tuples___operands_values = list()
                try:
                    for i in range(50000):
                        operand_tuples___operands_values.append( cPickle.load( self.operand_tuples___operands_values_tmp_file ) )
                except EOFError:
                    done = True
                total_inserted += len(operand_tuples___operands_values)
                if self.use_new_schema is True:
                    self.db.cursor.executemany( self.db.cursor,
                        ('INSERT IGNORE INTO ex_%d_operands(address, expression_tree_id, position) ' %
                        self.db.get_module_id() ) + 'VALUES(%s, %s, %s)', operand_tuples___operands_values )
                else:
                    self.db.cursor.executemany( self.db.cursor,
                        ('INSERT IGNORE INTO ex_%d_operand_tuples(address, operand_id, position) ' %
                        self.db.get_module_id() ) + 'VALUES(%s, %s, %s)', operand_tuples___operands_values )
                self.db.commit()
                print 'Inserted %d rows total' % (total_inserted)
            del operand_tuples___operands_values
            
            self.address_references_values_count = len(self.address_references_values)
            if self.use_new_schema is True:
                self.db.cursor.executemany( self.db.cursor,
                    ('INSERT IGNORE INTO ex_%d_address_references(address, destination, `type`, expression_node_id, position) ' %
                    self.db.get_module_id()) + 'VALUES(%s, %s, %s, %s, %s)', list(self.address_references_values) )
            else:
                self.db.cursor.executemany( self.db.cursor,
                    ('INSERT IGNORE INTO ex_%d_address_references(address, target, kind, operand_id, expression_id) ' %
                    self.db.get_module_id()) + 'VALUES(%s, %s, %s, %s, %s)', list(self.address_references_values) )
            self.db.commit()
            del self.address_references_values
            
            self.db.cursor.executemany( self.db.cursor,
                ('INSERT IGNORE INTO ex_%d_address_comments(address, comment) ' %
                self.db.get_module_id()) + 'VALUES(%s, %s)', self.address_comments_values )
            self.db.commit()
            del self.address_comments_values
        
        if self.callgraph_only or self.exporting_manually:
            callgraph_values = list()
        
            for edge in self.calltree_information:
        
                # If the destination address in not within the 
                # functions processed show a warning that
                # could help the user pinpoint the source of trouble
                # and act on it. There are cases where a call is made
                # to functions which are embedded into other functions
                # as their epilog. In that case IDA is unable of 
                # representing that code as both, part of the function
                # for which it's the epilog, and a funcion on its own.
                #
                if edge[2] not in self.exported_functions:
                    dbg_message(
                        ('INVALID REFERENCE. Source Function: %x '   +
                        'Source Address: %x ' +
                        'Basic Block Id: %s Destination: %x ') % (
                        edge[0], edge[3], self.block_ids[edge[1]], edge[2]))
                    dbg_message( ' [There is no function defined at target: 0x%0x]' % edge[2] )
                    continue
                
                callgraph_values.append( (edge[0], self.block_ids[edge[1]], edge[2], edge[3]) )
                
            if self.use_new_schema is True:
                self.db.cursor.executemany( self.db.cursor,
                    ('INSERT IGNORE INTO ex_%d_callgraph(source, source_basic_block_id, destination, source_address) ' %
                    self.db.get_module_id()) + 'VALUES(%s, %s, %s, %s)', callgraph_values )
            else:
                self.db.cursor.executemany( self.db.cursor,
                    ('INSERT IGNORE INTO ex_%d_callgraph(src, src_basic_block_id, dst, src_address) ' %
                    self.db.get_module_id()) + 'VALUES(%s, %s, %s, %s)', callgraph_values )

        self.db.commit()
        
    def breadth_first_count(self, branches, starting_block):
        
        results = list()
        visited = list()
        block_queue = [(starting_block, 0)]
        depth = 0
        
        while True:
            
            if not block_queue:
                break
            
            block, depth = block_queue.pop()
            results.append((block, depth))
            
            child_blocks = [branch[1] for branch in branches if branch[0]==block]
            
            for new_block in child_blocks:
                if new_block not in visited:
                    block_queue.append((new_block, depth+1))
                    visited.append(new_block)
            
        return results
    

