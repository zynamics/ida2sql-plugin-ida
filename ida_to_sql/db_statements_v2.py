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

import common

__author__ = 'Ero Carrera'
__version__ = common.__version__
__license__ = 'GPL'

MYSQL_SCHEMA_VERSION = 3

mysql_new_db_statements = """
CREATE table modules(
   id INTEGER UNSIGNED NOT NULL UNIQUE PRIMARY KEY AUTO_INCREMENT,
   name TEXT NOT NULL,
   architecture VARCHAR( 32 ) NOT NULL,
   base_address BIGINT UNSIGNED NOT NULL,
   exporter VARCHAR( 256 ) NOT NULL,
   version INT NOT NULL,
   md5 CHAR(32) NOT NULL,
   sha1 CHAR(40) NOT NULL,
   comment TEXT,
   import_time TIMESTAMP NOT NULL )
ENGINE=InnoDB;
"""


mysql_new_module_statements = """
CREATE TABLE IF NOT EXISTS
ex_{MODULE_ID}_functions (
   `address` BIGINT UNSIGNED UNIQUE NOT NULL UNIQUE,
   `name` TEXT NOT NULL,
   `has_real_name` BOOLEAN NOT NULL DEFAULT TRUE,
   `type` INTEGER UNSIGNED NOT NULL DEFAULT 0 CHECK( `type` <= 3 ),
   `module_name` TEXT NULL DEFAULT NULL,
   PRIMARY KEY ( `address` ))
ENGINE=InnoDB;


CREATE TABLE IF NOT EXISTS
ex_{MODULE_ID}_basic_blocks (
   `id` INTEGER UNSIGNED NOT NULL,
   `parent_function` BIGINT UNSIGNED NOT NULL,
   `address` BIGINT UNSIGNED NOT NULL,
   PRIMARY KEY( `id`, `parent_function`),
   KEY(`address`),
   FOREIGN KEY (`parent_function`) REFERENCES ex_{MODULE_ID}_functions(`address`) ON DELETE CASCADE ON UPDATE CASCADE )
ENGINE=InnoDB;


CREATE TABLE IF NOT EXISTS
ex_{MODULE_ID}_instructions (
   `address` BIGINT UNSIGNED NOT NULL,
   `basic_block_id` INTEGER UNSIGNED NOT NULL,
   `mnemonic` VARCHAR(32),
   `sequence` INT UNSIGNED NOT NULL,
   `data` BLOB NOT NULL,
   PRIMARY KEY(`address`, `basic_block_id`),
   FOREIGN KEY (`basic_block_id`) REFERENCES ex_{MODULE_ID}_basic_blocks(`id`) ON DELETE CASCADE ON UPDATE CASCADE )
ENGINE=InnoDB;


CREATE TABLE IF NOT EXISTS
ex_{MODULE_ID}_callgraph (
   `id` INTEGER UNSIGNED NOT NULL UNIQUE PRIMARY KEY AUTO_INCREMENT,
   `source` BIGINT UNSIGNED NOT NULL,
   `source_basic_block_id` INTEGER UNSIGNED NOT NULL,
   `source_address` BIGINT UNSIGNED NOT NULL, 
   `destination` BIGINT UNSIGNED NOT NULL, 
   FOREIGN KEY (`source`) REFERENCES ex_{MODULE_ID}_functions(`address`) ON DELETE CASCADE ON UPDATE CASCADE,
   FOREIGN KEY (`destination`) REFERENCES ex_{MODULE_ID}_functions(`address`) ON DELETE CASCADE ON UPDATE CASCADE,
   FOREIGN KEY (`source_basic_block_id`) REFERENCES ex_{MODULE_ID}_basic_blocks(`id`) ON DELETE CASCADE ON UPDATE CASCADE,
   FOREIGN KEY (`source_address`) REFERENCES ex_{MODULE_ID}_instructions(`address`) ON DELETE CASCADE ON UPDATE CASCADE )
ENGINE=InnoDB;


CREATE TABLE IF NOT EXISTS
ex_{MODULE_ID}_control_flow_graphs (
   `id` INTEGER UNSIGNED NOT NULL UNIQUE PRIMARY KEY AUTO_INCREMENT,
   `parent_function` BIGINT UNSIGNED NOT NULL,
   `source` INTEGER UNSIGNED NOT NULL,
   `destination` INTEGER UNSIGNED NOT NULL,
   `type` INTEGER UNSIGNED NOT NULL DEFAULT 0 CHECK( `type` <= 3 ),
   FOREIGN KEY (`source`) REFERENCES ex_{MODULE_ID}_basic_blocks(`id`) ON DELETE CASCADE ON UPDATE CASCADE,
   FOREIGN KEY (`destination`) REFERENCES ex_{MODULE_ID}_basic_blocks(`id`) ON DELETE CASCADE ON UPDATE CASCADE,
   FOREIGN KEY (`parent_function`) REFERENCES ex_{MODULE_ID}_functions(`address`) ON DELETE CASCADE ON UPDATE CASCADE,
   INDEX (parent_function, source) )
ENGINE=InnoDB;


CREATE TABLE IF NOT EXISTS
ex_{MODULE_ID}_expression_trees (
   `id` INTEGER UNSIGNED NOT NULL UNIQUE PRIMARY KEY AUTO_INCREMENT
    )
ENGINE=InnoDB;


CREATE TABLE IF NOT EXISTS
ex_{MODULE_ID}_expression_nodes (
   `id` INTEGER UNSIGNED NOT NULL UNIQUE PRIMARY KEY AUTO_INCREMENT,
   `type` INTEGER UNSIGNED NOT NULL DEFAULT 0 CHECK( `type` <= 7 ),
   `symbol` VARCHAR(256), 
   `immediate` BIGINT SIGNED, 
   `position` INTEGER, 
   `parent_id` INTEGER UNSIGNED CHECK(`id` > `parent_id`),
   FOREIGN KEY (`parent_id`) REFERENCES ex_{MODULE_ID}_expression_nodes(`id`) ON DELETE CASCADE ON UPDATE CASCADE )
ENGINE=InnoDB;


CREATE TABLE IF NOT EXISTS
ex_{MODULE_ID}_operands (
   `address` BIGINT UNSIGNED NOT NULL,
   `expression_tree_id` INTEGER UNSIGNED NOT NULL,
   `position` INTEGER UNSIGNED NOT NULL,
   FOREIGN KEY (`expression_tree_id`) REFERENCES ex_{MODULE_ID}_expression_trees(`id`) ON DELETE CASCADE ON UPDATE CASCADE,
   FOREIGN KEY (`address`) REFERENCES ex_{MODULE_ID}_instructions(`address`) ON DELETE CASCADE ON UPDATE CASCADE,
   PRIMARY KEY( `address`, `position` ) )
ENGINE=InnoDB;


CREATE TABLE IF NOT EXISTS
ex_{MODULE_ID}_expression_substitutions (
   `id` INTEGER UNSIGNED NOT NULL UNIQUE PRIMARY KEY AUTO_INCREMENT,
   `address` BIGINT UNSIGNED NOT NULL,
   `position` INTEGER UNSIGNED NOT NULL,
   `expression_node_id` INTEGER UNSIGNED NOT NULL,
   `replacement` TEXT NOT NULL,
   FOREIGN KEY (`address`, `position`) REFERENCES ex_{MODULE_ID}_operands(`address`, `position`) ON DELETE CASCADE ON UPDATE CASCADE,
   FOREIGN KEY (`expression_node_id`) REFERENCES ex_{MODULE_ID}_expression_nodes(`id`) ON DELETE CASCADE ON UPDATE CASCADE )
ENGINE=InnoDB;


CREATE TABLE IF NOT EXISTS
ex_{MODULE_ID}_expression_tree_nodes (
   `expression_tree_id` INTEGER UNSIGNED NOT NULL,
   `expression_node_id` INTEGER UNSIGNED NOT NULL,
   FOREIGN KEY (`expression_tree_id`) REFERENCES ex_{MODULE_ID}_expression_trees(`id`) ON DELETE CASCADE ON UPDATE CASCADE,
   FOREIGN KEY (`expression_node_id`) REFERENCES ex_{MODULE_ID}_expression_nodes(`id`) ON DELETE CASCADE ON UPDATE CASCADE )
ENGINE=InnoDB;


CREATE TABLE IF NOT EXISTS
ex_{MODULE_ID}_address_references (
   `address` BIGINT UNSIGNED NOT NULL,
   `position` INTEGER UNSIGNED NULL,
   `expression_node_id` INTEGER UNSIGNED NULL,
   `destination` BIGINT UNSIGNED NOT NULL,
   `type` INT UNSIGNED NOT NULL DEFAULT 0 CHECK( `type` <= 8 ),
   FOREIGN KEY (`address`, `position`) REFERENCES ex_{MODULE_ID}_operands(`address`, `position`) ON DELETE CASCADE ON UPDATE CASCADE,
   FOREIGN KEY (`expression_node_id`) REFERENCES ex_{MODULE_ID}_expression_nodes( `id` ) ON DELETE CASCADE ON UPDATE CASCADE,
   KEY(`destination`),
   KEY(`type`) )
ENGINE=InnoDB;


CREATE TABLE IF NOT EXISTS
ex_{MODULE_ID}_address_comments (
   `address` BIGINT UNSIGNED UNIQUE NOT NULL,
   `comment` TEXT NOT NULL,
   PRIMARY KEY(`address`))
ENGINE=InnoDB;


CREATE TABLE IF NOT EXISTS
ex_{MODULE_ID}_sections (
   `name` VARCHAR(256) NOT NULL,
   `base` BIGINT UNSIGNED NOT NULL,
   `start_address` BIGINT UNSIGNED NOT NULL,
   `end_address` BIGINT UNSIGNED NOT NULL,
   `length` BIGINT UNSIGNED NOT NULL,
   `data` LONGBLOB )
ENGINE=InnoDB;

"""


####################################
########### PostgreSQL #############
####################################

#-removed INNODB
#-removed backticks
#-removed UNSIGNED, SIGNED
#-changed AUTO_INCREMENT into SERIAL
#-removed "IF NOT EXISTS"
#-changed BLOB to BYTEA

postgresql_new_db_statements = """
"""

postgresql_new_module_statements = """"""
