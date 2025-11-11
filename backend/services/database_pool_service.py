"""
Database Connection Pooling and Query Optimization Service

This module provides enterprise-grade database connection pooling,
query optimization, performance monitoring, and connection management.
"""

import time
import threading
import queue
import logging
from contextlib import contextmanager
from typing import Dict, Any, Optional, List, Callable
from datetime import datetime, timedelta
import mysql.connector
from mysql.connector import pooling, Error
from flask import current_app, g
from db.database import get_connection

logger = logging.getLogger(__name__)

class DatabasePoolService:
    """
    Enterprise-grade database connection pool with optimization
    """
    
    def __init__(self, app=None):
        self.app = app
        self._connection_pool = None
        self._pool_config = {}
        self._query_stats = {
            'total_queries': 0,
            'slow_queries': 0,
            'failed_queries': 0,
            'avg_execution_time': 0.0,
            'pool_hits': 0,
            'pool_misses': 0
        }
        self._lock = threading.Lock()
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize database pool service with Flask app"""
        self.app = app
        app.db_pool_service = self
        
        # Initialize connection pool
        self._init_connection_pool()
        
        # Start monitoring thread
        self._start_monitoring_thread()
    
    def _init_connection_pool(self):
        """Initialize database connection pool"""
        try:
            config = current_app.config
            
            # Pool configuration
            self._pool_config = {
                'pool_name': 'enterprise_pool',
                'pool_size': config.get('DB_POOL_SIZE', 10),
                'max_overflow': config.get('DB_POOL_MAX_OVERFLOW', 20),
                'pool_reset_session': True,
                'pool_recycle': config.get('DB_POOL_RECYCLE', 3600),  # 1 hour
                'pool_timeout': config.get('DB_POOL_TIMEOUT', 30),
                'autocommit': False,
                'sql_mode': 'STRICT_TRANS_TABLES,NO_ZERO_DATE,NO_ZERO_IN_DATE,NO_ENGINE_SUBSTITUTION'
            }
            
            # Create connection pool
            pool_config = {
                'host': config.get('DB_HOST', 'localhost'),
                'port': config.get('DB_PORT', '3306'),
                'user': config.get('DB_USER', 'root'),
                'password': config.get('DB_PASSWORD', ''),
                'database': config.get('DB_NAME', 'library_db'),
                'charset': 'utf8mb4',
                'collation': 'utf8mb4_unicode_ci',
                'autocommit': self._pool_config['autocommit'],
                'sql_mode': self._pool_config['sql_mode'],
                'connection_timeout': config.get('DB_CONNECTION_TIMEOUT', 60),
                'command_timeout': config.get('DB_COMMAND_TIMEOUT', 30),
                'raise_on_warnings': True,
                'use_pure': True
            }
            
            self._connection_pool = pooling.MySQLConnectionPool(
                pool_name=self._pool_config['pool_name'],
                pool_size=self._pool_config['pool_size'],
                max_overflow=self._pool_config['max_overflow'],
                pool_reset_session=self._pool_config['pool_reset_session'],
                pool_recycle=self._pool_config['pool_recycle'],
                pool_timeout=self._pool_config['pool_timeout'],
                **pool_config
            )
            
            logger.info(f"Database connection pool initialized: {self._pool_config['pool_size']} connections")
            
        except Exception as e:
            logger.error(f"Failed to initialize database pool: {str(e)}")
            raise RuntimeError(f"Database pool initialization failed: {str(e)}")
    
    def _start_monitoring_thread(self):
        """Start background monitoring thread"""
        def monitor_pool():
            while True:
                try:
                    time.sleep(60)  # Monitor every minute
                    self._monitor_pool_health()
                    self._log_pool_stats()
                except Exception as e:
                    logger.error(f"Pool monitoring error: {str(e)}")
                    time.sleep(60)
        
        monitor_thread = threading.Thread(target=monitor_pool, daemon=True)
        monitor_thread.start()
        logger.info("Database pool monitoring thread started")
    
    def _monitor_pool_health(self):
        """Monitor connection pool health"""
        if not self._connection_pool:
            return
        
        try:
            with self._lock:
                # Get pool statistics
                pool_stats = self._connection_pool._pool_stats
                
                # Log warnings for pool issues
                if pool_stats['overflow_used'] > 0:
                    logger.warning(f"Database pool overflow detected: {pool_stats['overflow_used']} connections")
                
                if pool_stats['pool_error_count'] > 0:
                    logger.error(f"Database pool errors: {pool_stats['pool_error_count']}")
                
                # Check for connection leaks
                active_connections = pool_stats['pool_size'] - pool_stats['idle_connections']
                if active_connections > self._pool_config['pool_size']:
                    logger.warning(f"Potential connection leak: {active_connections} active connections")
        
        except Exception as e:
            logger.error(f"Pool health monitoring error: {str(e)}")
    
    def _log_pool_stats(self):
        """Log pool performance statistics"""
        try:
            with self._lock:
                stats = self._query_stats
                
                # Calculate averages
                if stats['total_queries'] > 0:
                    stats['avg_execution_time'] = (
                        stats.get('total_execution_time', 0.0) / stats['total_queries']
                    )
                
                # Log performance metrics
                logger.info(f"DB Pool Stats - Queries: {stats['total_queries']}, "
                           f"Slow: {stats['slow_queries']}, "
                           f"Avg Time: {stats['avg_execution_time']:.3f}s, "
                           f"Pool Hits: {stats['pool_hits']}, "
                           f"Pool Misses: {stats['pool_misses']}")
                
                # Reset counters for next interval
                self._query_stats = {
                    'total_queries': 0,
                    'slow_queries': 0,
                    'failed_queries': 0,
                    'total_execution_time': 0.0,
                    'pool_hits': 0,
                    'pool_misses': 0
                }
        
        except Exception as e:
            logger.error(f"Failed to log pool stats: {str(e)}")
    
    @contextmanager
    def get_connection(self):
        """
        Get a database connection from the pool
        
        Yields:
            Database connection object
        """
        start_time = time.time()
        connection = None
        
        try:
            with self._lock:
                connection = self._connection_pool.get_connection()
                self._query_stats['pool_hits'] += 1
                
                # Set connection options
                if connection:
                    connection.cmd_query("SET SESSION sql_mode = 'STRICT_TRANS_TABLES,NO_ZERO_DATE,NO_ZERO_IN_DATE,NO_ENGINE_SUBSTITUTION'")
                    connection.cmd_query("SET SESSION innodb_lock_wait_timeout = 5")
                    connection.cmd_query("SET SESSION query_cache_type = ON")
                    connection.cmd_query("SET SESSION query_cache_size = 268435456")
                    connection.cmd_query("SET SESSION tmp_table_size = 67108864")
                
                yield connection
                
        except Exception as e:
            logger.error(f"Failed to get database connection: {str(e)}")
            self._query_stats['failed_queries'] += 1
            raise
        finally:
            execution_time = time.time() - start_time
            
            # Update statistics
            with self._lock:
                self._query_stats['total_queries'] += 1
                self._query_stats['total_execution_time'] += execution_time
                
                if execution_time > 1.0:  # Slow query threshold
                    self._query_stats['slow_queries'] += 1
                    logger.warning(f"Slow query detected: {execution_time:.3f}s")
            
            # Return connection to pool
            if connection:
                try:
                    self._connection_pool.return_connection(connection)
                except Exception as e:
                    logger.error(f"Failed to return connection to pool: {str(e)}")
    
    def execute_query(self, query: str, params: Optional[tuple] = None, 
                   fetch_one: bool = False, fetch_all: bool = False,
                   commit: bool = False) -> Any:
        """
        Execute a database query with optimization and monitoring
        
        Args:
            query: SQL query to execute
            params: Query parameters
            fetch_one: Return single result
            fetch_all: Return all results
            commit: Commit transaction
            
        Returns:
            Query result(s)
        """
        start_time = time.time()
        
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor(dictionary=True, buffered=True)
                
                # Execute query
                if params:
                    cursor.execute(query, params)
                else:
                    cursor.execute(query)
                
                # Fetch results
                if fetch_one:
                    result = cursor.fetchone()
                elif fetch_all:
                    result = cursor.fetchall()
                else:
                    result = cursor.rowcount
                
                # Commit if requested
                if commit:
                    conn.commit()
                
                return result
                
        except Error as e:
            logger.error(f"MySQL error: {str(e)}")
            self._query_stats['failed_queries'] += 1
            raise
        except Exception as e:
            logger.error(f"Query execution error: {str(e)}")
            self._query_stats['failed_queries'] += 1
            raise
        finally:
            execution_time = time.time() - start_time
            
            # Log slow queries
            if execution_time > 2.0:  # Very slow query threshold
                logger.error(f"Very slow query: {execution_time:.3f}s - {query[:100]}...")
    
    def execute_batch(self, queries: List[tuple]) -> List[Any]:
        """
        Execute multiple queries in a batch for better performance
        
        Args:
            queries: List of (query, params) tuples
            
        Returns:
            List of results
        """
        start_time = time.time()
        results = []
        
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor(dictionary=True, buffered=True)
                
                # Execute all queries
                for query, params in queries:
                    if params:
                        cursor.execute(query, params)
                    else:
                        cursor.execute(query)
                    results.append(cursor.fetchall())
                
                conn.commit()
                return results
                
        except Error as e:
            logger.error(f"Batch execution error: {str(e)}")
            self._query_stats['failed_queries'] += len(queries)
            raise
        except Exception as e:
            logger.error(f"Batch execution error: {str(e)}")
            self._query_stats['failed_queries'] += len(queries)
            raise
        finally:
            execution_time = time.time() - start_time
            logger.debug(f"Batch execution time: {execution_time:.3f}s for {len(queries)} queries")
    
    def execute_procedure(self, procedure_name: str, params: Optional[tuple] = None) -> Any:
        """
        Execute a stored procedure with optimization
        
        Args:
            procedure_name: Name of stored procedure
            params: Procedure parameters
            
        Returns:
            Procedure result
        """
        start_time = time.time()
        
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor(dictionary=True, buffered=True)
                
                # Call stored procedure
                if params:
                    cursor.callproc(procedure_name, params)
                else:
                    cursor.callproc(procedure_name)
                
                result = cursor.fetchall()
                conn.commit()
                
                return result
                
        except Error as e:
            logger.error(f"Stored procedure error: {str(e)}")
            self._query_stats['failed_queries'] += 1
            raise
        except Exception as e:
            logger.error(f"Procedure execution error: {str(e)}")
            self._query_stats['failed_queries'] += 1
            raise
        finally:
            execution_time = time.time() - start_time
            logger.debug(f"Procedure {procedure_name} execution time: {execution_time:.3f}s")
    
    def optimize_table(self, table_name: str) -> bool:
        """
        Optimize a database table
        
        Args:
            table_name: Name of table to optimize
            
        Returns:
            True if successful, False otherwise
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Analyze table
                cursor.execute(f"ANALYZE TABLE {table_name}")
                
                # Optimize table (if supported)
                try:
                    cursor.execute(f"OPTIMIZE TABLE {table_name}")
                except Error:
                    # OPTIMIZE might not be supported or allowed
                    pass
                
                conn.commit()
                return True
                
        except Exception as e:
            logger.error(f"Table optimization error: {str(e)}")
            return False
    
    def get_pool_stats(self) -> Dict[str, Any]:
        """
        Get current pool statistics
        
        Returns:
            Dictionary with pool statistics
        """
        try:
            with self._lock:
                if self._connection_pool:
                    pool_stats = self._connection_pool._pool_stats
                    
                    return {
                        'pool_size': self._pool_config['pool_size'],
                        'max_overflow': self._pool_config['max_overflow'],
                        'active_connections': pool_stats.get('pool_size', 0) - pool_stats.get('idle_connections', 0),
                        'idle_connections': pool_stats.get('idle_connections', 0),
                        'overflow_used': pool_stats.get('overflow_used', 0),
                        'pool_error_count': pool_stats.get('pool_error_count', 0),
                        'query_stats': self._query_stats.copy()
                    }
                else:
                    return {'error': 'Connection pool not initialized'}
                    
        except Exception as e:
            logger.error(f"Failed to get pool stats: {str(e)}")
            return {'error': str(e)}
    
    def reset_pool_stats(self) -> bool:
        """
        Reset pool statistics
        
        Returns:
            True if successful, False otherwise
        """
        try:
            with self._lock:
                self._query_stats = {
                    'total_queries': 0,
                    'slow_queries': 0,
                    'failed_queries': 0,
                    'total_execution_time': 0.0,
                    'pool_hits': 0,
                    'pool_misses': 0
                }
                
                logger.info("Pool statistics reset")
                return True
                
        except Exception as e:
            logger.error(f"Failed to reset pool stats: {str(e)}")
            return False
    
    def close_pool(self):
        """Close all connections in the pool"""
        try:
            if self._connection_pool:
                self._connection_pool.close()
                logger.info("Database connection pool closed")
        except Exception as e:
            logger.error(f"Failed to close pool: {str(e)}")


# Global database pool service instance
db_pool_service = DatabasePoolService()

# Decorator for automatic connection management
def with_db_connection(func):
    """
    Decorator to automatically provide database connection
    
    Args:
        func: Function to decorate
        
    Returns:
        Decorated function with connection management
    """
    def decorated_function(*args, **kwargs):
        with db_pool_service.get_connection() as conn:
            # Store connection in Flask g for access in function
            g.db_connection = conn
            try:
                result = func(*args, **kwargs)
                return result
            finally:
                # Clean up connection reference
                if hasattr(g, 'db_connection'):
                    delattr(g, 'db_connection')
    
    return decorated_function

# Decorator for transaction management
def with_transaction(func):
    """
    Decorator for automatic transaction management
    
    Args:
        func: Function to decorate
        
    Returns:
        Decorated function with transaction management
    """
    def decorated_function(*args, **kwargs):
        with db_pool_service.get_connection() as conn:
            try:
                # Start transaction
                conn.start_transaction()
                
                # Execute function
                result = func(*args, **kwargs)
                
                # Commit transaction
                conn.commit()
                return result
                
            except Exception as e:
                # Rollback on error
                try:
                    conn.rollback()
                except:
                    pass
                logger.error(f"Transaction failed and rolled back: {str(e)}")
                raise
            finally:
                # End transaction
                try:
                    conn.end_transaction()
                except:
                    pass
    
    return decorated_function

# Query builder for optimized queries
class QueryBuilder:
    """
    Query builder for optimized SQL generation
    """
    
    @staticmethod
    def select(table: str, columns: List[str] = None, 
               where_clause: str = None, order_by: str = None,
               limit: int = None, offset: int = None) -> str:
        """
        Build optimized SELECT query
        
        Args:
            table: Table name
            columns: Columns to select
            where_clause: WHERE clause
            order_by: ORDER BY clause
            limit: LIMIT value
            offset: OFFSET value
            
        Returns:
            Optimized SQL query
        """
        # Build column list
        column_list = "*"
        if columns:
            column_list = ", ".join([f"`{col}`" for col in columns])
        
        # Build query
        query = f"SELECT {column_list} FROM `{table}`"
        
        if where_clause:
            query += f" WHERE {where_clause}"
        
        if order_by:
            query += f" ORDER BY {order_by}"
        
        if limit:
            query += f" LIMIT {limit}"
        
        if offset:
            query += f" OFFSET {offset}"
        
        return query
    
    @staticmethod
    def insert(table: str, data: Dict[str, Any], 
               on_duplicate: str = None) -> tuple:
        """
        Build optimized INSERT query
        
        Args:
            table: Table name
            data: Data to insert
            on_duplicate: ON DUPLICATE clause
            
        Returns:
            Tuple of (query, params)
        """
        columns = list(data.keys())
        placeholders = ", ".join(["%s"] * len(columns))
        column_names = ", ".join([f"`{col}`" for col in columns])
        
        query = f"INSERT INTO `{table}` ({column_names}) VALUES ({placeholders})"
        
        if on_duplicate:
            query += f" ON DUPLICATE KEY {on_duplicate}"
        
        params = list(data.values())
        return query, params
    
    @staticmethod
    def update(table: str, data: Dict[str, Any], 
               where_clause: str) -> tuple:
        """
        Build optimized UPDATE query
        
        Args:
            table: Table name
            data: Data to update
            where_clause: WHERE clause
            
        Returns:
            Tuple of (query, params)
        """
        set_clauses = []
        params = []
        
        for column, value in data.items():
            set_clauses.append(f"`{column}` = %s")
            params.append(value)
        
        set_clause = ", ".join(set_clauses)
        query = f"UPDATE `{table}` SET {set_clause} WHERE {where_clause}"
        
        return query, params