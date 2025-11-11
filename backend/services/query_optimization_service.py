"""
Query Optimization Service

This module provides advanced query optimization, performance analysis,
and database tuning recommendations for enterprise applications.
"""

import re
import time
import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta
from collections import defaultdict
import mysql.connector
from mysql.connector import Error
from flask import current_app
from services.database_pool_service import db_pool_service, QueryBuilder

logger = logging.getLogger(__name__)

class QueryOptimizationService:
    """
    Advanced query optimization and performance analysis service
    """
    
    def __init__(self):
        self._query_cache = {}
        self._slow_query_log = []
        self._index_recommendations = {}
        self._query_patterns = defaultdict(int)
        self._performance_metrics = {
            'total_queries': 0,
            'optimized_queries': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'avg_execution_time': 0.0,
            'slow_queries': 0
        }
    
    def analyze_query(self, query: str, params: Optional[tuple] = None) -> Dict[str, Any]:
        """
        Analyze a SQL query for optimization opportunities
        
        Args:
            query: SQL query to analyze
            params: Query parameters
            
        Returns:
            Dictionary with analysis results
        """
        analysis = {
            'query': query,
            'query_type': self._get_query_type(query),
            'tables': self._extract_tables(query),
            'columns': self._extract_columns(query),
            'joins': self._extract_joins(query),
            'where_clauses': self._extract_where_clauses(query),
            'optimization_suggestions': [],
            'estimated_cost': 0,
            'index_recommendations': [],
            'warnings': []
        }
        
        # Analyze query structure
        analysis['optimization_suggestions'].extend(self._analyze_query_structure(query))
        
        # Check for missing indexes
        analysis['index_recommendations'].extend(self._check_missing_indexes(query))
        
        # Analyze join performance
        analysis['optimization_suggestions'].extend(self._analyze_joins(query))
        
        # Check for N+1 query problems
        analysis['warnings'].extend(self._check_n_plus_one(query))
        
        # Estimate query cost
        analysis['estimated_cost'] = self._estimate_query_cost(query)
        
        return analysis
    
    def _get_query_type(self, query: str) -> str:
        """Extract query type (SELECT, INSERT, UPDATE, DELETE)"""
        query_upper = query.strip().upper()
        if query_upper.startswith('SELECT'):
            return 'SELECT'
        elif query_upper.startswith('INSERT'):
            return 'INSERT'
        elif query_upper.startswith('UPDATE'):
            return 'UPDATE'
        elif query_upper.startswith('DELETE'):
            return 'DELETE'
        elif query_upper.startswith('CREATE'):
            return 'CREATE'
        elif query_upper.startswith('ALTER'):
            return 'ALTER'
        elif query_upper.startswith('DROP'):
            return 'DROP'
        else:
            return 'OTHER'
    
    def _extract_tables(self, query: str) -> List[str]:
        """Extract table names from query"""
        tables = []
        
        # Match FROM and JOIN clauses
        from_pattern = r'\bFROM\s+([`"]?(\w+)[`"]?)'
        join_pattern = r'\bJOIN\s+([`"]?(\w+)[`"]?)'
        
        for match in re.finditer(from_pattern, query, re.IGNORECASE):
            tables.append(match.group(2))
        
        for match in re.finditer(join_pattern, query, re.IGNORECASE):
            tables.append(match.group(2))
        
        return list(set(tables))
    
    def _extract_columns(self, query: str) -> List[str]:
        """Extract column names from SELECT query"""
        columns = []
        
        # Match SELECT columns
        select_pattern = r'\bSELECT\s+(.*?)\s+FROM'
        match = re.search(select_pattern, query, re.IGNORECASE | re.DOTALL)
        
        if match:
            select_clause = match.group(1).strip()
            if select_clause != '*':
                # Split by comma and clean up
                for col in select_clause.split(','):
                    col = col.strip()
                    # Remove table prefixes and aliases
                    col = re.sub(r'^[`"]?\w+[`"]?\.', '', col)
                    col = re.sub(r'\s+AS\s+[`"]?\w+[`"]?$', '', col, flags=re.IGNORECASE)
                    col = col.strip('`"')
                    if col and col != '*':
                        columns.append(col)
        
        return columns
    
    def _extract_joins(self, query: str) -> List[Dict[str, str]]:
        """Extract join information from query"""
        joins = []
        
        # Match JOIN clauses
        join_pattern = r'\b(INNER|LEFT|RIGHT|FULL|CROSS)\s+JOIN\s+([`"]?(\w+)[`"]?)\s+ON\s+([^)]+)'
        
        for match in re.finditer(join_pattern, query, re.IGNORECASE):
            joins.append({
                'type': match.group(1),
                'table': match.group(3),
                'condition': match.group(4).strip()
            })
        
        return joins
    
    def _extract_where_clauses(self, query: str) -> List[str]:
        """Extract WHERE clauses from query"""
        where_clauses = []
        
        # Match WHERE clause
        where_pattern = r'\bWHERE\s+(.*?)(?:\s+GROUP\s+BY|\s+ORDER\s+BY|\s+LIMIT|$)'
        match = re.search(where_pattern, query, re.IGNORECASE | re.DOTALL)
        
        if match:
            where_clause = match.group(1).strip()
            # Split by AND/OR for individual conditions
            conditions = re.split(r'\s+(AND|OR)\s+', where_clause, flags=re.IGNORECASE)
            where_clauses = [cond.strip() for cond in conditions if cond.strip() and cond.upper() not in ['AND', 'OR']]
        
        return where_clauses
    
    def _analyze_query_structure(self, query: str) -> List[str]:
        """Analyze query structure for optimization opportunities"""
        suggestions = []
        
        # Check for SELECT *
        if re.search(r'\bSELECT\s+\*\s+FROM', query, re.IGNORECASE):
            suggestions.append("Avoid SELECT * - specify only needed columns")
        
        # Check for missing LIMIT clause
        if (query.upper().startswith('SELECT') and 
            not re.search(r'\bLIMIT\s+\d+', query, re.IGNORECASE)):
            suggestions.append("Consider adding LIMIT clause for large result sets")
        
        # Check for subqueries that could be JOINs
        if re.search(r'\bSELECT.*\(SELECT.*\)', query, re.IGNORECASE | re.DOTALL):
            suggestions.append("Consider converting subqueries to JOINs for better performance")
        
        # Check for ORDER BY without index
        if (re.search(r'\bORDER\s+BY', query, re.IGNORECASE) and 
            not re.search(r'\bLIMIT\s+', query, re.IGNORECASE)):
            suggestions.append("ORDER BY without LIMIT may cause full table scans")
        
        # Check for LIKE with leading wildcard
        if re.search(r"LIKE\s+['\"]%.*%['\"]", query, re.IGNORECASE):
            suggestions.append("LIKE with leading wildcard prevents index usage")
        
        # Check for functions on indexed columns
        if re.search(r'\bWHERE\s+.*\b(UPPER|LOWER|SUBSTRING|DATE_FORMAT|YEAR|MONTH)\s*\(', query, re.IGNORECASE):
            suggestions.append("Functions on indexed columns prevent index usage")
        
        return suggestions
    
    def _check_missing_indexes(self, query: str) -> List[Dict[str, Any]]:
        """Check for missing indexes based on query patterns"""
        recommendations = []
        
        # Extract WHERE clauses
        where_clauses = self._extract_where_clauses(query)
        
        # Extract ORDER BY columns
        order_by_pattern = r'\bORDER\s+BY\s+(.*?)(?:\s+LIMIT|$)'
        order_match = re.search(order_by_pattern, query, re.IGNORECASE)
        order_columns = []
        if order_match:
            order_columns = [col.strip() for col in order_match.group(1).split(',')]
        
        # Extract JOIN conditions
        joins = self._extract_joins(query)
        
        # Analyze WHERE clauses for index opportunities
        for clause in where_clauses:
            # Extract column names from WHERE clause
            column_match = re.search(r'([`"]?\w+[`"]?)\s*(?:=|>|<|>=|<=|LIKE|IN)', clause)
            if column_match:
                column = column_match.group(1).strip('`"')
                table = self._get_table_for_column(query, column)
                
                if table:
                    recommendations.append({
                        'table': table,
                        'column': column,
                        'type': 'WHERE',
                        'reason': f"Column '{column}' used in WHERE clause"
                    })
        
        # Analyze ORDER BY columns
        for column in order_columns:
            column = column.strip('`"')
            table = self._get_table_for_column(query, column)
            
            if table:
                recommendations.append({
                    'table': table,
                    'column': column,
                    'type': 'ORDER_BY',
                    'reason': f"Column '{column}' used in ORDER BY clause"
                })
        
        # Analyze JOIN conditions
        for join in joins:
            # Extract columns from JOIN condition
            join_columns = re.findall(r'([`"]?\w+[`"]?)\s*=', join['condition'])
            for column in join_columns:
                column = column.strip('`"')
                table = self._get_table_for_column(query, column)
                
                if table:
                    recommendations.append({
                        'table': table,
                        'column': column,
                        'type': 'JOIN',
                        'reason': f"Column '{column}' used in JOIN condition"
                    })
        
        return recommendations
    
    def _get_table_for_column(self, query: str, column: str) -> Optional[str]:
        """Try to determine which table a column belongs to"""
        tables = self._extract_tables(query)
        
        # Simple heuristic: if only one table, column belongs to it
        if len(tables) == 1:
            return tables[0]
        
        # Check for table.column pattern in query
        table_column_pattern = rf'([`"]?(\w+)[`"]?)\.{re.escape(column)}'
        match = re.search(table_column_pattern, query)
        if match:
            return match.group(2)
        
        # Default to first table if uncertain
        return tables[0] if tables else None
    
    def _analyze_joins(self, query: str) -> List[str]:
        """Analyze JOIN performance"""
        suggestions = []
        joins = self._extract_joins(query)
        
        # Check for CROSS JOINs
        for join in joins:
            if join['type'] == 'CROSS':
                suggestions.append("CROSS JOIN can be expensive - consider INNER JOIN with explicit condition")
        
        # Check for multiple JOINs without proper indexing
        if len(joins) > 3:
            suggestions.append("Multiple JOINs detected - ensure all join columns are properly indexed")
        
        # Check for JOIN conditions without indexes
        for join in joins:
            if not re.search(r'[=<>!]', join['condition']):
                suggestions.append(f"JOIN condition '{join['condition']}' may not use indexes effectively")
        
        return suggestions
    
    def _check_n_plus_one(self, query: str) -> List[str]:
        """Check for potential N+1 query problems"""
        warnings = []
        
        # This is a simplified check - in practice, you'd need to analyze
        # the application code to detect N+1 problems
        if re.search(r'\bSELECT.*FROM.*WHERE.*IN\s*\(', query, re.IGNORECASE):
            warnings.append("Potential N+1 query pattern detected - consider using JOINs instead")
        
        return warnings
    
    def _estimate_query_cost(self, query: str) -> float:
        """Estimate query execution cost (simplified)"""
        cost = 1.0
        
        # Base cost by query type
        query_type = self._get_query_type(query)
        if query_type == 'SELECT':
            cost += 1.0
        elif query_type == 'INSERT':
            cost += 2.0
        elif query_type == 'UPDATE':
            cost += 3.0
        elif query_type == 'DELETE':
            cost += 3.0
        
        # Add cost for JOINs
        joins = self._extract_joins(query)
        cost += len(joins) * 2.0
        
        # Add cost for subqueries
        subqueries = len(re.findall(r'\(SELECT', query, re.IGNORECASE))
        cost += subqueries * 3.0
        
        # Add cost for complex WHERE clauses
        where_clauses = self._extract_where_clauses(query)
        cost += len(where_clauses) * 0.5
        
        # Add cost for ORDER BY
        if re.search(r'\bORDER\s+BY', query, re.IGNORECASE):
            cost += 1.5
        
        # Add cost for GROUP BY
        if re.search(r'\bGROUP\s+BY', query, re.IGNORECASE):
            cost += 2.0
        
        return cost
    
    def execute_optimized_query(self, query: str, params: Optional[tuple] = None,
                               fetch_one: bool = False, fetch_all: bool = False,
                               commit: bool = False) -> Any:
        """
        Execute query with automatic optimization
        
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
        
        # Check query cache
        cache_key = self._generate_cache_key(query, params)
        if cache_key in self._query_cache:
            self._performance_metrics['cache_hits'] += 1
            cached_result = self._query_cache[cache_key]
            logger.debug(f"Query cache hit for: {query[:50]}...")
            return cached_result
        
        self._performance_metrics['cache_misses'] += 1
        
        # Analyze query for optimization
        analysis = self.analyze_query(query, params)
        
        # Log optimization suggestions
        if analysis['optimization_suggestions']:
            logger.info(f"Query optimization suggestions: {analysis['optimization_suggestions']}")
        
        # Execute query
        try:
            result = db_pool_service.execute_query(
                query, params, fetch_one, fetch_all, commit
            )
            
            execution_time = time.time() - start_time
            
            # Update performance metrics
            self._performance_metrics['total_queries'] += 1
            if execution_time > 1.0:
                self._performance_metrics['slow_queries'] += 1
                self._log_slow_query(query, params, execution_time)
            
            # Cache result if appropriate
            if self._should_cache_query(query, result):
                self._query_cache[cache_key] = result
            
            return result
            
        except Exception as e:
            logger.error(f"Optimized query execution failed: {str(e)}")
            raise
    
    def _generate_cache_key(self, query: str, params: Optional[tuple]) -> str:
        """Generate cache key for query"""
        import hashlib
        
        # Normalize query
        normalized_query = re.sub(r'\s+', ' ', query.strip().upper())
        
        # Create hash
        key_data = normalized_query + str(params) if params else normalized_query
        return hashlib.md5(key_data.encode()).hexdigest()
    
    def _should_cache_query(self, query: str, result: Any) -> bool:
        """Determine if query result should be cached"""
        # Only cache SELECT queries
        if not query.strip().upper().startswith('SELECT'):
            return False
        
        # Don't cache large result sets
        if isinstance(result, list) and len(result) > 1000:
            return False
        
        # Don't cache queries with time-sensitive functions
        if re.search(r'\b(NOW|CURRENT_TIMESTAMP|CURRENT_DATE|CURRENT_TIME)\b', query, re.IGNORECASE):
            return False
        
        return True
    
    def _log_slow_query(self, query: str, params: Optional[tuple], execution_time: float):
        """Log slow query for analysis"""
        slow_query = {
            'query': query,
            'params': params,
            'execution_time': execution_time,
            'timestamp': datetime.utcnow().isoformat(),
            'analysis': self.analyze_query(query, params)
        }
        
        self._slow_query_log.append(slow_query)
        
        # Keep only last 100 slow queries
        if len(self._slow_query_log) > 100:
            self._slow_query_log.pop(0)
        
        logger.warning(f"Slow query detected ({execution_time:.3f}s): {query[:100]}...")
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get query performance metrics"""
        metrics = self._performance_metrics.copy()
        
        # Calculate cache hit ratio
        total_cache_requests = metrics['cache_hits'] + metrics['cache_misses']
        if total_cache_requests > 0:
            metrics['cache_hit_ratio'] = metrics['cache_hits'] / total_cache_requests
        else:
            metrics['cache_hit_ratio'] = 0.0
        
        # Calculate slow query ratio
        if metrics['total_queries'] > 0:
            metrics['slow_query_ratio'] = metrics['slow_queries'] / metrics['total_queries']
        else:
            metrics['slow_query_ratio'] = 0.0
        
        return metrics
    
    def get_slow_queries(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent slow queries"""
        return self._slow_query_log[-limit:]
    
    def get_index_recommendations(self) -> Dict[str, List[Dict[str, Any]]]:
        """Get index recommendations by table"""
        recommendations = defaultdict(list)
        
        # Collect recommendations from query analysis
        for cache_key, cached_result in self._query_cache.items():
            # This is a simplified approach - in practice, you'd
            # store analysis results with cached queries
            pass
        
        return dict(recommendations)
    
    def optimize_database(self) -> Dict[str, Any]:
        """
        Perform database optimization tasks
        
        Returns:
            Dictionary with optimization results
        """
        results = {
            'tables_optimized': [],
            'indexes_created': [],
            'errors': []
        }
        
        try:
            # Get list of tables
            tables_query = "SHOW TABLES"
            tables = db_pool_service.execute_query(tables_query, fetch_all=True)
            
            for table_info in tables:
                table_name = list(table_info.values())[0]
                
                try:
                    # Optimize table
                    if db_pool_service.optimize_table(table_name):
                        results['tables_optimized'].append(table_name)
                    
                    # Analyze table for index opportunities
                    self._analyze_table_indexes(table_name, results)
                    
                except Exception as e:
                    results['errors'].append(f"Error optimizing table {table_name}: {str(e)}")
            
            logger.info(f"Database optimization completed: {len(results['tables_optimized'])} tables optimized")
            
        except Exception as e:
            logger.error(f"Database optimization failed: {str(e)}")
            results['errors'].append(f"Optimization failed: {str(e)}")
        
        return results
    
    def _analyze_table_indexes(self, table_name: str, results: Dict[str, Any]):
        """Analyze table for missing indexes"""
        try:
            # Get table structure
            describe_query = f"DESCRIBE `{table_name}`"
            columns = db_pool_service.execute_query(describe_query, fetch_all=True)
            
            # Get existing indexes
            index_query = f"SHOW INDEX FROM `{table_name}`"
            existing_indexes = db_pool_service.execute_query(index_query, fetch_all=True)
            
            # Analyze for missing indexes (simplified)
            indexed_columns = set()
            for index in existing_indexes:
                indexed_columns.add(index['Column_name'])
            
            # Recommend indexes for commonly queried columns
            for column in columns:
                column_name = column['Field']
                
                # Skip if already indexed
                if column_name in indexed_columns:
                    continue
                
                # Recommend indexes for certain column types
                if (column['Key'] == '' and 
                    column_name.endswith('_id') or 
                    column_name.endswith('_code') or
                    column_name in ['email', 'username', 'status', 'created_at']):
                    
                    index_name = f"idx_{table_name}_{column_name}"
                    create_index_query = f"CREATE INDEX `{index_name}` ON `{table_name}` (`{column_name}`)"
                    
                    try:
                        db_pool_service.execute_query(create_index_query, commit=True)
                        results['indexes_created'].append({
                            'table': table_name,
                            'column': column_name,
                            'index': index_name
                        })
                        logger.info(f"Created index {index_name} on {table_name}.{column_name}")
                    except Exception as e:
                        logger.warning(f"Failed to create index {index_name}: {str(e)}")
            
        except Exception as e:
            logger.error(f"Error analyzing table indexes for {table_name}: {str(e)}")
            results['errors'].append(f"Index analysis failed for {table_name}: {str(e)}")
    
    def clear_cache(self):
        """Clear query cache"""
        self._query_cache.clear()
        logger.info("Query cache cleared")
    
    def reset_metrics(self):
        """Reset performance metrics"""
        self._performance_metrics = {
            'total_queries': 0,
            'optimized_queries': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'avg_execution_time': 0.0,
            'slow_queries': 0
        }
        logger.info("Performance metrics reset")


# Global query optimization service instance
query_optimization_service = QueryOptimizationService()