"""
Database Management API Routes

This module provides REST API endpoints for database connection pool management,
query optimization, performance monitoring, and database administration.
"""

import logging
from flask import Blueprint, request, jsonify, current_app
from functools import wraps
from services.database_pool_service import db_pool_service, with_db_connection, with_transaction
from services.query_optimization_service import query_optimization_service
from services.jwt_service import jwt_required, role_required, permission_required
from utils.enterprise_validators import validate_pagination, validate_sort_order

logger = logging.getLogger(__name__)

# Create blueprint
database_bp = Blueprint('database', __name__, url_prefix='/api/database')

def admin_required(f):
    """Decorator to require database admin permissions"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check for admin role or specific database permission
        if not (hasattr(request, 'user') and 
                (request.user.get('role') == 'admin' or 
                 'database_admin' in request.user.get('permissions', []))):
            return jsonify({'error': 'Database admin access required'}), 403
        return f(*args, **kwargs)
    return decorated_function

@database_bp.route('/pool/stats', methods=['GET'])
@jwt_required
@permission_required('database', 'view')
def get_pool_stats():
    """Get database connection pool statistics"""
    try:
        stats = db_pool_service.get_pool_stats()
        return jsonify({
            'success': True,
            'data': stats
        })
    except Exception as e:
        logger.error(f"Failed to get pool stats: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to retrieve pool statistics'
        }), 500

@database_bp.route('/pool/reset-stats', methods=['POST'])
@jwt_required
@admin_required
def reset_pool_stats():
    """Reset database connection pool statistics"""
    try:
        success = db_pool_service.reset_pool_stats()
        return jsonify({
            'success': success,
            'message': 'Pool statistics reset successfully'
        })
    except Exception as e:
        logger.error(f"Failed to reset pool stats: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to reset pool statistics'
        }), 500

@database_bp.route('/query/analyze', methods=['POST'])
@jwt_required
@permission_required('database', 'query')
def analyze_query():
    """Analyze a SQL query for optimization opportunities"""
    try:
        data = request.get_json()
        if not data or 'query' not in data:
            return jsonify({
                'success': False,
                'error': 'Query is required'
            }), 400
        
        query = data['query']
        params = data.get('params')
        
        # Analyze query
        analysis = query_optimization_service.analyze_query(query, params)
        
        return jsonify({
            'success': True,
            'data': analysis
        })
    except Exception as e:
        logger.error(f"Query analysis failed: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Query analysis failed'
        }), 500

@database_bp.route('/query/execute', methods=['POST'])
@jwt_required
@permission_required('database', 'query')
def execute_query():
    """Execute a SQL query with optimization"""
    try:
        data = request.get_json()
        if not data or 'query' not in data:
            return jsonify({
                'success': False,
                'error': 'Query is required'
            }), 400
        
        query = data['query']
        params = data.get('params')
        fetch_one = data.get('fetch_one', False)
        fetch_all = data.get('fetch_all', True)
        commit = data.get('commit', False)
        
        # Execute optimized query
        result = query_optimization_service.execute_optimized_query(
            query, params, fetch_one, fetch_all, commit
        )
        
        return jsonify({
            'success': True,
            'data': result
        })
    except Exception as e:
        logger.error(f"Query execution failed: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'Query execution failed: {str(e)}'
        }), 500

@database_bp.route('/query/batch', methods=['POST'])
@jwt_required
@permission_required('database', 'query')
def execute_batch():
    """Execute multiple queries in a batch"""
    try:
        data = request.get_json()
        if not data or 'queries' not in data:
            return jsonify({
                'success': False,
                'error': 'Queries array is required'
            }), 400
        
        queries = data['queries']
        if not isinstance(queries, list):
            return jsonify({
                'success': False,
                'error': 'Queries must be an array'
            }), 400
        
        # Execute batch
        results = db_pool_service.execute_batch(queries)
        
        return jsonify({
            'success': True,
            'data': results
        })
    except Exception as e:
        logger.error(f"Batch execution failed: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'Batch execution failed: {str(e)}'
        }), 500

@database_bp.route('/query/procedure', methods=['POST'])
@jwt_required
@permission_required('database', 'query')
def execute_procedure():
    """Execute a stored procedure"""
    try:
        data = request.get_json()
        if not data or 'procedure_name' not in data:
            return jsonify({
                'success': False,
                'error': 'Procedure name is required'
            }), 400
        
        procedure_name = data['procedure_name']
        params = data.get('params')
        
        # Execute procedure
        result = db_pool_service.execute_procedure(procedure_name, params)
        
        return jsonify({
            'success': True,
            'data': result
        })
    except Exception as e:
        logger.error(f"Procedure execution failed: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'Procedure execution failed: {str(e)}'
        }), 500

@database_bp.route('/performance/metrics', methods=['GET'])
@jwt_required
@permission_required('database', 'view')
def get_performance_metrics():
    """Get query performance metrics"""
    try:
        metrics = query_optimization_service.get_performance_metrics()
        return jsonify({
            'success': True,
            'data': metrics
        })
    except Exception as e:
        logger.error(f"Failed to get performance metrics: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to retrieve performance metrics'
        }), 500

@database_bp.route('/performance/slow-queries', methods=['GET'])
@jwt_required
@permission_required('database', 'view')
def get_slow_queries():
    """Get recent slow queries"""
    try:
        # Validate pagination parameters
        page, per_page = validate_pagination(request.args)
        limit = request.args.get('limit', per_page, type=int)
        
        slow_queries = query_optimization_service.get_slow_queries(limit)
        
        return jsonify({
            'success': True,
            'data': slow_queries,
            'count': len(slow_queries)
        })
    except Exception as e:
        logger.error(f"Failed to get slow queries: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to retrieve slow queries'
        }), 500

@database_bp.route('/performance/index-recommendations', methods=['GET'])
@jwt_required
@permission_required('database', 'view')
def get_index_recommendations():
    """Get index recommendations"""
    try:
        recommendations = query_optimization_service.get_index_recommendations()
        return jsonify({
            'success': True,
            'data': recommendations
        })
    except Exception as e:
        logger.error(f"Failed to get index recommendations: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to retrieve index recommendations'
        }), 500

@database_bp.route('/optimize', methods=['POST'])
@jwt_required
@admin_required
def optimize_database():
    """Perform database optimization"""
    try:
        results = query_optimization_service.optimize_database()
        return jsonify({
            'success': True,
            'data': results
        })
    except Exception as e:
        logger.error(f"Database optimization failed: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Database optimization failed'
        }), 500

@database_bp.route('/cache/clear', methods=['POST'])
@jwt_required
@admin_required
def clear_query_cache():
    """Clear query cache"""
    try:
        query_optimization_service.clear_cache()
        return jsonify({
            'success': True,
            'message': 'Query cache cleared successfully'
        })
    except Exception as e:
        logger.error(f"Failed to clear query cache: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to clear query cache'
        }), 500

@database_bp.route('/metrics/reset', methods=['POST'])
@jwt_required
@admin_required
def reset_metrics():
    """Reset performance metrics"""
    try:
        query_optimization_service.reset_metrics()
        return jsonify({
            'success': True,
            'message': 'Performance metrics reset successfully'
        })
    except Exception as e:
        logger.error(f"Failed to reset metrics: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to reset performance metrics'
        }), 500

@database_bp.route('/tables', methods=['GET'])
@jwt_required
@permission_required('database', 'view')
def get_tables():
    """Get list of database tables"""
    try:
        query = "SHOW TABLES"
        tables = db_pool_service.execute_query(query, fetch_all=True)
        
        # Get table information
        table_info = []
        for table in tables:
            table_name = list(table.values())[0]
            
            # Get table status
            status_query = f"SHOW TABLE STATUS LIKE '{table_name}'"
            status = db_pool_service.execute_query(status_query, fetch_one=True)
            
            if status:
                table_info.append({
                    'name': table_name,
                    'rows': status.get('Rows', 0),
                    'size': status.get('Data_length', 0) + status.get('Index_length', 0),
                    'engine': status.get('Engine'),
                    'collation': status.get('Collation'),
                    'created': status.get('Create_time'),
                    'updated': status.get('Update_time')
                })
        
        return jsonify({
            'success': True,
            'data': table_info
        })
    except Exception as e:
        logger.error(f"Failed to get tables: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to retrieve table list'
        }), 500

@database_bp.route('/tables/<table_name>/describe', methods=['GET'])
@jwt_required
@permission_required('database', 'view')
def describe_table(table_name):
    """Get table structure"""
    try:
        # Validate table name
        if not table_name.replace('_', '').isalnum():
            return jsonify({
                'success': False,
                'error': 'Invalid table name'
            }), 400
        
        # Get table structure
        describe_query = f"DESCRIBE `{table_name}`"
        columns = db_pool_service.execute_query(describe_query, fetch_all=True)
        
        # Get table indexes
        index_query = f"SHOW INDEX FROM `{table_name}`"
        indexes = db_pool_service.execute_query(index_query, fetch_all=True)
        
        # Group indexes by name
        index_groups = {}
        for index in indexes:
            index_name = index['Key_name']
            if index_name not in index_groups:
                index_groups[index_name] = {
                    'name': index_name,
                    'unique': index['Non_unique'] == 0,
                    'columns': []
                }
            index_groups[index_name]['columns'].append(index['Column_name'])
        
        return jsonify({
            'success': True,
            'data': {
                'table': table_name,
                'columns': columns,
                'indexes': list(index_groups.values())
            }
        })
    except Exception as e:
        logger.error(f"Failed to describe table {table_name}: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'Failed to describe table: {str(e)}'
        }), 500

@database_bp.route('/tables/<table_name>/optimize', methods=['POST'])
@jwt_required
@admin_required
def optimize_table(table_name):
    """Optimize a specific table"""
    try:
        # Validate table name
        if not table_name.replace('_', '').isalnum():
            return jsonify({
                'success': False,
                'error': 'Invalid table name'
            }), 400
        
        # Optimize table
        success = db_pool_service.optimize_table(table_name)
        
        if success:
            return jsonify({
                'success': True,
                'message': f'Table {table_name} optimized successfully'
            })
        else:
            return jsonify({
                'success': False,
                'error': f'Failed to optimize table {table_name}'
            }), 500
    except Exception as e:
        logger.error(f"Failed to optimize table {table_name}: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'Table optimization failed: {str(e)}'
        }), 500

@database_bp.route('/health', methods=['GET'])
@jwt_required
@permission_required('database', 'view')
def database_health():
    """Get database health status"""
    try:
        # Test database connection
        test_query = "SELECT 1 as test"
        result = db_pool_service.execute_query(test_query, fetch_one=True)
        
        # Get pool stats
        pool_stats = db_pool_service.get_pool_stats()
        
        # Get performance metrics
        perf_metrics = query_optimization_service.get_performance_metrics()
        
        # Determine health status
        health_status = 'healthy'
        issues = []
        
        if not result or result.get('test') != 1:
            health_status = 'unhealthy'
            issues.append('Database connection test failed')
        
        if pool_stats.get('pool_error_count', 0) > 0:
            health_status = 'degraded'
            issues.append('Pool errors detected')
        
        if perf_metrics.get('slow_query_ratio', 0) > 0.1:
            health_status = 'degraded'
            issues.append('High slow query ratio')
        
        return jsonify({
            'success': True,
            'data': {
                'status': health_status,
                'issues': issues,
                'pool_stats': pool_stats,
                'performance_metrics': perf_metrics,
                'timestamp': current_app.config.get('CURRENT_TIME')
            }
        })
    except Exception as e:
        logger.error(f"Database health check failed: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Database health check failed',
            'data': {
                'status': 'unhealthy',
                'issues': [str(e)]
            }
        }), 500

@database_bp.route('/backup', methods=['POST'])
@jwt_required
@admin_required
def create_backup():
    """Create database backup (placeholder)"""
    try:
        # This is a placeholder for backup functionality
        # In a real implementation, you would integrate with your backup system
        
        data = request.get_json() or {}
        backup_type = data.get('type', 'full')
        
        # Log backup request
        logger.info(f"Database backup requested: type={backup_type}")
        
        return jsonify({
            'success': True,
            'message': 'Backup request received',
            'data': {
                'backup_id': f"backup_{current_app.config.get('CURRENT_TIME')}",
                'type': backup_type,
                'status': 'initiated'
            }
        })
    except Exception as e:
        logger.error(f"Backup request failed: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Backup request failed'
        }), 500

@database_bp.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({
        'success': False,
        'error': 'Database management endpoint not found'
    }), 404

@database_bp.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    logger.error(f"Database management internal error: {str(error)}")
    return jsonify({
        'success': False,
        'error': 'Internal server error in database management'
    }), 500