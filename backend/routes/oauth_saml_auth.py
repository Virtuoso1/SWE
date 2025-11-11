from flask import Blueprint, request, jsonify, session, redirect, url_for, make_response
from flask_cors import cross_origin
from services.oauth_service import oauth_service
from services.saml_service import saml_service
from services.jwt_service import JWTService
from utils.security import get_client_ip
import logging

# Configure logging
logger = logging.getLogger(__name__)

# Create blueprint
oauth_saml_bp = Blueprint('oauth_saml', __name__, url_prefix='/auth')

@oauth_saml_bp.route('/oauth/<provider_name>', methods=['GET'])
@cross_origin(supports_credentials=True)
def oauth_authorize(provider_name):
    """
    Start OAuth authorization flow
    
    Args:
        provider_name: OAuth provider name (google, microsoft, github)
        
    Returns:
        Redirect to OAuth provider
    """
    try:
        # Generate state parameter for CSRF protection
        state = secrets.token_urlsafe(32)
        session['oauth_state'] = state
        session['oauth_provider'] = provider_name
        
        # Get authorization URL
        auth_url = oauth_service.authorize(provider_name)
        
        if auth_url:
            return redirect(auth_url)
        else:
            return jsonify({
                'success': False,
                'message': f'OAuth provider {provider_name} not supported',
                'error_code': 'PROVIDER_NOT_SUPPORTED'
            }), 400
            
    except Exception as e:
        logger.error(f"OAuth authorization error for {provider_name}: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'An error occurred during OAuth authorization',
            'error_code': 'OAUTH_ERROR'
        }), 500

@oauth_saml_bp.route('/oauth/<provider_name>/callback', methods=['GET'])
@cross_origin(supports_credentials=True)
def oauth_callback(provider_name):
    """
    Handle OAuth callback
    
    Args:
        provider_name: OAuth provider name
        
    Returns:
        Authentication result or error
    """
    try:
        # Verify state parameter
        state = request.args.get('state')
        if not state or state != session.get('oauth_state'):
            return jsonify({
                'success': False,
                'message': 'Invalid state parameter',
                'error_code': 'INVALID_STATE'
            }), 400
        
        # Clear state from session
        session.pop('oauth_state', None)
        session.pop('oauth_provider', None)
        
        # Handle OAuth callback
        result = oauth_service.handle_callback(provider_name)
        
        if result and result.get('status') == 'success':
            # Create response with secure cookies
            response = make_response(redirect(url_for('dashboard.index')))
            
            # Set secure HTTP-only cookies
            from flask import current_app
            config = current_app.config
            
            # Access token cookie
            response.set_cookie(
                config.JWT_ACCESS_COOKIE_NAME,
                result['tokens']['access_token'],
                max_age=config.JWT_ACCESS_TOKEN_EXPIRES * 60,
                httponly=config.JWT_COOKIE_HTTPONLY,
                secure=config.JWT_COOKIE_SECURE,
                samesite=config.JWT_COOKIE_SAMESITE,
                path='/'
            )
            
            # Refresh token cookie
            response.set_cookie(
                config.JWT_REFRESH_COOKIE_NAME,
                result['tokens']['refresh_token'],
                max_age=config.JWT_REFRESH_TOKEN_EXPIRES * 24 * 60 * 60,
                httponly=config.JWT_COOKIE_HTTPONLY,
                secure=config.JWT_COOKIE_SECURE,
                samesite=config.JWT_COOKIE_SAMESITE,
                path='/'
            )
            
            return response
        else:
            return jsonify({
                'success': False,
                'message': 'OAuth authentication failed',
                'error_code': 'OAUTH_FAILED'
            }), 400
            
    except Exception as e:
        logger.error(f"OAuth callback error for {provider_name}: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'An error occurred during OAuth callback',
            'error_code': 'OAUTH_CALLBACK_ERROR'
        }), 500

@oauth_saml_bp.route('/saml/<provider_name>/login', methods=['GET'])
@cross_origin(supports_credentials=True)
def saml_login(provider_name):
    """
    Start SAML authentication flow
    
    Args:
        provider_name: SAML provider name
        
    Returns:
        Redirect to SAML provider
    """
    try:
        # Generate relay state for CSRF protection
        relay_state = secrets.token_urlsafe(32)
        session['saml_state'] = relay_state
        session['saml_provider'] = provider_name
        
        # Get SAML authorization URL
        auth_url = saml_service.create_auth_request(provider_name, relay_state)
        
        if auth_url:
            return redirect(auth_url)
        else:
            return jsonify({
                'success': False,
                'message': f'SAML provider {provider_name} not supported',
                'error_code': 'PROVIDER_NOT_SUPPORTED'
            }), 400
            
    except Exception as e:
        logger.error(f"SAML login error for {provider_name}: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'An error occurred during SAML login',
            'error_code': 'SAML_ERROR'
        }), 500

@oauth_saml_bp.route('/saml/acs', methods=['POST'])
@cross_origin(supports_credentials=True)
def saml_acs():
    """
    SAML Assertion Consumer Service - handles SAML response
    
    Returns:
        Authentication result or error
    """
    try:
        # Get SAML response from form data
        saml_response = request.form.get('SAMLResponse')
        if not saml_response:
            return jsonify({
                'success': False,
                'message': 'SAML response missing',
                'error_code': 'MISSING_SAML_RESPONSE'
            }), 400
        
        # Get provider from session
        provider_name = session.get('saml_provider')
        if not provider_name:
            return jsonify({
                'success': False,
                'message': 'SAML provider not found in session',
                'error_code': 'MISSING_PROVIDER'
            }), 400
        
        # Clear provider from session
        session.pop('saml_state', None)
        session.pop('saml_provider', None)
        
        # Process SAML response
        result = saml_service.process_response(provider_name, saml_response)
        
        if result and result.get('status') == 'success':
            # Create response with secure cookies
            response = make_response(redirect(url_for('dashboard.index')))
            
            # Set secure HTTP-only cookies
            from flask import current_app
            config = current_app.config
            
            # Access token cookie
            response.set_cookie(
                config.JWT_ACCESS_COOKIE_NAME,
                result['tokens']['access_token'],
                max_age=config.JWT_ACCESS_TOKEN_EXPIRES * 60,
                httponly=config.JWT_COOKIE_HTTPONLY,
                secure=config.JWT_COOKIE_SECURE,
                samesite=config.JWT_COOKIE_SAMESITE,
                path='/'
            )
            
            # Refresh token cookie
            response.set_cookie(
                config.JWT_REFRESH_COOKIE_NAME,
                result['tokens']['refresh_token'],
                max_age=config.JWT_REFRESH_TOKEN_EXPIRES * 24 * 60 * 60,
                httponly=config.JWT_COOKIE_HTTPONLY,
                secure=config.JWT_COOKIE_SECURE,
                samesite=config.JWT_COOKIE_SAMESITE,
                path='/'
            )
            
            return response
        else:
            return jsonify({
                'success': False,
                'message': 'SAML authentication failed',
                'error_code': 'SAML_FAILED'
            }), 400
            
    except Exception as e:
        logger.error(f"SAML ACS error: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'An error occurred during SAML authentication',
            'error_code': 'SAML_ACS_ERROR'
        }), 500

@oauth_saml_bp.route('/saml/sls', methods=['POST'])
@cross_origin(supports_credentials=True)
def saml_sls():
    """
    SAML Single Logout Service - handles SAML logout request
    
    Returns:
        Logout response
    """
    try:
        # Get SAML logout request
        saml_request = request.form.get('SAMLRequest')
        if not saml_request:
            return jsonify({
                'success': False,
                'message': 'SAML logout request missing',
                'error_code': 'MISSING_SAML_REQUEST'
            }), 400
        
        # Get provider from request or use default
        provider_name = request.args.get('provider', 'default')
        
        # Process SAML logout request
        # This would typically redirect to IdP logout
        # For now, return success response
        return jsonify({
            'success': True,
            'message': 'SAML logout processed'
        }), 200
            
    except Exception as e:
        logger.error(f"SAML SLS error: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'An error occurred during SAML logout',
            'error_code': 'SAML_SLS_ERROR'
        }), 500

@oauth_saml_bp.route('/saml/metadata', methods=['GET'])
@cross_origin(supports_credentials=True)
def saml_metadata():
    """
    Generate SAML service provider metadata
    
    Returns:
        SAML metadata XML
    """
    try:
        metadata = saml_service.generate_metadata()
        
        if metadata:
            from flask import Response
            return Response(metadata, mimetype='application/xml')
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to generate SAML metadata',
                'error_code': 'METADATA_ERROR'
            }), 500
            
    except Exception as e:
        logger.error(f"SAML metadata error: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'An error occurred while generating SAML metadata',
            'error_code': 'METADATA_GENERATION_ERROR'
        }), 500

@oauth_saml_bp.route('/linked-accounts', methods=['GET'])
@cross_origin(supports_credentials=True)
def get_linked_accounts():
    """
    Get all linked OAuth and SAML accounts for current user
    
    Returns:
        List of linked accounts
    """
    try:
        # Get user from JWT token
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({
                'success': False,
                'message': 'Authorization required',
                'error_code': 'AUTHORIZATION_REQUIRED'
            }), 401
        
        try:
            token = auth_header.split(' ')[1]
        except IndexError:
            return jsonify({
                'success': False,
                'message': 'Invalid authorization header format',
                'error_code': 'INVALID_AUTH_HEADER'
            }), 400
        
        # Verify token
        payload = JWTService.verify_access_token(token)
        if not payload:
            return jsonify({
                'success': False,
                'message': 'Invalid or expired access token',
                'error_code': 'INVALID_TOKEN'
            }), 401
        
        user_id = payload['user_id']
        
        # Get linked OAuth accounts
        oauth_accounts = oauth_service.get_linked_oauth_accounts(user_id)
        
        # Get linked SAML accounts
        saml_accounts = saml_service.get_linked_saml_accounts(user_id)
        
        return jsonify({
            'success': True,
            'oauth_accounts': oauth_accounts,
            'saml_accounts': saml_accounts
        }), 200
        
    except Exception as e:
        logger.error(f"Get linked accounts error: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'An error occurred while fetching linked accounts',
            'error_code': 'LINKED_ACCOUNTS_ERROR'
        }), 500

@oauth_saml_bp.route('/unlink/<provider_type>/<provider_name>', methods=['POST'])
@cross_origin(supports_credentials=True)
def unlink_account(provider_type, provider_name):
    """
    Unlink OAuth or SAML account
    
    Args:
        provider_type: 'oauth' or 'saml'
        provider_name: Provider name
        
    Returns:
        Unlink result
    """
    try:
        # Get user from JWT token
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({
                'success': False,
                'message': 'Authorization required',
                'error_code': 'AUTHORIZATION_REQUIRED'
            }), 401
        
        try:
            token = auth_header.split(' ')[1]
        except IndexError:
            return jsonify({
                'success': False,
                'message': 'Invalid authorization header format',
                'error_code': 'INVALID_AUTH_HEADER'
            }), 400
        
        # Verify token
        payload = JWTService.verify_access_token(token)
        if not payload:
            return jsonify({
                'success': False,
                'message': 'Invalid or expired access token',
                'error_code': 'INVALID_TOKEN'
            }), 401
        
        user_id = payload['user_id']
        
        # Unlink account based on type
        if provider_type == 'oauth':
            success = oauth_service.unlink_oauth_account(user_id, provider_name)
        elif provider_type == 'saml':
            success = saml_service.unlink_saml_account(user_id, provider_name)
        else:
            return jsonify({
                'success': False,
                'message': 'Invalid provider type',
                'error_code': 'INVALID_PROVIDER_TYPE'
            }), 400
        
        if success:
            return jsonify({
                'success': True,
                'message': f'{provider_name.title()} account unlinked successfully'
            }), 200
        else:
            return jsonify({
                'success': False,
                'message': f'Failed to unlink {provider_name.title()} account',
                'error_code': 'UNLINK_FAILED'
            }), 500
        
    except Exception as e:
        logger.error(f"Unlink account error: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'An error occurred while unlinking account',
            'error_code': 'UNLINK_ERROR'
        }), 500

@oauth_saml_bp.route('/providers', methods=['GET'])
@cross_origin(supports_credentials=True)
def get_providers():
    """
    Get list of available OAuth and SAML providers
    
    Returns:
        List of available providers
    """
    try:
        # Get OAuth providers
        oauth_providers = []
        if hasattr(oauth_service, 'oauth'):
            for provider_name in ['google', 'microsoft', 'github']:
                if oauth_service.oauth.create_client(provider_name):
                    oauth_providers.append({
                        'name': provider_name,
                        'display_name': provider_name.title(),
                        'type': 'oauth',
                        'url': url_for('oauth_saml.oauth_authorize', provider_name=provider_name, _external=True)
                    })
        
        # Get SAML providers
        saml_providers = []
        if hasattr(saml_service, 'providers'):
            for provider_name, config in saml_service.providers.items():
                saml_providers.append({
                    'name': provider_name,
                    'display_name': config['display_name'],
                    'type': 'saml',
                    'url': url_for('oauth_saml.saml_login', provider_name=provider_name, _external=True)
                })
        
        return jsonify({
            'success': True,
            'oauth_providers': oauth_providers,
            'saml_providers': saml_providers
        }), 200
        
    except Exception as e:
        logger.error(f"Get providers error: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'An error occurred while fetching providers',
            'error_code': 'PROVIDERS_ERROR'
        }), 500