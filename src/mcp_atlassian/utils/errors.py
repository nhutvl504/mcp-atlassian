"""
Error handling utilities for MCP Atlassian tools.
Provides structured error responses with error codes and detailed information.
"""

import json
import logging
from enum import Enum
from typing import Any, Dict, Optional
from requests.exceptions import HTTPError, ConnectionError, Timeout


logger = logging.getLogger("mcp-atlassian.errors")


class ErrorCode(Enum):
    """Standard error codes for MCP Atlassian tools."""
    
    # Authentication & Authorization Errors (AUTH_xxx)
    AUTH_INVALID_CREDENTIALS = "AUTH_001"
    AUTH_EXPIRED_TOKEN = "AUTH_002"
    AUTH_INSUFFICIENT_PERMISSIONS = "AUTH_003"
    AUTH_CONFIGURATION_ERROR = "AUTH_004"
    
    # Resource Not Found Errors (NOT_FOUND_xxx)
    NOT_FOUND_PAGE = "NOT_FOUND_001"
    NOT_FOUND_SPACE = "NOT_FOUND_002"
    NOT_FOUND_USER = "NOT_FOUND_003"
    NOT_FOUND_ISSUE = "NOT_FOUND_004"
    NOT_FOUND_PROJECT = "NOT_FOUND_005"
    NOT_FOUND_COMMENT = "NOT_FOUND_006"
    
    # Validation Errors (VALIDATION_xxx)
    VALIDATION_MISSING_PARAMETER = "VALIDATION_001"
    VALIDATION_INVALID_PARAMETER = "VALIDATION_002"
    VALIDATION_PARAMETER_FORMAT = "VALIDATION_003"
    VALIDATION_PARAMETER_RANGE = "VALIDATION_004"
    
    # Network & Connection Errors (NETWORK_xxx)
    NETWORK_CONNECTION_ERROR = "NETWORK_001"
    NETWORK_TIMEOUT = "NETWORK_002"
    NETWORK_DNS_ERROR = "NETWORK_003"
    NETWORK_SSL_ERROR = "NETWORK_004"
    
    # Server Errors (SERVER_xxx)
    SERVER_INTERNAL_ERROR = "SERVER_001"
    SERVER_SERVICE_UNAVAILABLE = "SERVER_002"
    SERVER_BAD_GATEWAY = "SERVER_003"
    SERVER_RATE_LIMITED = "SERVER_004"
    
    # Content Errors (CONTENT_xxx)
    CONTENT_TOO_LARGE = "CONTENT_001"
    CONTENT_INVALID_FORMAT = "CONTENT_002"
    CONTENT_PROCESSING_ERROR = "CONTENT_003"
    
    # Operation Errors (OPERATION_xxx)
    OPERATION_CONFLICT = "OPERATION_001"
    OPERATION_FAILED = "OPERATION_002"
    OPERATION_NOT_SUPPORTED = "OPERATION_003"
    
    # Generic Errors
    UNKNOWN_ERROR = "UNKNOWN_001"


def map_http_status_to_error_code(status_code: int) -> ErrorCode:
    """Map HTTP status codes to appropriate error codes."""
    mapping = {
        400: ErrorCode.VALIDATION_INVALID_PARAMETER,
        401: ErrorCode.AUTH_INVALID_CREDENTIALS,
        403: ErrorCode.AUTH_INSUFFICIENT_PERMISSIONS,
        404: ErrorCode.NOT_FOUND_PAGE,  # Generic not found, can be overridden
        409: ErrorCode.OPERATION_CONFLICT,
        413: ErrorCode.CONTENT_TOO_LARGE,
        429: ErrorCode.SERVER_RATE_LIMITED,
        500: ErrorCode.SERVER_INTERNAL_ERROR,
        502: ErrorCode.SERVER_BAD_GATEWAY,
        503: ErrorCode.SERVER_SERVICE_UNAVAILABLE,
        504: ErrorCode.NETWORK_TIMEOUT,
    }
    return mapping.get(status_code, ErrorCode.UNKNOWN_ERROR)


def categorize_exception(exception: Exception) -> ErrorCode:
    """Automatically categorize exceptions to appropriate error codes."""
    # Import here to avoid circular imports
    try:
        from mcp_atlassian.exceptions import MCPAtlassianAuthenticationError
        if isinstance(exception, MCPAtlassianAuthenticationError):
            return ErrorCode.AUTH_INSUFFICIENT_PERMISSIONS
    except ImportError:
        pass  # Module not available, continue with other checks
    
    if isinstance(exception, HTTPError):
        if hasattr(exception, 'response') and exception.response is not None:
            return map_http_status_to_error_code(exception.response.status_code)
        return ErrorCode.SERVER_INTERNAL_ERROR
    elif isinstance(exception, ConnectionError):
        return ErrorCode.NETWORK_CONNECTION_ERROR
    elif isinstance(exception, Timeout):
        return ErrorCode.NETWORK_TIMEOUT
    elif isinstance(exception, ValueError):
        return ErrorCode.VALIDATION_INVALID_PARAMETER
    else:
        return ErrorCode.UNKNOWN_ERROR


class MCPError:
    """Structured error response for MCP tools."""
    
    def __init__(
        self,
        code: ErrorCode,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        suggestion: Optional[str] = None,
        original_exception: Optional[Exception] = None
    ):
        self.code = code
        self.message = message
        self.details = details or {}
        self.suggestion = suggestion
        self.original_exception = original_exception
        
        # Log the error
        logger.error(
            f"MCP Error [{code.value}]: {message}",
            extra={
                "error_code": code.value,
                "details": details,
                "suggestion": suggestion
            },
            exc_info=original_exception is not None
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert error to dictionary format."""
        error_dict = {
            "error": {
                "code": self.code.value,
                "message": self.message,
                "category": self._get_category(),
                "timestamp": self._get_timestamp()
            }
        }
        
        if self.details:
            error_dict["error"]["details"] = self.details
            
        if self.suggestion:
            error_dict["error"]["suggestion"] = self.suggestion
            
        # Add HTTP status for debugging
        if isinstance(self.original_exception, HTTPError):
            if hasattr(self.original_exception, 'response') and self.original_exception.response is not None:
                error_dict["error"]["http_status"] = self.original_exception.response.status_code
                
        return error_dict
    
    def to_json(self) -> str:
        """Convert error to JSON string."""
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)
    
    def _get_category(self) -> str:
        """Get error category from error code."""
        code_value = self.code.value
        if code_value.startswith("AUTH_"):
            return "Authentication"
        elif code_value.startswith("NOT_FOUND_"):
            return "Resource Not Found"
        elif code_value.startswith("VALIDATION_"):
            return "Validation"
        elif code_value.startswith("NETWORK_"):
            return "Network"
        elif code_value.startswith("SERVER_"):
            return "Server"
        elif code_value.startswith("CONTENT_"):
            return "Content"
        elif code_value.startswith("OPERATION_"):
            return "Operation"
        else:
            return "Unknown"
    
    def _get_timestamp(self) -> str:
        """Get current timestamp in ISO format."""
        from datetime import datetime
        return datetime.utcnow().isoformat() + "Z"


def create_error_response(
    exception: Exception,
    context: str,
    error_code: Optional[ErrorCode] = None,
    custom_message: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    suggestion: Optional[str] = None
) -> str:
    """
    Create a standardized error response from an exception.
    
    Args:
        exception: The original exception
        context: Context description (e.g., "fetching page", "creating issue")
        error_code: Override automatic error code detection
        custom_message: Override automatic message generation
        details: Additional error details
        suggestion: Helpful suggestion for the user
        
    Returns:
        JSON string with structured error response
    """
    # Determine error code
    if error_code is None:
        error_code = categorize_exception(exception)
    
    # Generate message
    if custom_message:
        message = custom_message
    else:
        message = f"Failed {context}: {str(exception)}"
    
    # Add default suggestions based on error type
    if suggestion is None:
        suggestion = _get_default_suggestion(error_code)
    
    # Create and return error
    error = MCPError(
        code=error_code,
        message=message,
        details=details,
        suggestion=suggestion,
        original_exception=exception
    )
    
    return error.to_json()


def _get_default_suggestion(error_code: ErrorCode) -> str:
    """Get default suggestion based on error code."""
    suggestions = {
        ErrorCode.AUTH_INVALID_CREDENTIALS: "Please check your API token or credentials and try again.",
        ErrorCode.AUTH_EXPIRED_TOKEN: "Your access token may have expired. Please refresh your token.",
        ErrorCode.AUTH_INSUFFICIENT_PERMISSIONS: "Please check your API token and ensure it has proper permissions. For PAT tokens, verify they are valid and not expired.",
        ErrorCode.NOT_FOUND_PAGE: "The page may have been deleted or moved. Please verify the page ID or title.",
        ErrorCode.NOT_FOUND_SPACE: "The space may not exist or you don't have access to it. Please verify the space key.",
        ErrorCode.NOT_FOUND_USER: "The user may not exist or you don't have permission to view their details.",
        ErrorCode.VALIDATION_MISSING_PARAMETER: "Please provide all required parameters.",
        ErrorCode.VALIDATION_INVALID_PARAMETER: "Please check parameter values and formats.",
        ErrorCode.NETWORK_CONNECTION_ERROR: "Please check your network connection and server URL.",
        ErrorCode.NETWORK_TIMEOUT: "The request timed out. Please try again or check server status.",
        ErrorCode.SERVER_RATE_LIMITED: "Too many requests. Please wait before making more requests.",
    }
    
    return suggestions.get(error_code, "Please check the error details and try again.") 