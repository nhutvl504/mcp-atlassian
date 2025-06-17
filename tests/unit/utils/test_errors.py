"""
Unit tests for error handling utilities.
"""

import json
import pytest
from unittest.mock import Mock
from requests.exceptions import HTTPError, ConnectionError, Timeout

from mcp_atlassian.utils.errors import (
    ErrorCode,
    MCPError,
    create_error_response,
    categorize_exception,
    map_http_status_to_error_code,
)


class TestErrorCode:
    """Test error code enum."""
    
    def test_error_code_values(self):
        """Test that error codes have expected values."""
        assert ErrorCode.AUTH_INVALID_CREDENTIALS.value == "AUTH_001"
        assert ErrorCode.NOT_FOUND_PAGE.value == "NOT_FOUND_001"
        assert ErrorCode.VALIDATION_MISSING_PARAMETER.value == "VALIDATION_001"
        assert ErrorCode.NETWORK_CONNECTION_ERROR.value == "NETWORK_001"
        assert ErrorCode.SERVER_INTERNAL_ERROR.value == "SERVER_001"


class TestMapHTTPStatusToErrorCode:
    """Test HTTP status code mapping."""
    
    def test_common_status_codes(self):
        """Test mapping of common HTTP status codes."""
        assert map_http_status_to_error_code(400) == ErrorCode.VALIDATION_INVALID_PARAMETER
        assert map_http_status_to_error_code(401) == ErrorCode.AUTH_INVALID_CREDENTIALS
        assert map_http_status_to_error_code(403) == ErrorCode.AUTH_INSUFFICIENT_PERMISSIONS
        assert map_http_status_to_error_code(404) == ErrorCode.NOT_FOUND_PAGE
        assert map_http_status_to_error_code(409) == ErrorCode.OPERATION_CONFLICT
        assert map_http_status_to_error_code(429) == ErrorCode.SERVER_RATE_LIMITED
        assert map_http_status_to_error_code(500) == ErrorCode.SERVER_INTERNAL_ERROR
        assert map_http_status_to_error_code(502) == ErrorCode.SERVER_BAD_GATEWAY
        assert map_http_status_to_error_code(503) == ErrorCode.SERVER_SERVICE_UNAVAILABLE
        assert map_http_status_to_error_code(504) == ErrorCode.NETWORK_TIMEOUT
    
    def test_unknown_status_code(self):
        """Test mapping of unknown status codes."""
        assert map_http_status_to_error_code(999) == ErrorCode.UNKNOWN_ERROR


class TestCategorizeException:
    """Test exception categorization."""
    
    def test_http_error_with_response(self):
        """Test HTTPError with response."""
        response = Mock()
        response.status_code = 404
        http_error = HTTPError("Not Found", response=response)
        
        assert categorize_exception(http_error) == ErrorCode.NOT_FOUND_PAGE
    
    def test_http_error_without_response(self):
        """Test HTTPError without response."""
        http_error = HTTPError("Generic HTTP Error")
        
        assert categorize_exception(http_error) == ErrorCode.SERVER_INTERNAL_ERROR
    
    def test_connection_error(self):
        """Test ConnectionError."""
        conn_error = ConnectionError("Connection failed")
        
        assert categorize_exception(conn_error) == ErrorCode.NETWORK_CONNECTION_ERROR
    
    def test_timeout_error(self):
        """Test Timeout error."""
        timeout_error = Timeout("Request timeout")
        
        assert categorize_exception(timeout_error) == ErrorCode.NETWORK_TIMEOUT
    
    def test_value_error(self):
        """Test ValueError."""
        value_error = ValueError("Invalid parameter")
        
        assert categorize_exception(value_error) == ErrorCode.VALIDATION_INVALID_PARAMETER
    
    def test_unknown_exception(self):
        """Test unknown exception type."""
        runtime_error = RuntimeError("Unknown error")
        
        assert categorize_exception(runtime_error) == ErrorCode.UNKNOWN_ERROR


class TestMCPError:
    """Test MCPError class."""
    
    def test_basic_error_creation(self):
        """Test basic error creation."""
        error = MCPError(
            code=ErrorCode.NOT_FOUND_PAGE,
            message="Page not found"
        )
        
        assert error.code == ErrorCode.NOT_FOUND_PAGE
        assert error.message == "Page not found"
        assert error.details == {}
        assert error.suggestion is None
    
    def test_error_with_details_and_suggestion(self):
        """Test error with details and suggestion."""
        details = {"page_id": "123", "space_key": "TEST"}
        suggestion = "Please verify the page ID"
        
        error = MCPError(
            code=ErrorCode.NOT_FOUND_PAGE,
            message="Page not found",
            details=details,
            suggestion=suggestion
        )
        
        assert error.details == details
        assert error.suggestion == suggestion
    
    def test_to_dict(self):
        """Test error conversion to dictionary."""
        error = MCPError(
            code=ErrorCode.NOT_FOUND_PAGE,
            message="Page not found",
            details={"page_id": "123"},
            suggestion="Check the page ID"
        )
        
        result = error.to_dict()
        
        assert result["error"]["code"] == "NOT_FOUND_001"
        assert result["error"]["message"] == "Page not found"
        assert result["error"]["category"] == "Resource Not Found"
        assert result["error"]["details"]["page_id"] == "123"
        assert result["error"]["suggestion"] == "Check the page ID"
        assert "timestamp" in result["error"]
    
    def test_to_json(self):
        """Test error conversion to JSON."""
        error = MCPError(
            code=ErrorCode.VALIDATION_MISSING_PARAMETER,
            message="Missing parameter"
        )
        
        json_str = error.to_json()
        parsed = json.loads(json_str)
        
        assert parsed["error"]["code"] == "VALIDATION_001"
        assert parsed["error"]["message"] == "Missing parameter"
        assert parsed["error"]["category"] == "Validation"
    
    def test_category_mapping(self):
        """Test error category mapping."""
        test_cases = [
            (ErrorCode.AUTH_INVALID_CREDENTIALS, "Authentication"),
            (ErrorCode.NOT_FOUND_PAGE, "Resource Not Found"),
            (ErrorCode.VALIDATION_MISSING_PARAMETER, "Validation"),
            (ErrorCode.NETWORK_CONNECTION_ERROR, "Network"),
            (ErrorCode.SERVER_INTERNAL_ERROR, "Server"),
            (ErrorCode.CONTENT_TOO_LARGE, "Content"),
            (ErrorCode.OPERATION_CONFLICT, "Operation"),
            (ErrorCode.UNKNOWN_ERROR, "Unknown"),
        ]
        
        for error_code, expected_category in test_cases:
            error = MCPError(code=error_code, message="Test message")
            assert error._get_category() == expected_category
    
    def test_http_error_status_included(self):
        """Test that HTTP status is included for HTTPError."""
        response = Mock()
        response.status_code = 403
        http_error = HTTPError("Forbidden", response=response)
        
        error = MCPError(
            code=ErrorCode.AUTH_INSUFFICIENT_PERMISSIONS,
            message="Access denied",
            original_exception=http_error
        )
        
        result = error.to_dict()
        assert result["error"]["http_status"] == 403


class TestCreateErrorResponse:
    """Test create_error_response function."""
    
    def test_basic_error_response(self):
        """Test basic error response creation."""
        exception = ValueError("Invalid input")
        
        response = create_error_response(
            exception=exception,
            context="validating parameters"
        )
        
        parsed = json.loads(response)
        assert parsed["error"]["code"] == "VALIDATION_002"
        assert "validating parameters" in parsed["error"]["message"]
        assert "Invalid input" in parsed["error"]["message"]
        assert parsed["error"]["category"] == "Validation"
    
    def test_custom_error_code_and_message(self):
        """Test with custom error code and message."""
        exception = RuntimeError("Something went wrong")
        
        response = create_error_response(
            exception=exception,
            context="processing data",
            error_code=ErrorCode.CONTENT_PROCESSING_ERROR,
            custom_message="Failed to process content",
            details={"file_size": "10MB"},
            suggestion="Try with a smaller file"
        )
        
        parsed = json.loads(response)
        assert parsed["error"]["code"] == "CONTENT_003"
        assert parsed["error"]["message"] == "Failed to process content"
        assert parsed["error"]["details"]["file_size"] == "10MB"
        assert parsed["error"]["suggestion"] == "Try with a smaller file"
    
    def test_http_error_response(self):
        """Test HTTP error response."""
        response_mock = Mock()
        response_mock.status_code = 404
        http_error = HTTPError("Not Found", response=response_mock)
        
        response = create_error_response(
            exception=http_error,
            context="fetching page",
            details={"page_id": "123456"}
        )
        
        parsed = json.loads(response)
        assert parsed["error"]["code"] == "NOT_FOUND_001"
        assert parsed["error"]["http_status"] == 404
        assert parsed["error"]["details"]["page_id"] == "123456"
        assert "The page may have been deleted" in parsed["error"]["suggestion"]
    
    def test_default_suggestions(self):
        """Test that default suggestions are provided."""
        test_cases = [
            (ErrorCode.AUTH_INVALID_CREDENTIALS, "check your API token"),
            (ErrorCode.AUTH_INSUFFICIENT_PERMISSIONS, "api token"),
            (ErrorCode.NOT_FOUND_PAGE, "page may have been deleted"),
            (ErrorCode.VALIDATION_MISSING_PARAMETER, "provide all required parameters"),
            (ErrorCode.NETWORK_CONNECTION_ERROR, "check your network connection"),
            (ErrorCode.SERVER_RATE_LIMITED, "Too many requests"),
        ]
        
        for error_code, expected_text in test_cases:
            exception = RuntimeError("Test error")
            response = create_error_response(
                exception=exception,
                context="testing",
                error_code=error_code
            )
            
            parsed = json.loads(response)
            suggestion = parsed["error"]["suggestion"].lower()
            assert expected_text.lower() in suggestion
    
    def test_mcp_atlassian_authentication_error(self):
        """Test MCPAtlassianAuthenticationError categorization."""
        try:
            from mcp_atlassian.exceptions import MCPAtlassianAuthenticationError
            
            auth_error = MCPAtlassianAuthenticationError("Authentication failed")
            error_code = categorize_exception(auth_error)
            
            assert error_code == ErrorCode.AUTH_INSUFFICIENT_PERMISSIONS
        except ImportError:
            pytest.skip("MCPAtlassianAuthenticationError not available") 