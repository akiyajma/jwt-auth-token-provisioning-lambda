import os
import json
import pytest
import requests_mock
import jwt
import base64
from unittest.mock import patch
from app import generate_jwt, get_installation_id, get_installation_access_token, lambda_handler
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Mock environment variables
GITHUB_APP_ID = "123456"

@pytest.fixture(scope="session")
def valid_rsa_private_key():
    """
    Generates a valid RSA private key in PEM format, encodes it in Base64,
    and returns it as a string for testing purposes.

    This fixture simulates a valid private key that would be used in a real GitHub App.

    Returns:
        str: The base64-encoded RSA private key.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    return base64.b64encode(pem).decode("utf-8")

@pytest.fixture()
def mock_requests():
    """
    Creates a `requests_mock.Mocker` instance for mocking HTTP requests.

    This fixture is used to simulate API responses from GitHub,
    allowing tests to run without making actual API calls.

    Yields:
        requests_mock.Mocker: A mock instance of `requests_mock.Mocker`.
    """
    with requests_mock.Mocker() as mock:
        yield mock

def test_generate_jwt(valid_rsa_private_key):
    """
    Tests the `generate_jwt()` function to ensure it correctly generates a JWT.

    The test verifies:
    - The JWT is successfully generated.
    - The JWT is a string.
    - The decoded JWT contains the expected fields (`iss`, `iat`, `exp`).
    - The `exp` (expiration time) is greater than `iat` (issued at time).

    Raises:
        AssertionError: If the JWT does not match the expected structure.
    """
    token = generate_jwt(GITHUB_APP_ID, valid_rsa_private_key)
    assert isinstance(token, str)
    
    decoded = jwt.decode(token, options={"verify_signature": False})
    assert decoded["iss"] == GITHUB_APP_ID
    assert "iat" in decoded
    assert "exp" in decoded
    assert decoded["exp"] > decoded["iat"]

def test_get_installation_id(valid_rsa_private_key, mock_requests):
    """
    Tests the `get_installation_id()` function to verify it correctly retrieves the installation ID.

    The test simulates a response from GitHub containing a valid installation ID
    and ensures that the function correctly extracts and returns the expected ID.

    Raises:
        AssertionError: If the function does not return the expected installation ID.
    """
    jwt_token = generate_jwt(GITHUB_APP_ID, valid_rsa_private_key)
    mock_requests.get("https://api.github.com/app/installations", json=[{"id": 98765}])
    installation_id = get_installation_id(jwt_token)
    assert installation_id == 98765

def test_get_installation_id_no_installations(valid_rsa_private_key, mock_requests):
    """
    Tests the behavior of `get_installation_id()` when no installations exist.

    The test simulates an empty response from GitHub and verifies that
    the function raises a `ValueError` with an appropriate error message.

    Raises:
        ValueError: If no installations are found.
    """
    jwt_token = generate_jwt(GITHUB_APP_ID, valid_rsa_private_key)
    mock_requests.get("https://api.github.com/app/installations", json=[])
    with pytest.raises(ValueError, match="No installations found for the GitHub App."):
        get_installation_id(jwt_token)

def test_get_installation_access_token(valid_rsa_private_key, mock_requests):
    """
    Tests the `get_installation_access_token()` function to verify it correctly generates an access token.

    The test simulates a valid GitHub API response for generating an installation access token
    and ensures that the function correctly returns the expected token.

    Raises:
        AssertionError: If the function does not return the expected access token.
    """
    jwt_token = generate_jwt(GITHUB_APP_ID, valid_rsa_private_key)
    installation_id = 98765
    mock_requests.post(
        f"https://api.github.com/app/installations/{installation_id}/access_tokens",
        json={"token": "mocked-access-token"}
    )
    token = get_installation_access_token(installation_id, jwt_token)
    assert token == "mocked-access-token"

def test_lambda_handler(valid_rsa_private_key, mock_requests):
    """
    Tests the `lambda_handler()` function to ensure end-to-end functionality.

    The test mocks API responses for installation retrieval and token generation,
    then verifies that the function correctly processes the request and returns the expected response.

    Raises:
        AssertionError: If the response does not match the expected output.
    """
    mock_requests.get("https://api.github.com/app/installations", json=[{"id": 98765}])
    mock_requests.post("https://api.github.com/app/installations/98765/access_tokens", json={"token": "mocked-access-token"})
    
    event = {
        "body": json.dumps({"githubAppId": GITHUB_APP_ID}),
        "headers": {"X-GitHub-Private-Key": valid_rsa_private_key}
    }
    
    response = lambda_handler(event, {})
    body = json.loads(response["body"])
    assert response["statusCode"] == 200
    assert body["message"] == "GitHub Access Token successfully retrieved"
    assert body["access_token"] == "mocked-access-token"

def test_lambda_handler_failure():
    """
    Tests the `lambda_handler()` function when an error occurs.

    The test uses `unittest.mock.patch` to simulate an exception in `generate_jwt()`,
    then verifies that the function correctly returns an error response.

    Raises:
        AssertionError: If the function does not return the expected error response.
    """
    with patch("app.generate_jwt", side_effect=Exception("JWT error")):
        event = {
            "body": json.dumps({"githubAppId": GITHUB_APP_ID}),
            "headers": {"X-GitHub-Private-Key": "INVALID_PRIVATE_KEY"}
        }
        
        response = lambda_handler(event, {})
        body = json.loads(response["body"])
        assert response["statusCode"] == 500
        assert "error" in body
        assert body["error"] == "JWT error"
