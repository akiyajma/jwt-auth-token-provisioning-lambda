import json
import time
import jwt
import requests
import logging
import base64
from cryptography.hazmat.primitives import serialization

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def generate_jwt(github_app_id: str, encoded_private_key: str) -> str:
    """
    Generates a JSON Web Token (JWT) for GitHub App authentication.

    This function decodes a base64-encoded private key, loads it as a PEM-formatted key,
    and then generates a JWT signed with the private key. The JWT is used to authenticate
    GitHub App requests and retrieve installation access tokens.

    Args:
        github_app_id (str): The GitHub App ID.
        encoded_private_key (str): The base64-encoded private key associated with the GitHub App.

    Returns:
        str: The generated JWT, signed with the provided private key.

    Raises:
        ValueError: If the private key is missing.
        Exception: If JWT generation fails due to key issues or cryptographic errors.
    """
    try:
        if not encoded_private_key:
            raise ValueError("githubPrivateKey is missing in request header")

        # Decode the base64-encoded private key
        private_key = base64.b64decode(encoded_private_key).decode()
        private_key_bytes = private_key.encode()

        # Load the private key using the cryptography library
        private_key_obj = serialization.load_pem_private_key(
            private_key_bytes,
            password=None,
        )

        # Construct JWT payload
        payload = {
            "iat": int(time.time()),
            "exp": int(time.time()) + 600,  # JWT expires in 10 minutes
            "iss": github_app_id
        }

        # Encode the JWT using RS256 algorithm
        token = jwt.encode(payload, private_key_obj, algorithm="RS256")
        logger.info("JWT token successfully generated.")
        return token
    except Exception as e:
        logger.error(f"Failed to generate JWT: {e}")
        raise

def get_installation_id(jwt_token: str) -> int:
    """
    Retrieves the installation ID associated with the GitHub App.

    This function sends an authenticated request using a JWT to fetch all installations
    associated with the GitHub App. The installation ID is required to obtain an access token.

    Args:
        jwt_token (str): A valid GitHub JWT used for authentication.

    Returns:
        int: The first available installation ID.

    Raises:
        ValueError: If no installations are found.
        Exception: If the request to the GitHub API fails.
    """
    try:
        url = "https://api.github.com/app/installations"
        headers = {
            "Authorization": f"Bearer {jwt_token}",
            "Accept": "application/vnd.github.v3+json"
        }
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        installations = response.json()

        if not installations:
            raise ValueError("No installations found for the GitHub App.")

        installation_id = installations[0]["id"]
        logger.info(f"Installation ID retrieved: {installation_id}")
        return installation_id
    except Exception as e:
        logger.error(f"Failed to retrieve installation ID: {e}")
        raise

def get_installation_access_token(installation_id: int, jwt_token: str) -> str:
    """
    Obtains an Installation Access Token for the GitHub App.

    The Installation Access Token allows authenticated API calls for repository management,
    metadata retrieval, and other operations within the installed repositories.

    Args:
        installation_id (int): The installation ID of the GitHub App.
        jwt_token (str): A valid JWT for authentication.

    Returns:
        str: A GitHub Installation Access Token.

    Raises:
        Exception: If the request to generate the access token fails.
    """
    try:
        url = f"https://api.github.com/app/installations/{installation_id}/access_tokens"
        headers = {
            "Authorization": f"Bearer {jwt_token}",
            "Accept": "application/vnd.github.v3+json"
        }
        response = requests.post(url, headers=headers)
        response.raise_for_status()
        token = response.json()["token"]
        logger.info("Successfully obtained Installation Access Token.")
        return token
    except Exception as e:
        logger.error(f"Failed to obtain Installation Access Token: {e}")
        raise

def lambda_handler(event: dict, context) -> dict:
    """
    AWS Lambda function for generating a GitHub Access Token.

    This function:
    1. Extracts the `githubAppId` from the request body.
    2. Extracts the base64-encoded `githubPrivateKey` from the request headers.
    3. Decodes and loads the private key.
    4. Generates a JWT for GitHub App authentication.
    5. Retrieves the installation ID associated with the App.
    6. Generates an Installation Access Token to authenticate API requests.

    Args:
        event (dict): The AWS Lambda event payload, containing the request data.
        context: AWS Lambda context object (not used explicitly).

    Returns:
        dict: A response object containing the generated GitHub access token or an error message.

    Example Usage:
        Input:
        {
            "githubAppId": "123456"
        }
        Headers:
        {
            "X-GitHub-Private-Key": "base64_encoded_private_key"
        }

        Output (Success):
        {
            "statusCode": 200,
            "body": {
                "message": "GitHub Access Token successfully retrieved",
                "access_token": "ghp_abcdef1234567890"
            }
        }

        Output (Failure):
        {
            "statusCode": 500,
            "body": {
                "error": "Failed to obtain Installation Access Token"
            }
        }
    """
    try:
        logger.info(f"Received event: {json.dumps(event)}")

        # Parse request body and headers
        body = json.loads(event['body']) if 'body' in event and event['body'] else {}
        headers = event.get('headers', {})

        # Convert all keys to lowercase for case-insensitive access
        body_lower = {k.lower(): v for k, v in body.items()}
        headers_lower = {k.lower(): v for k, v in headers.items()}

        # Retrieve values
        github_app_id = body_lower.get('githubappid')
        encoded_private_key = headers_lower.get('x-github-private-key')

        if not github_app_id or not encoded_private_key:
            raise ValueError("Both githubAppId (body) and X-GitHub-Private-Key (header) are required")

        # Generate JWT
        jwt_token = generate_jwt(github_app_id, encoded_private_key)

        # Retrieve Installation ID
        installation_id = get_installation_id(jwt_token)

        # Generate Installation Access Token
        access_token = get_installation_access_token(installation_id, jwt_token)

        return {
            "statusCode": 200,
            "body": json.dumps({
                "message": "GitHub Access Token successfully retrieved",
                "access_token": access_token
            })
        }
    except Exception as e:
        logger.error(f"Lambda function execution failed: {e}")
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(e)})
        }
