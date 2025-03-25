# GitHub App Authentication with AWS Lambda

## Overview

This project provides an AWS Lambda function that generates a GitHub Installation Access Token for a GitHub App. The function:

1. Generates a JSON Web Token (JWT) using the GitHub App's private key.
2. Retrieves the GitHub App's installation ID.
3. Generates an Installation Access Token, which allows API requests to GitHub.

The repository also includes tests using `pytest`, a GitHub Actions CI/CD pipeline for automated testing and Docker deployment, and an API Gateway configuration for secure authentication.

---

## Features

- Generates JWT for GitHub App authentication.
- Retrieves the installation ID of a GitHub App.
- Fetches an Installation Access Token to perform GitHub API actions.
- API Gateway configuration to securely pass authentication headers.
- Includes unit tests with `pytest`.
- Implements GitHub Actions for automated testing and deployment.
- Deploys a Docker container to Amazon ECR.

---

## Project Structure

```
├── app.py                 # Main Lambda function code
├── tests/
│   ├── test_app.py        # Unit tests
├── actions/
│   ├── ci-cd.yml          # GitHub Actions workflow
├── api/
│   ├── swagger.yaml       # API Gateway OpenAPI specification
├── requirements.txt       # Python dependencies
├── requirements-dev.txt   # Development dependencies (testing)
├── Dockerfile             # Docker build configuration
└── README.md              # Project documentation
```

---

## Installation & Setup

### Prerequisites

- Python 3.12
- AWS CLI configured with appropriate permissions
- Docker (if deploying to AWS)
- GitHub App credentials (App ID & Private Key in **Base64-encoded format**)

### Install Dependencies

```sh
pip install -r requirements-dev.txt
```

---

## Usage

### Local Execution

Invoke the lambda_handler function with a JSON payload containing:

```json
{
  "githubAppId": "123456"
}
```

Additionally, provide the **Base64-encoded** private key via the `X-GitHub-Private-Key` header.

Expected Response:

```json
{
  "statusCode": 200,
  "body": {
    "message": "GitHub Access Token successfully retrieved",
    "access_token": "ghp_abcdef1234567890"
  }
}
```

---

## Testing

### Run Unit Tests

```sh
pytest tests/
```

---

## API Gateway Configuration

This Lambda function is integrated with AWS API Gateway, which securely passes authentication headers. Ensure the following configurations are applied:

1. The `X-GitHub-Private-Key` header is correctly passed from API Gateway to Lambda.
2. The OpenAPI specification (`swagger.yaml`) defines `X-GitHub-Private-Key` in the `securitySchemes` section.

### Example cURL Request

```sh
curl -X POST "https://your-api-gateway-url/v1/github/token" \
     -H "Authorization: Bearer YOUR_COGNITO_ACCESS_TOKEN" \
     -H "Content-Type: application/json" \
     -H "X-GitHub-Private-Key: BASE64_ENCODED_PRIVATE_KEY" \
     -d '{
           "githubAppId": "123456"
         }'
```

---

## CI/CD Pipeline (GitHub Actions)

The pipeline:

- Runs pytest to ensure all tests pass.
- Builds and pushes a Docker image to Amazon ECR.

### Workflow Configuration

Located in `.github/workflows/ci-cd.yml`, the pipeline includes:

- **Test Stage**: Runs pytest to validate code.
- **Build & Deploy Stage**: Builds and pushes the Docker image to Amazon ECR.

---

## Deployment

### Authenticate with AWS

```sh
aws ecr get-login-password --region ap-northeast-1 | docker login --username AWS --password-stdin ${AWS_ACCOUNT_ID}.dkr.ecr.ap-northeast-1.amazonaws.com
```

### Build & Push the Docker Image

```sh
docker build -t #{APP_NAME} .
docker tag #{APP_NAME}:latest ${AWS_ACCOUNT_ID}.dkr.ecr.ap-northeast-1.amazonaws.com/#{APP_NAME}:latest
docker push ${AWS_ACCOUNT_ID}.dkr.ecr.ap-northeast-1.amazonaws.com/#{APP_NAME}:latest
```

---

## Notes

- Ensure `X-GitHub-Private-Key` is correctly passed as a **Base64-encoded string** in API requests.
- API Gateway should correctly forward the `X-GitHub-Private-Key` header to Lambda.
- If encountering issues, check the Lambda logs in AWS CloudWatch to verify incoming headers.
