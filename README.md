# Shuttle Cobra 🐍

![CI Status](https://img.shields.io/badge/CI-passing-brightgreen) ![License](https://img.shields.io/badge/license-MIT-blue)

Shuttle Cobra is a framework that empowers you to effortlessly deploy your
Python applications and their required AWS infrastructure with a delightful,
Python-native development experience.

Define your application and its cloud resources directly in Python code using
type hints and annotations, and let the Shuttle CLI handle the provisioning,
building, and deployment to AWS.

## ✨ Features

*   **Python-Native Infrastructure:** Define AWS resources like S3 buckets,
    PostgreSQL databases, and scheduled tasks using standard Python syntax.
*   **Declarative Deployment:** The Shuttle CLI understands your Python code
    and provisions/updates your infrastructure on AWS to match your
    definitions.
*   **Local Development:** Run your Shuttle applications locally, seamlessly
    connecting to your provisioned remote resources or local emulations.
*   **Simplified Workflow:** Focus on your application logic, not complex
    infrastructure-as-code configurations.
*   **Powered by `uv`:** Leverages `uv` for fast, robust dependency management.

## 🚀 Getting Started

Follow these steps to set up your environment and deploy your first Shuttle
Cobra application.

### Prerequisites

1.  **AWS Account and Credentials:** Ensure you have an AWS account and your
    credentials configured. You can authenticate with AWS using one of the
    following methods:
    *   **SSO Enabled**: Use `aws configure sso` for AWS Single Sign-On.
    *   **IAM User Account**: Use `aws configure` for standard IAM user
        credentials.
    *   **Temporary IAM Credentials**: Set the following environment variables:
        *   `AWS_ACCESS_KEY_ID`
        *   `AWS_SECRET_ACCESS_KEY`
        *   `AWS_SESSION_TOKEN`
    *   **Other Options**: IAM role metadata and OIDC federation are also
        supported.
2.  **`uv` installed:** `uv` is recommended for managing Python environments
    and dependencies. Install it via pip:
    ```bash
    pip install uv
    ```

### Installation

Once `uv` is installed, you can create a virtual environment and install the
Shuttle CLI:

```bash
# Create a new virtual environment
uv venv

# Activate the virtual environment (Linux/macOS)
source .venv/bin/activate

# Activate the virtual environment (Windows PowerShell)
.venv\Scripts\Activate.ps1

# Install Shuttle CLI and its dependencies
uv init
uv add shuttle-cobra
```

### Invoking Shuttle Commands

Once Shuttle is installed and your virtual environment is activated (using
`source .venv/bin/activate` or `.venv\Scripts\Activate.ps1`), you can invoke
all Shuttle commands directly using `shuttle`.

If you are outside your virtual environment (i.e., you haven't activated it),
you can invoke all Shuttle commands using `uv run -m shuttle`.

Throughout this guide, examples will primarily use the `shuttle` command,
assuming your virtual environment is activated. We will also provide the `uv
run -m shuttle` equivalent where relevant.

### Create Your First Project

Start a new Shuttle project by defining a `main.py` file inside your virtual
environment.

Navigate into your project directory (or create a new one for your `main.py`
file). Open `main.py` (or your chosen application file) and define your
application.

Here's an example of a simple scheduled task that uses an S3 bucket:

```python
from typing import Annotated
import shuttle_runtime
import shuttle_task
from shuttle_aws.s3 import Bucket, BucketOptions

@shuttle_task.cron(schedule="0 * * * ? *") # Runs every hour
async def run(
    bucket: Annotated[
        Bucket,
        BucketOptions(bucket_name="my-unique-shuttle-bucket", policies=[]),
    ]
):
    print(f"Hello from Shuttle! Bucket name: {bucket.options.bucket_name}")
    # Use bucket.get_client() for boto3 S3 client operations

if __name__ == "__main__":
    shuttle_runtime.main(main)
```

### Deploy Your Application

Once your AWS credentials are configured and your application defined, deploy
it with a single command:

```bash
shuttle deploy
# or
uv run -m shuttle deploy
```

The CLI will show you a plan of the infrastructure changes and prompt for
confirmation before provisioning resources on AWS.

### View Logs

To see the output from your deployed application, use the `logs` command:

```bash
shuttle logs
# or
uv run -m shuttle logs
```

### Run Locally

Develop and test your application locally while connecting to your deployed
cloud resources:

```bash
shuttle run
# or
uv run -m shuttle run
```

This will execute your `run` function (or equivalent entrypoint) in your local
environment, using the remote AWS resources provisioned by Shuttle.

### Destroy Resources

When you no longer need your deployed application and its associated
infrastructure, you can destroy it:

```bash
shuttle destroy
# or
uv run -m shuttle destroy
```

## 🛠️ Development

To set up the development environment for Shuttle Cobra:

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/shuttle/shuttle-cobra.git # Replace with actual repo URL
    cd shuttle-cobra
    ```
2.  **Create and activate a virtual environment:**
    ```bash
    uv venv
    source .venv/bin/activate
    ```

### Running Tests

Ensure your `LOCALSTACK_AUTH_TOKEN` environment variable is set for integration
tests (if applicable).

```bash
# Run all tests
uv run pytest --capture=no shuttle*/test*.py

# Or, for more granular control, activate venv and run pytest directly
source .venv/bin/activate
pytest --capture=no shuttle*/test*.py
```

### Contributing

We welcome contributions! Please see our [CONTRIBUTING.md](CONTRIBUTING.md) for
more details on how to get involved.

## ❤️ Support & Community

*   **Documentation:** Visit the official Shuttle [Python
    documentation](https://docs.shuttle.dev/python/welcome/introduction) for in-depth guides and API
    references.
*   **Community:** Join our community forum or Discord channel (links to be
    provided).
*   **Issue Tracker:** Report bugs or request features on our [GitHub
    Issues](https://github.com/shuttle/shuttle-cobra/issues).

## 📄 License

This project is licensed under the Apache v2 License - see the
[LICENSE](LICENSE) file for details.
