import logging
import os
from pathlib import Path

os.environ["JSII_SILENCE_WARNING_UNTESTED_NODE_VERSION"] = "1"

import boto3
import click
from docker.errors import DockerException

from shuttle_common import RdsPostgres
from shuttle_infra import (
    AWSConnectionError,
    deploy_stack,
    destroy_stack,
    show_logs,
    InfraNotProvisionedError,
)
from shuttle_infra.build import DockerContextPathMissing, ImagePushError
from shuttle_infra.cf import (
    CloudFormationError,
    LogsNotFoundError,
    StackDeletionError,
    StackDeletionTimeoutError,
    UnparseableChangeSet,
)
from shuttle_infra.common import BotoSession

from .lib import InfraDiscoveryError, discover_project_and_infra
from .local import (
    ImportSpecError,
    ModuleExecError,
    RDSDescriptionError,
    RDSSecretRetrievalError,
    execute_user_main,
    rds_prep_environment,
)


# Configure basic logging setup if not already configured
if not logging.getLogger().handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )


def configure_debug_logging(ctx, param, value):
    """Callback to enable debug logging for shuttle modules."""
    if value:
        logging.getLogger("shuttle_common").setLevel(logging.DEBUG)
        logging.getLogger("shuttle_infra").setLevel(logging.DEBUG)
        logging.getLogger(__name__).setLevel(logging.DEBUG)
        click.echo("Debug logging enabled for shuttle-related modules.")
    return value


# Define the common debug option
debug_option = click.option(
    "--debug",
    is_flag=True,
    help="Enable debug logging for shuttle based modules.",
    callback=configure_debug_logging,
    expose_value=True,
    is_eager=True,
)


@click.group()
def app():
    """Shuttle CLI for Python 🤨🐍"""
    pass


@app.command()
@debug_option
@click.argument("path", required=False, default=".")
def deploy(path, debug):
    """Provision, build, and deploy the application."""

    session = boto3.session.Session()
    boto_session = BotoSession(endpoint_url=None, session=session)
    try:
        project_root, manifest, project_name = discover_project_and_infra(path)
    except FileNotFoundError as e:
        click.echo(
            f"Required file or directory not found: {e}. Please ensure the project structure is valid and all necessary files exist.",
            err=True,
        )
        return
    except InfraDiscoveryError as e:
        click.echo(f"Error discovering project infrastructure: {e}", err=True)
        return

    try:
        deploy_stack(boto_session, manifest, project_root, project_name)
    except UnparseableChangeSet as e:
        click.echo(
            f"Failed to parse CloudFormation change set due to an unknown or unexpected change type: {e}. This indicates an internal issue or an unexpected AWS CloudFormation response. Please report this issue.",
            err=True,
        )
    except CloudFormationError as e:  # Catch all CloudFormation-related errors (TemplateValidationError, ChangeSetCreationError, ChangeSetDescriptionError, ChangeSetTimeoutError, StackOperationError)
        click.echo(f"CloudFormation operation failed: {e}", err=True)
    except AWSConnectionError as e:
        click.echo(f"Failed to connect to AWS: {e}", err=True)
    except DockerException as e:
        click.echo(f"Fatal Docker error: {e}", err=True)
    except ImagePushError as e:
        click.echo(f"Failed to push Docker image: {e}", err=True)
    except DockerContextPathMissing as e:
        click.echo(
            f"Docker build context path missing: {e}. Please ensure the project directory exists and is accessible.",
            err=True,
        )


@app.command()
@debug_option
@click.argument("path", required=False, default=".")
def destroy(path, debug):
    """Destroy the stack."""

    session = boto3.session.Session()
    boto_session = BotoSession(endpoint_url=None, session=session)
    try:
        _, manifest, project_name = discover_project_and_infra(path)
    except FileNotFoundError as e:
        click.echo(
            f"Required file or directory not found: {e}. Please ensure the project structure is valid and all necessary files exist.",
            err=True,
        )
        return
    except InfraDiscoveryError as e:
        click.echo(f"Error discovering project infrastructure: {e}", err=True)
        return

    try:
        destroy_stack(boto_session, manifest, project_name)
    except StackDeletionTimeoutError as e:
        click.echo(
            f"Deletion of the CloudFormation stack timed out: {e}. Please check your AWS console for the stack's status and consider manual intervention if necessary.",
            err=True,
        )
    except StackDeletionError as e:
        click.echo(f"Deprovisioning of Cloudformation resources failed: {e}", err=True)
    except CloudFormationError as e:  # Catch all CloudFormation-related errors (StackOperationError, StackDeletionTimeoutError)
        click.echo(f"CloudFormation operation failed: {e}", err=True)
    except AWSConnectionError as e:
        click.echo(f"Failed to connect to AWS: {e}", err=True)


@app.command()
@debug_option
@click.argument("path", required=False, default=".")
def logs(path, debug):
    """Show logs from the deployed app."""

    session = boto3.session.Session()
    boto_session = BotoSession(endpoint_url=None, session=session)
    try:
        _, manifest, project_name = discover_project_and_infra(path)
    except FileNotFoundError as e:
        click.echo(
            f"Required file or directory not found: {e}. Please ensure the project structure is valid and all necessary files exist.",
            err=True,
        )
        return
    except InfraDiscoveryError as e:
        click.echo(f"Error discovering project infrastructure: {e}", err=True)
        return

    try:
        show_logs(boto_session, manifest, project_name)
    except LogsNotFoundError as e:
        click.echo(
            "Error: Logs not found for this application. Ensure the application is deployed and has a logs associated.",
            err=True,
        )
        click.echo(f"Details: {e}", err=True)
    except CloudFormationError as e:  # Catch all CloudFormation-related errors (e.g., StackOperationError from get_log_groups_for_stack)
        click.echo(f"CloudFormation operation failed: {e}", err=True)
    except AWSConnectionError as e:
        click.echo(f"Failed to connect to AWS: {e}", err=True)


@app.command()
@debug_option
@click.argument("path", required=False, default=".")
def run(path, debug):
    rpath = Path(path).resolve()
    if (entrypoint := rpath.joinpath("main.py")).exists():
        pass
    elif (entrypoint := rpath.joinpath("__main__.py")).exists():
        pass
    else:
        click.echo(f"Error: didn't find a main python file in {rpath}", err=True)
        return

    session = boto3.session.Session()
    boto_session = BotoSession(endpoint_url=None, session=session)
    try:
        _, manifest, project_name = discover_project_and_infra(path)
    except FileNotFoundError as e:
        click.echo(
            f"Required file or directory not found: {e}. Please ensure the project structure is valid and all necessary files exist.",
            err=True,
        )
        return
    except InfraDiscoveryError as e:
        click.echo(f"Error discovering project infrastructure: {e}", err=True)
        return

    try:
        # We need to specifically handle Rds, because CDK doesn't populate
        # connection details about Posgres until it applies infra - so if we're
        # just running locally we need to fetch RDS secrets manually.
        for annotation in manifest.resources:
            if isinstance(annotation, RdsPostgres):
                rds_prep_environment(boto_session, manifest, annotation, project_name)

        if debug:
            click.echo("Manifest Model Dump:")
            click.echo(manifest.model_dump())
        os.environ["__SHUTTLE_RUNTIME_INFRA_OUTPUT"] = manifest.model_dump_json()

        execute_user_main(path, entrypoint)
    except InfraNotProvisionedError as e:
        click.echo(f"Error: {e}", err=True)
    except CloudFormationError as e:  # Catch CloudFormation errors (e.g., ChangeSetDescriptionError from rds_prep_environment)
        click.echo(f"CloudFormation operation failed: {e}", err=True)
    except RDSDescriptionError as e:
        click.echo(f"Failed to describe RDS instance: {e}", err=True)
    except RDSSecretRetrievalError as e:
        click.echo(f"Failed to retrieve RDS secrets: {e}", err=True)
    except ImportSpecError as e:
        click.echo(f"Failed to load user module: {e}", err=True)
    except ModuleExecError as e:
        click.echo(f"Failed to execute user module: {e}", err=True)
    except AttributeError as e:
        click.echo(
            f"The application's 'main' function was not found or is not callable: {e}",
            err=True,
        )
    except Exception as e:
        click.echo(
            f"An unexpected error occurred during local execution: {e}", err=True
        )


if __name__ == "__main__":
    app()
