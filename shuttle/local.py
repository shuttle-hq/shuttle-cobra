import asyncio
import importlib.util
import json
import logging
import os
import sys
from pathlib import Path
from typing import Annotated

from shuttle_common import InfraManifest
from shuttle_infra import (
    inspect_stack,
)
from shuttle_infra.common import BotoSession

logger = logging.getLogger(__name__)


class ImportSpecError(Exception):
    pass


class ModuleExecError(Exception):
    pass


class RDSDescriptionError(Exception):
    """Exception raised when an RDS instance cannot be described."""


class RDSSecretRetrievalError(Exception):
    """Exception raised when RDS database credentials cannot be retrieved from Secrets Manager."""


def _set_environment_variable(env_var, value):
    """Helper function to set environment variable if env_var exists."""
    if env_var:
        os.environ[env_var.name] = value


def _get_db_credentials(secrets_client, secret_arn, db_instance_identifier):
    """Retrieve and return database credentials from Secrets Manager."""
    try:
        secret_response = secrets_client.get_secret_value(SecretId=secret_arn)
        return json.loads(secret_response["SecretString"])
    except (
        secrets_client.exceptions.ResourceNotFoundException,
        secrets_client.exceptions.DecryptionFailureException,
        json.JSONDecodeError,
    ) as e:
        # Replaced the placeholder with a custom exception for secret
        # retrieval issues.
        raise RDSSecretRetrievalError(
            f"Error retrieving secret for RDS instance {db_instance_identifier} with ARN {secret_arn}: {e}"
        ) from e


def rds_prep_environment(
    boto_session: BotoSession,
    manifest: InfraManifest,
    annotation: Annotated,
    project_name: str | None,
    # pylint: disable=too-many-locals
):
    infra_associations = inspect_stack(boto_session, manifest, project_name)
    for association in infra_associations:
        if association.annotation == annotation:
            rds_arn = association.rgsa_resource["ResourceARN"]
            db_instance_identifier = rds_arn.split(":")[-1]

            try:
                response = boto_session.session.client("rds").describe_db_instances(
                    DBInstanceIdentifier=db_instance_identifier
                )
                db_instance = response["DBInstances"][0]
            except (
                boto_session.session.client("rds").exceptions.DBInstanceNotFoundFault,
                boto_session.session.client("rds").exceptions.ClientError,
            ) as e:
                # Replaced the placeholder and subsequent error handling with a custom exception.
                raise RDSDescriptionError(
                    f"Error describing RDS instance {db_instance_identifier}: {e}"
                ) from e

            secret_arn = None
            if (
                "MasterUserSecret" in db_instance
                and "SecretArn" in db_instance["MasterUserSecret"]
            ):
                secret_arn = db_instance["MasterUserSecret"]["SecretArn"]
            else:
                secret_arn = "shuttle-db-secret"

            if secret_arn:
                secrets_client = boto_session.session.client("secretsmanager")
                # _get_db_credentials now raises an exception on failure
                secret_data = _get_db_credentials(
                    secrets_client, secret_arn, db_instance_identifier
                )

                if secret_data:
                    endpoint_address = db_instance["Endpoint"]["Address"]
                    endpoint_port = db_instance["Endpoint"]["Port"]

                    _set_environment_variable(
                        annotation.output.engine, secret_data.get("engine", "postgres")
                    )
                    _set_environment_variable(
                        annotation.output.username, secret_data.get("username")
                    )
                    _set_environment_variable(
                        annotation.output.password, secret_data.get("password")
                    )
                    _set_environment_variable(annotation.output.host, endpoint_address)
                    _set_environment_variable(
                        annotation.output.port, str(endpoint_port)
                    )
                    _set_environment_variable(
                        annotation.output.dbname,
                        secret_data.get("dbname", db_instance.get("DBName")),
                    )
                    _set_environment_variable(
                        annotation.output.dbInstanceIdentifier, db_instance_identifier
                    )
            else:
                logger.error(
                    "No MasterUserSecret found for RDS instance %s. "
                    "Cannot retrieve credentials.",
                    db_instance_identifier,
                )


def execute_user_main(module_name: str, module_path: Path):
    """Executes the main function of a user-provided module."""

    logger.info("Running locally...")

    spec = importlib.util.spec_from_file_location(module_name, str(module_path))

    if spec is None:
        raise ImportSpecError(f"Failed to load module spec for {module_name}")

    module = importlib.util.module_from_spec(spec)

    if module is None:
        raise ModuleExecError(f"Failed to create module from spec for {module_name}")

    sys.modules[module_name] = module

    if spec.loader is None:
        raise ModuleExecError("Module loader is None. Cannot execute module.")

    spec.loader.exec_module(module)

    logger.info("Starting local runner...")

    result = asyncio.run(module.main())
    return result
