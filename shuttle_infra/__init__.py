import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Union

import boto3
from aws_cdk import App
from aws_cdk import aws_ecs as ecs
from aws_cdk import aws_iam as iam
from aws_cdk.cx_api import CloudFormationStackArtifact
from botocore.exceptions import BotoCoreError
from pydantic import Field

from shuttle_common import (
    AllowWrite,
    Bucket,
    BucketOutput,
    EcsCronTask,
    EnvVar,
    InfraManifest,
    RdsPostgres,
    RdsPostgresOutput,
)

from . import cf
from .build import DockerClient
from .cdk import EcrRepository, EcsScheduledTaskStack
from .cf import CfClient, ChangeSetResult
from .common import BotoSession

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)

logging.getLogger("botocore").setLevel(logging.CRITICAL)


class AWSConnectionError(Exception):
    """Base exception for AWS connection errors"""


class InfraNotProvisionedError(Exception):
    """Raised when the expected infrastructure is not provisioned."""


@dataclass
class InfraAssociation:
    stack_name: str
    changeset_resource: dict
    annotation: Annotated[Union[Bucket, RdsPostgres], Field(..., discriminator="type")]
    rgsa_resource: dict


def _get_aws_config(boto_session: BotoSession):
    """Get AWS configuration details."""
    try:
        account_id = boto_session.session.client(
            "sts", endpoint_url=boto_session.endpoint_url
        ).get_caller_identity()["Account"]
        region = boto_session.session.region_name
        return account_id, region

    except BotoCoreError as e:
        raise AWSConnectionError(e) from e


def _create_resources(
    app: App, repository_name: str, image_uri: str, manifest: InfraManifest
):
    """Create all CDK resources."""
    # Create the ECR repository
    ecr_task = EcrRepository(
        app,
        f"Shuttle-EcrRepository-{repository_name}",
        repository_name=repository_name,
    )
    repository = ecr_task.create()

    # ECS task logic
    ecs_task_result = None
    if isinstance(manifest.service, EcsCronTask):
        # Create the scheduled ECS task
        ecs_task = EcsScheduledTaskStack(
            app,
            f"Shuttle-EcsScheduledTaskStack-{repository_name}",
            cron_schedule=manifest.service.options.schedule,
            repository=repository,
            image_uri=image_uri,
        )
        vpc = ecs_task.create_vpc()
        ecs_task_result = ecs_task.create_service(vpc)
    else:
        raise ValueError(
            f"Unsupported service type: {manifest.service.__class__.__name__}"
        )

    ecs_secrets = {}
    ecs_envvars = {}

    # Resource logic after ECS task is created
    for i, resource in enumerate(manifest.resources):
        if isinstance(resource, Bucket):
            # Define IAM principals to attach to Bucket policy
            s3_principals = [ecs_task_result.task_definition.task_role]
            if resource.options.policies is not None:
                for policy in resource.options.policies:
                    # Check policy type and handle accordingly
                    if isinstance(policy, AllowWrite):
                        s3_principals.append(
                            iam.ArnPrincipal(
                                f"arn:aws:iam::{policy.account_id}:role/{policy.role_name}"
                            )
                        )
            ecs_task.create_bucket(resource.options.bucket_name, s3_principals)
            resource.output = BucketOutput()
        elif isinstance(resource, RdsPostgres):
            database, _ = ecs_task.create_rds(vpc, ecs_task_result.security_group)
            database.secret.grant_read(ecs_task_result.task_definition.execution_role)
            output_kwargs = {}
            for secret_field in (
                "engine",
                "username",
                "password",
                "host",
                "port",
                "dbname",
                "dbInstanceIdentifier",
            ):
                var_name = f"SHUTTLE_RESOURCE_{i:04d}_{secret_field.upper()}"
                ecs_secrets[var_name] = ecs.Secret.from_secrets_manager(
                    database.secret, secret_field
                )
                output_kwargs[secret_field] = EnvVar(name=var_name)
            resource.output = RdsPostgresOutput(**output_kwargs)
        else:
            raise ValueError(
                f"Unsupported resource type: {resource.__class__.__name__}"
            )

    ecs_envvars["__SHUTTLE_RUNTIME_INFRA_OUTPUT"] = manifest.model_dump_json()

    # add env vars and secrets the very last, as they need info from everything else
    for envvar, value in ecs_envvars.items():
        # os.environ[envvar] = value

        ecs_task_result.runtime_container.add_environment(envvar, value)
    for envvar, secret in ecs_secrets.items():
        # os.environ[envvar] = secret
        ecs_task_result.runtime_container.add_secret(envvar, secret)

    return repository, ecs_task_result


def _handle_destroy_operations(session, stacks: list[CloudFormationStackArtifact]):
    """Handle destruction of CloudFormation stacks."""

    cf_client = CfClient(session)

    for stack in reversed(stacks):
        logger.debug("Trying to delete: %s", stack.stack_name)
        cf_client.destroy_stack(stack.stack_name)


def _handle_create_operations(
    session: BotoSession,
    stacks: list[CloudFormationStackArtifact],
    working_directory: Path,
    repository_uri: str,
    image_tag: str,
):
    """Handle creation of CloudFormation stacks."""

    cf_client = CfClient(session)

    # Apply the ECR Repository CF template
    changeset = cf_client.create_cloudformation_changeset(
        stacks[0].stack_name, json.dumps(stacks[0].template)
    )
    changesets = ["src/path/to/task.py", "  └── [~] shuttle_task.cron"]
    cf.change_set_result_str(changeset, changesets)

    if isinstance(changeset, ChangeSetResult):
        cf_client.execute_cloudformation_changeset(
            stacks[0].stack_name, changeset.change_set_name, changeset.change_set_type
        )

    # Build and push the End User image
    docker_client = DockerClient(session)
    docker_client.build(repository_uri, working_directory, image_tag)

    # Create a resource group stagging api client to fetch resource ARNs
    rgsa_client = session.session.client(
        "resourcegroupstaggingapi", endpoint_url=session.endpoint_url
    )

    # Apply remaining stacks
    for stack in stacks[1:]:
        changeset = cf_client.create_cloudformation_changeset(
            stack.stack_name, json.dumps(stack.template)
        )

        if isinstance(changeset, ChangeSetResult):
            cf_client.execute_cloudformation_changeset(
                stack.stack_name, changeset.change_set_name, changeset.change_set_type
            )

        # Fetch resource ARNs for stack resources
        rgsa_response = rgsa_client.get_resources(
            TagFilters=[
                {"Key": "aws:cloudformation:stack-name", "Values": [stack.stack_name]}
            ]
        )

        # Collect a diff changeset for output in the CLI
        cf.change_set_result_str(
            changeset, changesets, rgsa_response["ResourceTagMappingList"]
        )

    logger.info("\n".join(changesets))


def _handle_inspect_operations(
    session: BotoSession,
    stacks: list[CloudFormationStackArtifact],
    manifest: InfraManifest,
) -> list[InfraAssociation]:
    cf_client = CfClient(session)

    # Create a resource group stagging api client to fetch resource ARNs
    rgsa_client = session.session.client(
        "resourcegroupstaggingapi", endpoint_url=session.endpoint_url
    )

    infra_association = []
    for stack in stacks[1:]:
        # Apply the ECR Repository CF template
        changeset = cf_client.describe_cloudformation_changeset(stack.stack_name)

        # Check that the infra is actually provisioned
        if isinstance(changeset, cf.NoChangeResult):
            raise InfraNotProvisionedError(
                f"Infrastructure for stack '{stack.stack_name}' is not provisioned. Please deploy your application first."
            )

        # Fetch resource ARNs for stack resources
        rgsa_response = rgsa_client.get_resources(
            TagFilters=[
                {"Key": "aws:cloudformation:stack-name", "Values": [stack.stack_name]}
            ]
        )

        for annotation in manifest.resources:
            for changeset_resource in changeset.resources:
                # Check that this Annotation is relevant to this Cloudformation Changeset
                if annotation.is_cf_resource(changeset_resource):
                    # Add information on resource ARNs
                    for rgsa_resource in rgsa_response["ResourceTagMappingList"]:
                        match = {}
                        for tag in rgsa_resource.get("Tags", []):
                            if (
                                tag["Key"] == "aws:cloudformation:stack-id"
                                and tag["Value"] == changeset_resource["StackId"]
                            ):
                                match["active"] = True
                            if (
                                tag["Key"] == "aws:cloudformation:logical-id"
                                and tag["Value"]
                                == changeset_resource["LogicalResourceId"]
                            ):
                                match["rgsa"] = rgsa_resource

                        if match.get("active", None) and match.get("rgsa", None):
                            # Collect Annotation with Cloudformation and deployed Resource
                            infra_association.append(
                                InfraAssociation(
                                    stack_name=stack.stack_name,
                                    annotation=annotation,
                                    changeset_resource=changeset_resource,
                                    rgsa_resource=match["rgsa"],
                                )
                            )

    return infra_association


def create_cf_stack(
    session: BotoSession, manifest: InfraManifest, repository_name: str = "simple"
):
    """Main infrastructure deployment function. Constructs the CF stack and client."""
    # Create the CDK App - only one of these can exist
    app = App()
    image_tag = "dev"
    account_id, region = _get_aws_config(session)

    # Handle localstack testing
    if session.endpoint_url and ":" in session.endpoint_url:
        port = session.endpoint_url.split(":")[-1]
        repository_uri = f"{account_id}.dkr.ecr.{region}.localhost.localstack.cloud:{port}/{repository_name}"
    else:
        repository_uri = (
            f"{account_id}.dkr.ecr.{region}.amazonaws.com/{repository_name}"
        )

    image_uri = f"{repository_uri}:{image_tag}"

    # Create all resources
    _create_resources(app, repository_name, image_uri, manifest)

    # Export the CF template, this locks further creation of CDK resources
    stacks = app.synth().stacks

    return stacks, repository_uri, image_tag


def inspect_stack(
    session: BotoSession, manifest: InfraManifest, project_name: str | None
) -> list[InfraAssociation]:
    stacks, _, _ = create_cf_stack(session, manifest, project_name)

    return _handle_inspect_operations(session, stacks, manifest)


def deploy_stack(
    session: BotoSession,
    manifest: InfraManifest,
    working_directory: Path,
    project_name: str | None,
):
    stacks, repository_uri, image_tag = create_cf_stack(session, manifest, project_name)

    # Create the infra resources based on the Cloudformation stack
    _handle_create_operations(
        session, stacks, working_directory, repository_uri, image_tag
    )


def destroy_stack(
    session: boto3.session.Session, manifest: InfraManifest, project_name: str | None
):
    stacks, _, _ = create_cf_stack(session, manifest, project_name)

    _handle_destroy_operations(session, stacks)


def show_logs(session: BotoSession, manifest: InfraManifest, project_name: str | None):
    stacks, _, _ = create_cf_stack(session, manifest, project_name)

    cf_client = CfClient(session)

    for stack in stacks[1:]:
        log_groups = cf_client.get_log_groups_for_stack(stack.stack_name)
        for group in log_groups:
            logger.info("Log group: %s", group)
            for log_line, timestamp in cf_client.stream_log_events_from_group(group):
                t = datetime.fromtimestamp(timestamp / 1000, timezone.utc).strftime(
                    "%Y-%m-%d %H:%M:%S %z"
                )
                logger.info("[%s] %s", t, log_line)
