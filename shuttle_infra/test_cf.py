import os

import boto3
import pytest
from testcontainers.localstack import LocalStackContainer

from .cf import CfClient, ChangeSetResult, ExecutionResult
from .common import BotoSession


@pytest.fixture(scope="session")
def localstack_services():
    """Define the services needed for LocalStack"""
    return [
        "cloudformation",
        "logs",
    ]


@pytest.fixture(scope="module")
def localstack_url(localstack_services):
    """Start LocalStack container with required services"""
    with (
        LocalStackContainer(image="localstack/localstack-pro:stable")
        .with_env("LOCALSTACK_AUTH_TOKEN", os.environ.get("LOCALSTACK_AUTH_TOKEN"))
        .with_services(*localstack_services)
        .with_env("DEBUG", "1") as localstack
    ):
        yield localstack.get_url()


@pytest.fixture(scope="module")
def boto_session(localstack_url):
    session = boto3.session.Session(
        aws_access_key_id="localstack",
        aws_secret_access_key="localstack",
        region_name="eu-west-2",
    )

    boto_session = BotoSession(endpoint_url=localstack_url, session=session)
    yield boto_session


@pytest.fixture(scope="module")
def cloudformation_bucket_template():
    yield """
    {
      "Resources": {
        "ShuttleS3BucketEEFEBC97": {
          "Type": "AWS::S3::Bucket",
          "Properties": {
            "BucketEncryption": {
              "ServerSideEncryptionConfiguration": [
                {
                  "ServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "AES256"
                  }
                }
              ]
            },
            "BucketName": "shuttle-cron-123456",
            "OwnershipControls": {
              "Rules": [
                {
                  "ObjectOwnership": "BucketOwnerEnforced"
                }
              ]
            },
            "PublicAccessBlockConfiguration": {
              "BlockPublicAcls": true,
              "BlockPublicPolicy": true,
              "IgnorePublicAcls": true,
              "RestrictPublicBuckets": true
            },
            "VersioningConfiguration": {
              "Status": "Enabled"
            }
          },
          "UpdateReplacePolicy": "Delete",
          "DeletionPolicy": "Delete"
        }
      }
    }
    """


@pytest.fixture(scope="module")
def cloudformation_loggroup_template():
    yield """
    {
      "Resources": {
    		"ShuttleScheduledTaskDefinitionRuntimeLogGroup236EB809": {
			"Type": "AWS::Logs::LogGroup",
			"UpdateReplacePolicy": "Retain",
			"DeletionPolicy": "Retain"
		}
      }
    }
    """


@pytest.fixture(scope="module")
def cf_client(boto_session):
    cf = CfClient(boto_session)
    yield cf


def test_create_cf_changeset(boto_session, cf_client, cloudformation_bucket_template):
    # Create clients to verify resource creation
    result = cf_client.create_cloudformation_changeset(
        "test-create-cf-changeset", cloudformation_bucket_template
    )

    # Assert that we got a ChangeSetResult (not NoChangeResult)
    assert isinstance(result, ChangeSetResult), (
        f"Expected ChangeSetResult, got {type(result)}, with message: {result.message}"
    )

    # Assert basic properties of the changeset
    assert result.stack_name == "test-create-cf-changeset"
    assert result.change_set_type == "CREATE"  # Since this is a new stack
    assert result.stack_id is not None
    assert result.change_set_name.startswith("test-create-cf-changeset-")

    # Assert that we have changes (should contain the S3 bucket creation)
    assert len(result.changes) > 0, "Expected changes in the changeset"

    # Verify the change is for creating the S3 bucket
    s3_change = next(
        (
            change
            for change in result.changes
            if change["ResourceChange"]["LogicalResourceId"]
            == "ShuttleS3BucketEEFEBC97"
        ),
        None,
    )
    assert s3_change is not None, "Expected to find S3 bucket change"
    assert s3_change["ResourceChange"]["Action"] == "Add"
    assert s3_change["ResourceChange"]["ResourceType"] == "AWS::S3::Bucket"

    # Verify the changeset exists in CloudFormation
    cf = boto_session.session.client(
        "cloudformation", endpoint_url=boto_session.endpoint_url
    )
    describe_response = cf.describe_change_set(
        StackName="test-create-cf-changeset", ChangeSetName=result.change_set_name
    )
    assert describe_response["Status"] == "CREATE_COMPLETE"


def test_destroy_cf_stack(cf_client, boto_session, cloudformation_bucket_template):
    # Create clients to verify resource creation
    create_result = cf_client.create_cloudformation_changeset(
        "test-destroy-cf-stack", cloudformation_bucket_template
    )

    execution_result = cf_client.execute_cloudformation_changeset(
        create_result.stack_name, create_result.change_set_name, "CREATE"
    )

    # Assert that the changeset was executed successfully
    assert isinstance(execution_result, ExecutionResult), (
        f"Expected ExecutionResult, got {type(execution_result)}"
    )
    assert execution_result.operation == "create", (
        f"Expected 'create' operation, got {execution_result.operation}"
    )

    # Verify the stack was created successfully
    cf = boto_session.session.client(
        "cloudformation", endpoint_url=boto_session.endpoint_url
    )
    describe_stack_response = cf.describe_stacks(StackName="test-destroy-cf-stack")
    assert describe_stack_response["Stacks"][0]["StackStatus"] == "CREATE_COMPLETE"

    # Clean up after test
    destroy_result = cf_client.destroy_stack("test-destroy-cf-stack")

    # Assert that the stack deletion was initiated successfully
    assert isinstance(destroy_result, ExecutionResult), (
        f"Expected ExecutionResult, got {type(destroy_result)}"
    )
    assert destroy_result.operation == "delete", (
        f"Expected 'delete' operation, got {destroy_result.operation}"
    )

    # Verify the stack no longer exists after deletion
    try:
        cf.describe_stacks(StackName="test-destroy-cf-stack")
    except cf.exceptions.ClientError as e:
        assert "does not exist" in str(e), (
            f"Expected to find 'does not exist' in error message, got {str(e)}"
        )


def test_get_log_groups(cf_client, cloudformation_loggroup_template):
    # Create clients to verify resource creation
    result = cf_client.create_cloudformation_changeset(
        "test-get-log-groups", cloudformation_loggroup_template
    )

    cf_client.execute_cloudformation_changeset(
        result.stack_name, result.change_set_name, result.change_set_type
    )

    log_groups = cf_client.get_log_groups_for_stack(result.stack_name)
    assert log_groups, "Expected at least one log group"
