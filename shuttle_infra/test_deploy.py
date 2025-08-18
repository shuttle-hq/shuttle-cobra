import json
import os
from pathlib import Path

import boto3
from testcontainers.localstack import LocalStackContainer

from shuttle_common import (
    Bucket,
    BucketOptions,
    EcsCronTask,
    EcsCronTaskOptions,
    InfraManifest,
)

# from testcontainers.core.waiting_utils import wait_for_logs
from . import deploy_stack
from .common import BotoSession


def _verify_ecs_resources(ecs_client):
    """Verify ECS cluster and task definitions were created properly."""
    # Check if ECS cluster exists
    clusters = ecs_client.list_clusters()
    assert len(clusters["clusterArns"]) > 0, "No ECS clusters found"

    # Check if task definition exists
    task_definitions = ecs_client.list_task_definitions()
    assert len(task_definitions["taskDefinitionArns"]) > 0, (
        "No ECS task definitions found"
    )

    # Get the task definition details to verify it's configured correctly
    task_def_arn = task_definitions["taskDefinitionArns"][0]
    task_def = ecs_client.describe_task_definition(taskDefinition=task_def_arn)

    # Verify task definition has container definitions
    assert len(task_def["taskDefinition"]["containerDefinitions"]) > 0, (
        "No container definitions found"
    )


def _verify_s3_bucket(s3_client, bucket_name):
    """Verify S3 bucket was created with proper policies."""
    buckets = s3_client.list_buckets()
    bucket_names = [bucket["Name"] for bucket in buckets["Buckets"]]
    assert bucket_name in bucket_names, (
        f"Expected bucket '{bucket_name}' not found. Available buckets: {bucket_names}"
    )

    # Verify bucket policy exists (the bucket should have IAM policies attached)
    bucket_policy = s3_client.get_bucket_policy(Bucket=bucket_name)
    policy_doc = json.loads(bucket_policy["Policy"])
    assert "Statement" in policy_doc, "Bucket policy should contain statements"
    assert len(policy_doc["Statement"]) > 0, (
        "Bucket policy should have at least one statement"
    )


def test_deploy_stack():
    with (
        LocalStackContainer(image="localstack/localstack-pro:stable")
        .with_env("LOCALSTACK_AUTH_TOKEN", os.environ.get("LOCALSTACK_AUTH_TOKEN"))
        .with_services(
            "cloudformation",
            "ec2",
            "ecs",
            "ecr",
            "events",
            "iam",
            "logs",
            "secretsmanager",
            "sts",
            "resourcegroupstaggingapi",
            "rds",
        )
        .with_env("DEBUG", "1") as localstack
    ):
        endpoint_url = localstack.get_url()

        session = boto3.session.Session(
            aws_access_key_id="localstack",
            aws_secret_access_key="localstack",
            region_name="eu-west-2",
        )

        boto_session = BotoSession(endpoint_url=endpoint_url, session=session)

        bucket = Bucket(options=BucketOptions(bucket_name="test-bucket", policies=None))
        service = EcsCronTask(options=EcsCronTaskOptions(schedule="0 * * * ? *"))
        manifest = InfraManifest(service=service, resources=[bucket])

        working_directory = Path(__file__).parent.parent.resolve()

        deploy_stack(boto_session, manifest, working_directory, "test-deploy-stack")

        # Create clients to verify resource creation
        ecs_client = session.client("ecs", endpoint_url=endpoint_url)
        s3_client = session.client("s3", endpoint_url=endpoint_url)
        events_client = session.client("events", endpoint_url=endpoint_url)

        # Verify ECS resources
        _verify_ecs_resources(ecs_client)
        _verify_s3_bucket(s3_client, "test-bucket")

        # Verify EventBridge rule was created for the cron schedule
        rules = events_client.list_rules()
        assert len(rules["Rules"]) > 0, "No EventBridge rules found"

        # Check that at least one rule has a cron schedule expression
        cron_rule_found = False
        for rule in rules["Rules"]:
            if rule.get("ScheduleExpression", "").startswith("cron"):
                cron_rule_found = True

        assert cron_rule_found, (
            "No EventBridge rule found with the expected cron schedule '0 * * * ? *'"
        )
