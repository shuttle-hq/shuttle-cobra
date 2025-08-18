import time
from dataclasses import dataclass
from typing import Any, List

from botocore.exceptions import ClientError, WaiterError

from .common import BotoSession


# Custom exceptions
class CloudFormationError(Exception):
    """Base exception for CloudFormation operations"""


class TemplateValidationError(CloudFormationError):
    """Raised when template validation fails"""


class ChangeSetCreationError(CloudFormationError):
    """Raised when change set creation fails"""


class ChangeSetDescriptionError(CloudFormationError):
    """Raised when describing change set fails"""


class ChangeSetTimeoutError(CloudFormationError):
    """Raised when change set creation times out"""


class StackOperationError(CloudFormationError):
    """Raised when stack create/update operations fail"""


class StackDeletionError(Exception):
    """Raised when stack deletion operation fails"""


class StackDeletionTimeoutError(CloudFormationError):
    """Raised when stack deletion times out"""


class UnparseableChangeSet(Exception):
    """Raised when the ChangeSet cannot be converted to a string"""


class LogsNotFoundError(CloudFormationError):
    """Raised when a CloudWatch Log Group or Log Stream is not found."""


@dataclass
class ChangeSetResult:
    stack_name: str
    change_set_name: str
    change_set_type: str
    stack_id: str
    changes: List[Any]
    describe_response: dict


@dataclass
class StackResourcesResult:
    stack_name: str
    resources: List[Any]
    describe_response: dict


@dataclass
class NoChangeResult:
    operation: str
    message: str
    changes: List[Any]


@dataclass
class ExecutionResult:
    operation: str


class CfClient:
    def __init__(self, boto_session: BotoSession) -> None:
        self.session = boto_session.session
        self.client = self.session.client(
            "cloudformation", endpoint_url=boto_session.endpoint_url
        )
        self.logs_client = self.session.client(
            "logs", endpoint_url=boto_session.endpoint_url
        )

        super().__init__()

    def _stack_exists(self, stack_name: str) -> bool:
        try:
            self.client.describe_stacks(StackName=stack_name)
            return True
        except ClientError as e:
            if "does not exist" in str(e):
                return False
            raise

    def _create_change_set(
        self,
        stack_name: str,
        change_set_name: str,
        change_set_params: dict,
        change_set_type: str,
    ) -> ChangeSetResult | NoChangeResult:
        try:
            # Create the change set
            change_set_response = self.client.create_change_set(**change_set_params)

            # Wait for change set creation to complete
            max_attempts = 60
            attempt = 0

            while attempt < max_attempts:
                try:
                    describe_response = self.client.describe_change_set(
                        StackName=stack_name, ChangeSetName=change_set_name
                    )

                    status = describe_response["Status"]

                    if status == "CREATE_COMPLETE":
                        break
                    if status == "FAILED":
                        # Clean up the failed change set
                        self.client.delete_change_set(
                            StackName=stack_name, ChangeSetName=change_set_name
                        )

                        reason = describe_response.get("StatusReason", "Unknown reason")
                        if (
                            "didn't contain changes" in reason
                            or "No updates are to be performed" in reason
                        ):
                            return NoChangeResult(
                                operation="no_change",
                                message="No updates are to be performed on the stack",
                                changes=[],
                            )

                        raise ChangeSetCreationError(
                            f"Change set creation failed: {reason}"
                        )

                    time.sleep(2)
                    attempt += 1

                except ClientError as e:
                    raise ChangeSetDescriptionError(
                        f"Failed to describe change set: {str(e)}"
                    ) from e

            if attempt >= max_attempts:
                raise ChangeSetTimeoutError("Timeout waiting for change set creation")

            return ChangeSetResult(
                stack_name=stack_name,
                change_set_name=change_set_name,
                change_set_type=change_set_type,
                stack_id=change_set_response["StackId"],
                changes=describe_response.get("Changes", []),
                describe_response=describe_response,
            )

        except ClientError as e:
            raise ChangeSetCreationError(str(e)) from e

    def create_cloudformation_changeset(
        self, stack_name: str, template_json: str
    ) -> ChangeSetResult | NoChangeResult:
        # Validate the template first
        try:
            self.client.validate_template(TemplateBody=template_json)
        except ClientError as e:
            raise TemplateValidationError(
                f"Template validation failed: {str(e)}"
            ) from e

        # Check if stack exists
        exists = self._stack_exists(stack_name)

        # Determine change set type
        change_set_type = "UPDATE" if exists else "CREATE"
        change_set_name = f"{stack_name}-changeset-{int(time.time())}"

        # Create change set parameters
        change_set_params = {
            "StackName": stack_name,
            "ChangeSetName": change_set_name,
            "TemplateBody": template_json,
            "ChangeSetType": change_set_type,
            "Capabilities": [
                "CAPABILITY_IAM",
                "CAPABILITY_NAMED_IAM",
                "CAPABILITY_AUTO_EXPAND",
            ],
        }

        return self._create_change_set(
            stack_name, change_set_name, change_set_params, change_set_type
        )

    def _describe_change_set(
        self,
        stack_name: str,
    ) -> StackResourcesResult:
        try:
            describe_response = self.client.describe_stack_resources(
                StackName=stack_name
            )

            return StackResourcesResult(
                stack_name=stack_name,
                resources=describe_response.get("StackResources", []),
                describe_response=describe_response,
            )

        except ClientError as e:
            raise ChangeSetDescriptionError(
                f"Failed to describe stack resources for {stack_name}: {str(e)}"
            ) from e

    def describe_cloudformation_changeset(
        self, stack_name: str
    ) -> StackResourcesResult | NoChangeResult:
        # Check if stack exists
        if not self._stack_exists(stack_name):
            return NoChangeResult(
                operation="no_stack", message="Stack does not exist", changes=[]
            )

        return self._describe_change_set(stack_name)

    def execute_cloudformation_changeset(
        self, stack_name: str, change_set_name: str, change_set_type: str
    ) -> ExecutionResult:
        try:
            # Execute the change set
            self.client.execute_change_set(
                StackName=stack_name, ChangeSetName=change_set_name
            )

            # Wait for the operation to complete
            try:
                if change_set_type == "CREATE":
                    waiter = self.client.get_waiter("stack_create_complete")
                    waiter.wait(StackName=stack_name)
                else:  # update
                    waiter = self.client.get_waiter("stack_update_complete")
                    waiter.wait(StackName=stack_name)
            except WaiterError as e:
                try:
                    events = self.client.describe_stack_events(StackName=stack_name)
                    create_failure_event = filter(
                        lambda x: x["ResourceStatus"]
                        in [
                            "CREATE_FAILED",
                            "UPDATE_FAILED",
                            "UPDATE_ROLLBACK_IN_PROGRESS",
                        ]
                        and x["ResourceStatusReason"] != "Resource creation cancelled",
                        events["StackEvents"],
                    )
                    reason = list(create_failure_event)[-1]["ResourceStatusReason"]
                except (KeyError, IndexError, ClientError):
                    reason = "unknown"

                raise StackOperationError(
                    f"Stack {change_set_type.lower()} failed: {str(e)}; Reason: {reason}"
                ) from e

            return ExecutionResult(operation=change_set_type.lower())

        except ClientError as e:
            raise StackOperationError(str(e)) from e

    def destroy_stack(self, stack_name: str) -> ExecutionResult:
        try:
            # Check if stack exists, skip if it's already deleted
            if not self._stack_exists(stack_name):
                return ExecutionResult(operation="skip")

            # Delete the stack
            self.client.delete_stack(StackName=stack_name)

            # Wait for deletion to complete
            max_attempts = 360
            attempt = 0

            while attempt < max_attempts:
                describe_response = self.client.describe_stacks(StackName=stack_name)

                stack = describe_response["Stacks"][0]
                status = stack["StackStatus"]

                # Check if the CF stack has failed to delete
                if status == "DELETE_FAILED":
                    raise StackDeletionError(
                        f"Stack {stack_name} failed: {stack['StackStatusReason']}"
                    )

                time.sleep(2)
                attempt += 1

            if attempt >= max_attempts:
                raise StackDeletionTimeoutError("Timeout waiting for deletion")

            return ExecutionResult(operation="delete")

        except ClientError as e:
            # The `describe_stacks` call with throw a missing stack exception
            # if the stack was successfully deleted
            if "does not exist" in str(e):
                return ExecutionResult(operation="delete")
            raise StackOperationError(str(e)) from e

    def get_log_groups_for_stack(self, stack_name: str) -> List[str]:
        try:
            # Get all stack resources
            paginator = self.client.get_paginator("list_stack_resources")
            log_groups = []

            for page in paginator.paginate(StackName=stack_name):
                for resource in page["StackResourceSummaries"]:
                    if resource["ResourceType"] == "AWS::Logs::LogGroup":
                        log_groups.append(resource["PhysicalResourceId"])

            return log_groups
        except ClientError as e:
            raise StackOperationError(
                f"Failed to get log groups for stack {stack_name}: {str(e)}"
            ) from e

    def get_latest_log_stream(self, log_group_name: str) -> str | None:
        try:
            response = self.logs_client.describe_log_streams(
                logGroupName=log_group_name,
                orderBy="LastEventTime",
                descending=True,
                limit=1,
            )
            streams = response.get("logStreams", [])
            if streams:
                return streams[0]["logStreamName"]
            return None
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                raise LogsNotFoundError(
                    f"Log group '{log_group_name}' not found. It might not exist or the application might not be deployed yet."
                ) from e
            else:
                raise StackOperationError(
                    f"Failed to describe log streams for log group '{log_group_name}': {str(e)}"
                ) from e

    def stream_log_events_from_group(self, log_group_name: str):
        log_stream_name = self.get_latest_log_stream(log_group_name)
        if log_stream_name is None:
            raise LogsNotFoundError(
                f"No log streams found inside log group '{log_group_name}'. It might not exist or the application might not be deployed yet."
            )
        next_token = None

        while True:
            kwargs = {
                "logGroupName": log_group_name,
                "logStreamName": log_stream_name,
                "startFromHead": False,
            }
            if next_token:
                kwargs["nextToken"] = next_token

            response = self.logs_client.get_log_events(**kwargs)
            events = response.get("events", [])
            for event in events:
                yield event["message"], event["timestamp"]

            # Update the token to fetch only new events next time
            new_token = response.get("nextForwardToken")
            if new_token == next_token:
                break
            next_token = new_token


# Take a ChangeSetResult and a list and append string representations of the changes to the list
def change_set_result_str(
    change_set: ChangeSetResult,
    changesets: list[str],
    resource_tag_mapping_list: list[dict] | None = None,
):
    if resource_tag_mapping_list is None:
        resource_tag_mapping_list = []

    if change_set.changes:
        for change in change_set.changes:
            logical_id = change["ResourceChange"]["LogicalResourceId"]
            resource_type = change["ResourceChange"]["ResourceType"]
            action = change["ResourceChange"]["Action"]

            # Initial output
            if action == "Add":
                changesets.append(
                    f"          + {resource_type}\n          id = {logical_id}"
                )
            elif action == "Modify":
                changesets.append(
                    f"          ~ {resource_type}\n          id = {logical_id}"
                )
            elif action == "Remove":
                changesets.append(
                    f"          - {resource_type}\n          id = {logical_id}"
                )
            else:
                raise UnparseableChangeSet(change_set.changes)

            # Add information on resource ARNs if available
            for resource in resource_tag_mapping_list:
                match = {}
                for tag in resource.get("Tags", []):
                    if (
                        tag["Key"] == "aws:cloudformation:stack-id"
                        and tag["Value"] == change_set.stack_id
                    ):
                        match["active"] = True
                    if (
                        tag["Key"] == "aws:cloudformation:logical-id"
                        and tag["Value"] == logical_id
                    ):
                        match["arn"] = resource["ResourceARN"]

                if match.get("active", None) and match.get("arn", None):
                    changesets.append(f"          arn = {match['arn']}")
