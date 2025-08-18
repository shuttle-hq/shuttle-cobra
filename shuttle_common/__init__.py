from typing import Literal, Union, Annotated
import os

from pydantic import BaseModel, Field
import boto3
import psycopg2


class EnvVar(BaseModel):
    """The name of the env var where an output value can be found"""

    name: str

    def get_value(self):
        return os.environ.get(self.name)


class AllowWrite(BaseModel):
    account_id: str
    role_name: str


class BucketOptions(BaseModel):
    bucket_name: str | None
    policies: list[AllowWrite] | None
    # todo: add more


class BucketOutput(BaseModel):
    pass


class Bucket(BaseModel):
    type: Literal["shuttle_aws.s3.Bucket"] = "shuttle_aws.s3.Bucket"
    options: BucketOptions
    output: BucketOutput | None = None

    def init(self):
        # print(f"Bucket initializing at runtime with {self.options=}")
        pass

    def is_cf_resource(self, changeset: dict) -> bool:
        return (
            changeset["ResourceType"] == "AWS::S3::Bucket"
            and changeset["PhysicalResourceId"] == self.options.bucket_name
        )

    def get_client(self):
        s3 = boto3.client("s3")
        # check that the bucket exists and we have access to it
        _response = s3.head_bucket(Bucket=self.options.bucket_name)
        return s3


class RdsPostgresOptions(BaseModel):
    # todo: fields: engine_version, db_name
    pass


class RdsPostgresOutput(BaseModel):
    engine: EnvVar
    username: EnvVar
    password: EnvVar
    host: EnvVar
    port: EnvVar
    dbname: EnvVar
    dbInstanceIdentifier: EnvVar


class RdsPostgres(BaseModel):
    type: Literal["shuttle_aws.rds.Postgres"] = "shuttle_aws.rds.Postgres"
    options: RdsPostgresOptions
    output: RdsPostgresOutput | None = None

    def init(self):
        # print(f"RDS initializing at runtime with {self.options=}")
        pass

    def is_cf_resource(self, changeset: dict) -> bool:
        return changeset["ResourceType"] == "AWS::RDS::DBInstance"

    def get_connection(self):
        assert isinstance(self.output, RdsPostgresOutput)
        username = self.output.username.get_value()
        password = self.output.password.get_value()
        host = self.output.host.get_value()
        port = self.output.port.get_value()
        dbname = self.output.dbname.get_value()
        return psycopg2.connect(
            f"postgres://{username}:{password}@{host}:{port}/{dbname}"
        )


class EcsCronTaskOptions(BaseModel):
    schedule: str


class EcsCronTask(BaseModel):
    type: Literal["shuttle.ecs.cron_task"] = "shuttle.ecs.cron_task"
    options: EcsCronTaskOptions


AllResourcesUnion = Union[Bucket, RdsPostgres]


class InfraManifest(BaseModel):
    # todo: replace with union model when there are multiple options
    service: EcsCronTask
    resources: (
        list[Annotated[AllResourcesUnion, Field(..., discriminator="type")]] | None
    )
