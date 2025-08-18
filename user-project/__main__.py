from typing import Annotated

import shuttle_runtime
import shuttle_task
from shuttle_aws.s3 import Bucket, BucketOptions, AllowWrite
from shuttle_aws.rds import RdsPostgres, RdsPostgresOptions


@shuttle_task.cron(schedule="0 * * * ? *")
async def main(
    bucket: Annotated[
        Bucket,
        BucketOptions(
            bucket_name="shuttle-cron-123456",
            policies=[
                AllowWrite(
                    account_id="375543694826",  # dev2
                    role_name="dev2-bastion-ssm_role",
                ),
            ],
        ),
    ],
    postgres: Annotated[
        RdsPostgres,
        RdsPostgresOptions(),
    ],
):
    s3 = bucket.get_client()
    objects = s3.list_objects_v2(Bucket=bucket.options.bucket_name)
    if objects["KeyCount"] == 0:
        print(f"No objects in the bucket {bucket.options.bucket_name}.")
    else:
        print(f"Objects in the bucket {bucket.options.bucket_name}:")
        for obj in objects["Contents"]:
            print(
                f"[{obj['LastModified'].strftime('%Y-%m-%d %H:%M:%S %z')}] {obj['Key']} ({obj['Size']}B)",
            )

    pg = postgres.get_connection()
    with pg.cursor() as cur:
        cur.execute("SELECT 1;")
        print(f"Select query in RDS: {cur.fetchone()}")
        pg.commit()


if __name__ == "__main__":
    shuttle_runtime.main(main)
