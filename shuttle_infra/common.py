from dataclasses import dataclass
from typing import Optional

import boto3


@dataclass
class BotoSession:
    session: boto3.session.Session
    endpoint_url: Optional[str]
