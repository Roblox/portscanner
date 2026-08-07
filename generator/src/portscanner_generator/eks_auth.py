"""EKS authentication using botocore signing and the Kubernetes client."""

from __future__ import annotations

import base64
import os
import tempfile
import weakref
from contextlib import suppress
from typing import Any
from urllib.parse import urlsplit

from .config import GeneratorConfig


def generate_eks_bearer_token(
    cluster_name: str,
    region_name: str,
    *,
    session: Any | None = None,
) -> str:
    """Generate an EKS IAM token without invoking or logging awscli."""

    if session is None:
        import boto3

        session = boto3.session.Session(region_name=region_name)
    credentials = session.get_credentials()
    if credentials is None:
        raise RuntimeError("AWS credentials are unavailable")

    sts_client = session.client("sts", region_name=region_name)
    endpoint = sts_client.meta.endpoint_url.rstrip("/")
    endpoint_parts = urlsplit(endpoint)
    if endpoint_parts.scheme != "https" or not endpoint_parts.netloc:
        raise RuntimeError("STS client returned an invalid HTTPS endpoint")
    request = {
        "method": "GET",
        "url": (f"{endpoint}/?Action=GetCallerIdentity&Version=2011-06-15"),
        "body": b"",
        "headers": {
            "host": endpoint_parts.netloc,
            "x-k8s-aws-id": cluster_name,
        },
        "context": {},
    }

    from botocore.signers import RequestSigner

    signer = RequestSigner(
        sts_client.meta.service_model.service_id,
        region_name,
        "sts",
        "v4",
        credentials,
        sts_client.meta.events,
    )
    presigned_url = signer.generate_presigned_url(
        request_dict=request,
        region_name=region_name,
        expires_in=60,
        operation_name="",
    )
    encoded = base64.urlsafe_b64encode(presigned_url.encode("utf-8")).decode("ascii")
    return f"k8s-aws-v1.{encoded.rstrip('=')}"


def _write_cluster_ca(encoded_ca: str) -> str:
    try:
        certificate = base64.b64decode(encoded_ca, validate=True)
    except (ValueError, TypeError) as error:
        raise RuntimeError("EKS cluster CA data is invalid") from error
    if b"-----BEGIN CERTIFICATE-----" not in certificate:
        raise RuntimeError("EKS cluster CA data is not a PEM certificate")
    descriptor, path = tempfile.mkstemp(prefix="eks-ca-", suffix=".crt")
    try:
        os.fchmod(descriptor, 0o600)
        output = os.fdopen(descriptor, "wb")
        descriptor = -1
        with output:
            output.write(certificate)
    except Exception:
        if descriptor >= 0:
            os.close(descriptor)
        with suppress(OSError):
            os.unlink(path)
        raise
    return path


def build_custom_objects_api(
    config: GeneratorConfig,
    *,
    session: Any | None = None,
) -> Any:
    """Create a token-refreshing, CA-verified EKS CustomObjectsApi."""

    if session is None:
        import boto3

        session = boto3.session.Session(region_name=config.aws_region)
    eks_client = session.client("eks", region_name=config.aws_region)
    response = eks_client.describe_cluster(name=config.cluster_name)
    cluster = response.get("cluster")
    if not isinstance(cluster, dict):
        raise RuntimeError("EKS describe_cluster response has no cluster")
    endpoint = cluster.get("endpoint")
    authority = cluster.get("certificateAuthority")
    ca_data = authority.get("data") if isinstance(authority, dict) else None
    if (
        not isinstance(endpoint, str)
        or urlsplit(endpoint).scheme != "https"
        or not isinstance(ca_data, str)
    ):
        raise RuntimeError("EKS cluster endpoint or CA data is invalid")

    ca_path = _write_cluster_ca(ca_data)
    try:
        from kubernetes import client

        configuration = client.Configuration()
        configuration.host = endpoint
        configuration.verify_ssl = True
        configuration.ssl_ca_cert = ca_path
        configuration.api_key_prefix["authorization"] = "Bearer"

        def refresh_token(active_configuration: Any) -> None:
            active_configuration.api_key["authorization"] = generate_eks_bearer_token(
                config.cluster_name,
                config.aws_region,
                session=session,
            )

        configuration.refresh_api_key_hook = refresh_token
        refresh_token(configuration)
        api_client = client.ApiClient(configuration=configuration)
        weakref.finalize(api_client, _remove_file, ca_path)
        return client.CustomObjectsApi(api_client)
    except Exception:
        _remove_file(ca_path)
        raise


def _remove_file(path: str) -> None:
    with suppress(OSError):
        os.unlink(path)
