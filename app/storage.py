import hashlib
import boto3
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional
from botocore.client import Config

from app.config import settings


class StorageBackend(ABC):
    @abstractmethod
    def put(self, key: str, data: bytes) -> None: ...

    @abstractmethod
    def get(self, key: str) -> bytes: ...

    @abstractmethod
    def exists(self, key: str) -> bool: ...

    @abstractmethod
    def size(self, key: str) -> int: ...

    @abstractmethod
    def delete(self, key: str) -> None: ...

    @abstractmethod
    def hash_sha256(self, key: str) -> str: ...

    @abstractmethod
    def presigned_get_url(self, key: str, expires_seconds: int = 300) -> Optional[str]:
        pass

    def local_path(self, key: str) -> Optional[Path]:
        return None


class LocalDiskStorage(StorageBackend):
    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Path:
        return self.base_dir / Path(key).name

    def put(self, key: str, data: bytes) -> None:
        self._path(key).write_bytes(data)

    def get(self, key: str) -> bytes:
        return self._path(key).read_bytes()

    def exists(self, key: str) -> bool:
        return self._path(key).exists()

    def size(self, key: str) -> int:
        return self._path(key).stat().st_size

    def delete(self, key: str) -> None:
        self._path(key).unlink(missing_ok=True)

    def hash_sha256(self, key: str) -> str:
        sha256 = hashlib.sha256()
        with open(self._path(key), "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    def presigned_get_url(self, key: str, expires_seconds: int = 300) -> Optional[str]:
        return None

    def local_path(self, key: str) -> Optional[Path]:
        return self._path(key)


class S3Storage(StorageBackend):
    def __init__(self, bucket: str, endpoint_url: str, access_key_id: str, secret_access_key: str):
        self.bucket = bucket
        self.client = boto3.client(
            "s3",
            endpoint_url=endpoint_url,
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name="auto",
            config=Config(signature_version="s3v4", s3={"addressing_style": "virtual"}),
        )

    def put(self, key: str, data: bytes) -> None:
        self.client.put_object(Bucket=self.bucket, Key=key, Body=data)

    def get(self, key: str) -> bytes:
        body = self.client.get_object(Bucket=self.bucket, Key=key)["Body"]
        return body.read()

    def exists(self, key: str) -> bool:
        try:
            self.client.head_object(Bucket=self.bucket, Key=key)
            return True
        except Exception:
            return False

    def size(self, key: str) -> int:
        return self.client.head_object(Bucket=self.bucket, Key=key)["ContentLength"]

    def delete(self, key: str) -> None:
        self.client.delete_object(Bucket=self.bucket, Key=key)

    def hash_sha256(self, key: str) -> str:
        sha256 = hashlib.sha256()
        body = self.client.get_object(Bucket=self.bucket, Key=key)["Body"]
        for chunk in iter(lambda: body.read(8192), b""):
            sha256.update(chunk)
        return sha256.hexdigest()

    def presigned_get_url(self, key: str, expires_seconds: int = 300) -> Optional[str]:
        return self.client.generate_presigned_url(
            "get_object",
            Params={"Bucket": self.bucket, "Key": key},
            ExpiresIn=expires_seconds,
        )


def get_storage() -> StorageBackend:
    if settings.STORAGE_BACKEND == "s3":
        return S3Storage(
            bucket=settings.R2_BUCKET,
            endpoint_url=settings.R2_ENDPOINT_URL,
            access_key_id=settings.R2_ACCESS_KEY_ID,
            secret_access_key=settings.R2_SECRET_ACCESS_KEY,
        )
    return LocalDiskStorage(settings.EVIDENCE_STORAGE_PATH)


storage = get_storage()