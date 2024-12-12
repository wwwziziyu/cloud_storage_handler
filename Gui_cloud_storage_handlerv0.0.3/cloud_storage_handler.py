# -*- coding: utf-8 -*-
"""
cloud_storage_handler.py
-------------------------
多云对象存储服务的统一处理基类与各云厂商实现类。

此版本在原有基础上增加更多安全性相关的检查，并对5大云厂商进行完整实现：
1. 凭据有效性校验
2. Bucket存在性检测
3. 对象上传与下载
4. 对象存在性检测
5. ACL/权限检测
6. Bucket加密状态检测 (Encryption)
7. Bucket版本管理状态检测 (Versioning)
8. Bucket访问日志配置检测 (Access Logging)
9. Bucket策略(Bucket Policy)检查

针对未提供相应API的情况（如BOS缺乏加密、版本管理、访问日志、Bucket Policy相关API），统一返回False或空字符串，不抛出异常。
"""

from abc import ABC, abstractmethod
import json
import oss2
import os
import sys
from baidubce.bce_client_configuration import BceClientConfiguration
from baidubce.auth.bce_credentials import BceCredentials
from baidubce.services.bos.bos_client import BosClient
from baidubce import exception as bos_exception
from qcloud_cos import CosConfig, CosS3Client
from qcloud_cos.cos_exception import CosServiceError, CosClientError
import boto3
from botocore.exceptions import ClientError, NoCredentialsError

# 华为云OBS需要确保SDK安装后可用下述import，如有版本问题需根据实际版本调整
# 文档参考：https://support.huaweicloud.com/sdk-python-devg-obs/obs_26_1004.html
from obs import ObsClient


class BaseCloudHandler(ABC):
    def __init__(self, ak: str, sk: str, token: str, endpoint: str):
        self.ak = ak
        self.sk = sk
        self.token = token
        self.endpoint = endpoint

    @abstractmethod
    def check_credentials_valid(self) -> bool:
        pass

    @abstractmethod
    def does_bucket_exist(self, bucket_name: str) -> bool:
        pass

    @abstractmethod
    def upload_object_from_string(self, bucket_name: str, object_key: str, content: str) -> dict:
        pass

    @abstractmethod
    def download_object_to_string(self, bucket_name: str, object_key: str) -> str:
        pass

    @abstractmethod
    def does_object_exist(self, bucket_name: str, object_key: str) -> bool:
        pass

    @abstractmethod
    def check_permissions(self, bucket_name: str, object_key: str) -> bool:
        pass

    @abstractmethod
    def check_encryption(self, bucket_name: str) -> bool:
        pass

    @abstractmethod
    def get_encryption_details(self, bucket_name: str) -> dict:
        pass

    @abstractmethod
    def check_versioning(self, bucket_name: str) -> bool:
        pass

    @abstractmethod
    def check_access_logging(self, bucket_name: str) -> bool:
        pass

    @abstractmethod
    def check_bucket_policy(self, bucket_name: str) -> str:
        pass

    @abstractmethod
    def check_cors(self, bucket_name: str) -> list:
        pass

    @abstractmethod
    def check_bucket_tagging(self, bucket_name: str) -> dict:
        pass

    @abstractmethod
    def check_lifecycle(self, bucket_name: str) -> list:
        pass

    @abstractmethod
    def check_object_tagging(self, bucket_name: str, object_key: str) -> dict:
        pass

    @abstractmethod
    def get_object_storage_class(self, bucket_name: str, object_key: str) -> str:
        pass

    @abstractmethod
    def analyze_access_logs(self, bucket_name: str, log_prefix: str = "") -> dict:
        pass

    @abstractmethod
    def list_buckets(self) -> list:
        pass

    @abstractmethod
    def list_objects(self, bucket_name: str, prefix: str = "") -> list:
        pass

    @abstractmethod
    def search_sensitive_info(self, bucket_name: str, prefix: str = "", keywords: list = None) -> dict:
        pass

    @abstractmethod
    def get_object_url(self, bucket_name: str, object_key: str) -> str:
        pass

    @abstractmethod
    def list_objects(self, bucket_name: str, prefix: str = "", max_keys: int = 100, marker: str = None) -> (list, str):
        pass

class BosHandler(BaseCloudHandler):
    """BOS(Baidu Object Storage)实现。"""
    def __init__(self, ak, sk, token, endpoint):
        super().__init__(ak, sk, token, endpoint)
        config = BceClientConfiguration(
            credentials=BceCredentials(self.ak, self.sk),
            endpoint=self.endpoint,
            security_token=self.token
        )
        self.client = BosClient(config)

    def check_credentials_valid(self) -> bool:
        try:
            self.client.list_buckets()
            return True
        except bos_exception.BceBaseException:
            return False

    def does_bucket_exist(self, bucket_name: str) -> bool:
        return self.client.does_bucket_exist(bucket_name)

    def upload_object_from_string(self, bucket_name: str, object_key: str, content: str) -> dict:
        try:
            res = self.client.put_object_from_string(bucket_name, object_key, content)
            return res.__dict__ if res else {}
        except bos_exception.BceBaseException:
            return {}

    def download_object_to_string(self, bucket_name: str, object_key: str) -> str:
        try:
            response = self.client.get_object_as_string(bucket_name, object_key)
            return response
        except bos_exception.BceBaseException:
            return ""

    def does_object_exist(self, bucket_name: str, object_key: str) -> bool:
        try:
            self.client.get_object_meta_data(bucket_name, object_key)
            return True
        except bos_exception.BceHttpClientError:
            return False

    def check_permissions(self, bucket_name: str, object_key: str) -> bool:
        try:
            self.client.get_object_acl(bucket_name, object_key)
            return True
        except bos_exception.BceBaseException:
            return False

    def check_encryption(self, bucket_name: str) -> bool:
        # BOS目前无直接API获取加密配置，返回False
        return False

    def get_encryption_details(self, bucket_name: str) -> dict:
        # BOS目前无加密详情API，返回空字典
        return {}

    def check_versioning(self, bucket_name: str) -> bool:
        # BOS尚无版本管理API，返回False
        return False

    def check_access_logging(self, bucket_name: str) -> bool:
        # BOS尚无访问日志配置API，返回False
        return False

    def check_bucket_policy(self, bucket_name: str) -> str:
        # BOS无Bucket Policy概念
        return ""

    def check_cors(self, bucket_name: str) -> list:
        # BOS若支持CORS，可实现相应逻辑；否则返回空列表
        # 假设不支持，返回空列表
        return []

    def check_bucket_tagging(self, bucket_name: str) -> dict:
        # BOS若支持Tagging，可实现相应逻辑；否则返回空字典
        # 假设不支持，返回空字典
        return {}

    def check_lifecycle(self, bucket_name: str) -> list:
        # BOS若支持Lifecycle，可实现相应逻辑；否则返回空列表
        # 假设不支持，返回空列表
        return []

    def check_object_tagging(self, bucket_name: str, object_key: str) -> dict:
        # BOS若支持Object Tagging，可实现相应逻辑；否则返回空字典
        # 假设不支持，返回空字典
        return {}

    def get_object_storage_class(self, bucket_name: str, object_key: str) -> str:
        try:
            obj_info = self.client.get_object_meta_data(bucket_name, object_key)
            return obj_info.get('x-bce-storage-class', '')
        except bos_exception.BceBaseException:
            return ""

    def analyze_access_logs(self, bucket_name: str, log_prefix: str = "") -> dict:
        """
        分析Baidu BOS的访问日志文件。
        返回包含统计信息的字典。
        """
        # BOS的访问日志分析需根据具体日志格式实现，此处简化为返回空字典
        return {}

    def list_buckets(self) -> list:
        try:
            resp = self.client.list_buckets()
            return [b.name for b in resp.buckets]
        except bos_exception.BceBaseException:
            return []

    def list_objects(self, bucket_name: str, prefix: str = "") -> list:
        objects = []
        marker = None
        try:
            while True:
                resp = self.client.list_objects(bucket_name, prefix=prefix, marker=marker, max_keys=1000)
                for obj in resp.contents:
                    objects.append(obj.key)
                if resp.is_truncated:
                    marker = resp.next_marker
                else:
                    break
        except bos_exception.BceBaseException:
            pass
        return objects

    def search_sensitive_info(self, bucket_name: str, prefix: str = "", keywords: list = None) -> dict:
        if keywords is None:
            keywords = []
        matched = {}
        all_objects = self.list_objects(bucket_name, prefix)
        for obj_key in all_objects:
            try:
                content = self.download_object_to_string(bucket_name, obj_key)
                found = [kw for kw in keywords if kw in content]
                if found:
                    matched[obj_key] = found
            except Exception:
                pass
        return {"matched_objects": matched} if matched else {}

    def get_object_url(self, bucket_name: str, object_key: str) -> str:
        # BOS公共URL格式: http://{bucket}.{endpoint}/{object_key}
        endpoint = self.endpoint.replace("http://", "").replace("https://", "")
        return f"http://{bucket_name}.{endpoint}/{object_key}"
    
class AliyunHandler(BaseCloudHandler):
    """阿里云OSS实现。"""

    def __init__(self, ak, sk, token, endpoint):
        super().__init__(ak, sk, token, endpoint)
        if self.token:
            self.auth = oss2.StsAuth(self.ak, self.sk, self.token)
        else:
            self.auth = oss2.Auth(self.ak, self.sk)
        self.service = oss2.Service(self.auth, self.endpoint)

    def check_credentials_valid(self) -> bool:
        try:
            _ = self.service.list_buckets()
            return True
        except oss2.exceptions.OssError:
            return False

    def does_bucket_exist(self, bucket_name: str) -> bool:
        bucket = oss2.Bucket(self.auth, self.endpoint, bucket_name)
        try:
            bucket.get_bucket_info()
            return True
        except oss2.exceptions.OssError:
            return False

    def upload_object_from_string(self, bucket_name: str, object_key: str, content: str) -> dict:
        bucket = oss2.Bucket(self.auth, self.endpoint, bucket_name)
        result = bucket.put_object(object_key, content)
        return {
            "etag": result.etag,
            "status": result.status,
            "request_id": result.request_id
        }

    def download_object_to_string(self, bucket_name: str, object_key: str) -> str:
        bucket = oss2.Bucket(self.auth, self.endpoint, bucket_name)
        result = bucket.get_object(object_key)
        content = result.read()
        if isinstance(content, bytes):
            content = content.decode('utf-8', errors='replace')
        return content

    def does_object_exist(self, bucket_name: str, object_key: str) -> bool:
        bucket = oss2.Bucket(self.auth, self.endpoint, bucket_name)
        try:
            bucket.head_object(object_key)
            return True
        except oss2.exceptions.OssError:
            return False

    def check_permissions(self, bucket_name: str, object_key: str) -> bool:
        bucket = oss2.Bucket(self.auth, self.endpoint, bucket_name)
        try:
            bucket.get_object_acl(object_key)
            return True
        except oss2.exceptions.OssError:
            return False

    def check_encryption(self, bucket_name: str) -> bool:
        bucket = oss2.Bucket(self.auth, self.endpoint, bucket_name)
        try:
            bucket.get_bucket_encryption()
            return True
        except oss2.exceptions.NoSuchEncryptionConfiguration:
            return False
        except oss2.exceptions.OssError:
            return False

    def get_encryption_details(self, bucket_name: str) -> dict:
        """
        获取Bucket加密详细信息。
        返回示例：
        {
            "EncryptionDetails": [
                {
                    "SSEAlgorithm": "AES256",
                    "KMSMasterKeyID": "your-kms-key-id"
                }
            ]
        }
        若无加密配置，则返回空字典。
        """
        bucket = oss2.Bucket(self.auth, self.endpoint, bucket_name)
        try:
            encryption = bucket.get_bucket_encryption()
            rules = encryption.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])
            details = []
            for rule in rules:
                sse = rule.get('ServerSideEncryptionByDefault', {})
                algorithm = sse.get('SSEAlgorithm', '')
                kms_key_id = sse.get('KMSMasterKeyID', '')
                details.append({
                    "SSEAlgorithm": algorithm,
                    "KMSMasterKeyID": kms_key_id
                })
            return {"EncryptionDetails": details} if details else {}
        except oss2.exceptions.NoSuchEncryptionConfiguration:
            return {}
        except oss2.exceptions.OssError:
            return {}

    def check_versioning(self, bucket_name: str) -> bool:
        bucket = oss2.Bucket(self.auth, self.endpoint, bucket_name)
        try:
            vres = bucket.get_bucket_versioning()
            return (vres.status == 'Enabled')
        except oss2.exceptions.OssError:
            return False

    def check_access_logging(self, bucket_name: str) -> bool:
        bucket = oss2.Bucket(self.auth, self.endpoint, bucket_name)
        try:
            logging_config = bucket.get_bucket_logging()
            # 如果 target_bucket 存在且 target_prefix 非空，则认为已启用日志
            return bool(logging_config.target_bucket and logging_config.target_prefix)
        except oss2.exceptions.OssError:
            return False

    def check_bucket_policy(self, bucket_name: str) -> str:
        # OSS不提供类似AWS S3的Bucket Policy概念，权限主要通过ACL和RAM控制
        return ""

    def check_cors(self, bucket_name: str) -> list:
        """
        检查Bucket的CORS配置。
        返回CORS规则的列表，每个规则包含Origin、AllowedMethod、AllowedHeader等信息。
        若无CORS配置则返回空列表。
        """
        bucket = oss2.Bucket(self.auth, self.endpoint, bucket_name)
        try:
            cors_config = bucket.get_bucket_cors()
            rules = cors_config.get('CORSRules', [])
            return rules
        except oss2.exceptions.NoSuchCORSConfiguration:
            return []
        except oss2.exceptions.OssError:
            return []

    def check_bucket_tagging(self, bucket_name: str) -> dict:
        """
        返回Bucket标签的字典 {tag_key: tag_value}，若无标签则返回空字典。
        """
        bucket = oss2.Bucket(self.auth, self.endpoint, bucket_name)
        try:
            tagging = bucket.get_bucket_tagging()
            tags = tagging.get('TagSet', [])
            tag_dict = {tag['Key']: tag['Value'] for tag in tags}
            return tag_dict
        except oss2.exceptions.NoSuchTagging:
            return {}
        except oss2.exceptions.OssError:
            return {}

    def check_lifecycle(self, bucket_name: str) -> list:
        """
        检查Bucket的生命周期配置规则。
        返回生命周期规则的列表，每个元素包含ID、Prefix、Status等信息。
        若未配置Lifecycle则返回空列表。
        """
        bucket = oss2.Bucket(self.auth, self.endpoint, bucket_name)
        try:
            lifecycle = bucket.get_bucket_lifecycle()
            rules = lifecycle.get('Rules', [])
            return rules
        except oss2.exceptions.NoSuchLifecycle:
            return []
        except oss2.exceptions.OssError:
            return []

    def check_object_tagging(self, bucket_name: str, object_key: str) -> dict:
        """
        返回对象标签的字典 {tag_key: tag_value}，若无标签则返回空字典。
        """
        bucket = oss2.Bucket(self.auth, self.endpoint, bucket_name)
        try:
            tagging = bucket.get_object_tagging(object_key)
            tags = tagging.get('TagSet', [])
            tag_dict = {tag['Key']: tag['Value'] for tag in tags}
            return tag_dict
        except oss2.exceptions.NoSuchTagging:
            return {}
        except oss2.exceptions.OssError:
            return {}

    def get_object_storage_class(self, bucket_name: str, object_key: str) -> str:
        """
        获取指定对象的存储类型（例如 Standard、IA、Archive 等）。
        若无法获取或无此概念则返回空字符串。
        """
        bucket = oss2.Bucket(self.auth, self.endpoint, bucket_name)
        try:
            obj_info = bucket.get_object_info(object_key)
            storage_class = obj_info.storage_class
            return storage_class
        except oss2.exceptions.OssError:
            return ""

    def analyze_access_logs(self, bucket_name: str, log_prefix: str = "") -> dict:
        """
        分析访问日志文件（需先开启访问日志并指定日志前缀）。
        返回包含统计信息的字典，例如：
        {
            "total_requests": 100,
            "unique_ips": 10,
            "suspicious_ips": ["1.2.3.4"],
            "high_frequency_objects": ["obj1", "obj2"]
        }
        若未开启日志或无法分析则返回空字典。
        """
        from collections import defaultdict

        log_objects = self.list_objects(bucket_name, prefix=log_prefix)
        if not log_objects:
            return {}

        total_requests = 0
        ip_counter = defaultdict(int)
        object_counter = defaultdict(int)
        suspicious_ips = set()
        high_frequency_objects = set()
        FREQUENCY_THRESHOLD = 100  # 自定义阈值

        for log_obj in log_objects[:10]:  # 只分析最近的10个日志文件，避免耗时
            try:
                log_content = self.download_object_to_string(bucket_name, log_obj)
                for line in log_content.splitlines():
                    # 根据实际日志格式进行解析，以下为假设格式
                    parts = line.split()
                    if len(parts) < 10:
                        continue
                    ip = parts[3]
                    object_key = parts[6]
                    total_requests += 1
                    ip_counter[ip] += 1
                    object_counter[object_key] += 1
            except Exception:
                continue

        for ip, count in ip_counter.items():
            if count > FREQUENCY_THRESHOLD:
                suspicious_ips.add(ip)

        for obj, count in object_counter.items():
            if count > FREQUENCY_THRESHOLD:
                high_frequency_objects.add(obj)

        return {
            "total_requests": total_requests,
            "unique_ips": len(ip_counter),
            "suspicious_ips": list(suspicious_ips),
            "high_frequency_objects": list(high_frequency_objects)
        }

    def list_buckets(self) -> list:
        try:
            response = self.service.list_buckets()
            buckets = [b.name for b in response.buckets]
            return buckets
        except oss2.exceptions.OssError:
            return []

    def list_objects(self, bucket_name: str, prefix: str = "") -> list:
        objects = []
        bucket = oss2.Bucket(self.auth, self.endpoint, bucket_name)
        try:
            for obj_info in oss2.ObjectIterator(bucket, prefix=prefix):
                objects.append(obj_info.key)
        except oss2.exceptions.OssError:
            return []
        return objects

    def search_sensitive_info(self, bucket_name: str, prefix: str = "", keywords: list = None) -> dict:
        if keywords is None:
            keywords = []
        matched = {}
        all_objects = self.list_objects(bucket_name, prefix=prefix)
        for obj_key in all_objects:
            try:
                content = self.download_object_to_string(bucket_name, obj_key)
                found = [kw for kw in keywords if kw in content]
                if found:
                    matched[obj_key] = found
            except Exception:
                pass
        return {"matched_objects": matched} if matched else {}

    def get_object_url(self, bucket_name: str, object_key: str) -> str:
        # OSS公共URL格式: http://{bucket}.{endpoint}/{object_key}
        return f"http://{bucket_name}.{self.endpoint}/{object_key}"
    
    def list_objects(self, bucket_name: str, prefix: str = "", max_keys: int = 100, marker: str = None) -> (list, str):
        objects = []
        bucket = oss2.Bucket(self.auth, self.endpoint, bucket_name)
        try:
            if marker:
                iterator = oss2.ObjectIterator(bucket, prefix=prefix, max_keys=max_keys, marker=marker)
            else:
                iterator = oss2.ObjectIterator(bucket, prefix=prefix, max_keys=max_keys)
            
            for obj_info in iterator:
                objects.append(obj_info.key)
                if len(objects) >= max_keys:
                    break

            # 获取下一个标记
            if len(objects) >= max_keys:
                next_marker = objects[-1]
            else:
                next_marker = None
        except oss2.exceptions.OssError:
            return [], None
        return objects, next_marker

class TencentHandler(BaseCloudHandler):
    """腾讯云COS实现。"""
    def __init__(self, ak, sk, token, endpoint):
        super().__init__(ak, sk, token, endpoint)
        region = None
        parts = endpoint.replace("https://", "").replace("http://", "").split('.')
        if len(parts) >= 2 and parts[0] == "cos":
            region = parts[1]
        elif len(parts) >= 3 and parts[0].startswith("cos"):
            # 处理类似 cos.ap-beijing.myqcloud.com 的情况
            region = parts[1]
        else:
            raise ValueError("无法从endpoint中提取region，请提供正确的endpoint或修改代码。")

        config_params = {
            'Region': region,
            'SecretId': self.ak,
            'SecretKey': self.sk
        }
        if self.token:
            config_params['Token'] = self.token

        config = CosConfig(**config_params)
        self.client = CosS3Client(config)

    def check_credentials_valid(self) -> bool:
        try:
            self.client.list_buckets()
            return True
        except (CosServiceError, CosClientError):
            return False

    def does_bucket_exist(self, bucket_name: str) -> bool:
        try:
            self.client.head_bucket(Bucket=bucket_name)
            return True
        except (CosServiceError, CosClientError):
            return False

    def upload_object_from_string(self, bucket_name: str, object_key: str, content: str) -> dict:
        try:
            response = self.client.put_object(
                Bucket=bucket_name,
                Key=object_key,
                Body=content.encode('utf-8')
            )
            return {
                "etag": response.get("ETag", ""),
                "status": response.get("ResponseMetadata", {}).get("HTTPStatusCode", 200),
                "request_id": response.get("ResponseMetadata", {}).get("RequestId", "")
            }
        except (CosServiceError, CosClientError):
            return {}

    def download_object_to_string(self, bucket_name: str, object_key: str) -> str:
        try:
            response = self.client.get_object(
                Bucket=bucket_name,
                Key=object_key
            )
            body = response['Body'].read()
            return body.decode('utf-8', errors='replace')
        except (CosServiceError, CosClientError):
            return ""

    def does_object_exist(self, bucket_name: str, object_key: str) -> bool:
        try:
            self.client.head_object(Bucket=bucket_name, Key=object_key)
            return True
        except (CosServiceError, CosClientError):
            return False

    def check_permissions(self, bucket_name: str, object_key: str) -> bool:
        try:
            self.client.get_object_acl(Bucket=bucket_name, Key=object_key)
            return True
        except (CosServiceError, CosClientError):
            return False

    def check_encryption(self, bucket_name: str) -> bool:
        try:
            self.client.get_bucket_encryption(Bucket=bucket_name)
            return True
        except (CosServiceError, CosClientError):
            return False

    def get_encryption_details(self, bucket_name: str) -> dict:
        try:
            encryption = self.client.get_bucket_encryption(Bucket=bucket_name)
            rules = encryption.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])
            details = []
            for rule in rules:
                sse = rule.get('ApplyServerSideEncryptionByDefault', {})
                algorithm = sse.get('SSEAlgorithm', '')
                kms_key_id = sse.get('KMSMasterKeyID', '')
                details.append({
                    "SSEAlgorithm": algorithm,
                    "KMSMasterKeyID": kms_key_id
                })
            return {"EncryptionDetails": details} if details else {}
        except (CosServiceError, CosClientError):
            return {}

    def check_versioning(self, bucket_name: str) -> bool:
        try:
            versioning = self.client.get_bucket_versioning(Bucket=bucket_name)
            return versioning.get('Status', '') == 'Enabled'
        except (CosServiceError, CosClientError):
            return False

    def check_access_logging(self, bucket_name: str) -> bool:
        try:
            logging = self.client.get_bucket_logging(Bucket=bucket_name)
            return 'LoggingEnabled' in logging
        except (CosServiceError, CosClientError):
            return False

    def check_bucket_policy(self, bucket_name: str) -> str:
        try:
            policy = self.client.get_bucket_policy(Bucket=bucket_name)
            return policy.get('Policy', '')
        except (CosServiceError, CosClientError):
            return ""

    def check_cors(self, bucket_name: str) -> list:
        try:
            cors = self.client.get_bucket_cors(Bucket=bucket_name)
            return cors.get('CORSRules', [])
        except (CosServiceError, CosClientError):
            return []

    def check_bucket_tagging(self, bucket_name: str) -> dict:
        try:
            tagging = self.client.get_bucket_tagging(Bucket=bucket_name)
            tags = tagging.get('TagSet', [])
            tag_dict = {tag['Key']: tag['Value'] for tag in tags}
            return tag_dict
        except (CosServiceError, CosClientError):
            return {}

    def check_lifecycle(self, bucket_name: str) -> list:
        try:
            lifecycle = self.client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
            return lifecycle.get('Rules', [])
        except (CosServiceError, CosClientError):
            return []

    def check_object_tagging(self, bucket_name: str, object_key: str) -> dict:
        try:
            tagging = self.client.get_object_tagging(Bucket=bucket_name, Key=object_key)
            tags = tagging.get('TagSet', [])
            tag_dict = {tag['Key']: tag['Value'] for tag in tags}
            return tag_dict
        except (CosServiceError, CosClientError):
            return {}

    def get_object_storage_class(self, bucket_name: str, object_key: str) -> str:
        try:
            response = self.client.head_object(Bucket=bucket_name, Key=object_key)
            return response.get('StorageClass', '')
        except (CosServiceError, CosClientError):
            return ""

    def analyze_access_logs(self, bucket_name: str, log_prefix: str = "") -> dict:
        """
        分析腾讯云COS的访问日志文件。
        返回包含统计信息的字典。
        """
        import re
        from collections import defaultdict

        log_objects = self.list_objects(bucket_name, prefix=log_prefix)
        if not log_objects:
            return {}

        total_requests = 0
        ip_counter = defaultdict(int)
        object_counter = defaultdict(int)
        suspicious_ips = set()
        high_frequency_objects = set()
        FREQUENCY_THRESHOLD = 100

        for log_obj in log_objects[:10]:  # 只分析最近的10个日志文件，避免耗时
            try:
                log_content = self.download_object_to_string(bucket_name, log_obj)
                for line in log_content.splitlines():
                    # 根据实际日志格式进行解析，以下为假设格式
                    parts = line.split()
                    if len(parts) < 10:
                        continue
                    ip = parts[3]
                    object_key = parts[6]
                    total_requests += 1
                    ip_counter[ip] += 1
                    object_counter[object_key] += 1
            except Exception:
                continue

        for ip, count in ip_counter.items():
            if count > FREQUENCY_THRESHOLD:
                suspicious_ips.add(ip)

        for obj, count in object_counter.items():
            if count > FREQUENCY_THRESHOLD:
                high_frequency_objects.add(obj)

        return {
            "total_requests": total_requests,
            "unique_ips": len(ip_counter),
            "suspicious_ips": list(suspicious_ips),
            "high_frequency_objects": list(high_frequency_objects)
        }

    def list_buckets(self) -> list:
        try:
            response = self.client.list_buckets()
            return [b['Name'] for b in response.get('Buckets', [])]
        except (CosServiceError, CosClientError):
            return []

    def list_objects(self, bucket_name: str, prefix: str = "") -> list:
        objects = []
        marker = ''
        try:
            while True:
                resp = self.client.list_objects_v2(
                    Bucket=bucket_name,
                    Prefix=prefix,
                    ContinuationToken=marker,
                    MaxKeys=1000
                )
                for obj in resp.get('Contents', []):
                    objects.append(obj['Key'])
                if resp.get('IsTruncated'):
                    marker = resp.get('NextContinuationToken', '')
                else:
                    break
        except (CosServiceError, CosClientError):
            pass
        return objects

    def search_sensitive_info(self, bucket_name: str, prefix: str = "", keywords: list = None) -> dict:
        if keywords is None:
            keywords = []
        matched = {}
        all_objects = self.list_objects(bucket_name, prefix)
        for obj_key in all_objects:
            try:
                content = self.download_object_to_string(bucket_name, obj_key)
                found = [kw for kw in keywords if kw in content]
                if found:
                    matched[obj_key] = found
            except Exception:
                pass
        return {"matched_objects": matched} if matched else {}

    def get_object_url(self, bucket_name: str, object_key: str) -> str:
        return f"https://{bucket_name}.cos.{self.client._config.Region}.myqcloud.com/{object_key}"

class AWSHandler(BaseCloudHandler):
    """AWS S3实现。"""
    def __init__(self, ak, sk, token, endpoint):
        super().__init__(ak, sk, token, endpoint)
        import re
        match = re.search(r"s3[.-]([a-z0-9-]+)\.amazonaws\.com", self.endpoint)
        if match:
            region = match.group(1)
        else:
            region = "us-east-1"

        session_kwargs = {
            "aws_access_key_id": self.ak,
            "aws_secret_access_key": self.sk,
            "region_name": region
        }
        if self.token:
            session_kwargs["aws_session_token"] = self.token

        self.s3_client = boto3.client('s3', **session_kwargs)

    def check_credentials_valid(self) -> bool:
        try:
            self.s3_client.list_buckets()
            return True
        except (NoCredentialsError, ClientError):
            return False

    def does_bucket_exist(self, bucket_name: str) -> bool:
        try:
            self.s3_client.head_bucket(Bucket=bucket_name)
            return True
        except ClientError:
            return False

    def upload_object_from_string(self, bucket_name: str, object_key: str, content: str) -> dict:
        response = self.s3_client.put_object(
            Bucket=bucket_name,
            Key=object_key,
            Body=content.encode('utf-8')
        )
        return {
            "etag": response.get("ETag", ""),
            "status": response["ResponseMetadata"].get("HTTPStatusCode", 200),
            "request_id": response["ResponseMetadata"].get("RequestId", "")
        }

    def download_object_to_string(self, bucket_name: str, object_key: str) -> str:
        try:
            response = self.s3_client.get_object(Bucket=bucket_name, Key=object_key)
            body = response['Body'].read()
            return body.decode('utf-8', errors='replace')
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchKey':
                raise FileNotFoundError(f"Object '{object_key}' not found in '{bucket_name}'.")
            raise e

    def does_object_exist(self, bucket_name: str, object_key: str) -> bool:
        try:
            self.s3_client.head_object(Bucket=bucket_name, Key=object_key)
            return True
        except ClientError:
            return False

    def check_permissions(self, bucket_name: str, object_key: str) -> bool:
        try:
            self.s3_client.get_object_acl(Bucket=bucket_name, Key=object_key)
            return True
        except ClientError:
            return False

    def check_encryption(self, bucket_name: str) -> bool:
        try:
            self.s3_client.get_bucket_encryption(Bucket=bucket_name)
            return True
        except ClientError as e:
            if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                return False
            return False

    def get_encryption_details(self, bucket_name: str) -> dict:
        try:
            encryption = self.s3_client.get_bucket_encryption(Bucket=bucket_name)
            rules = encryption.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])
            details = []
            for rule in rules:
                sse = rule.get('ApplyServerSideEncryptionByDefault', {})
                algorithm = sse.get('SSEAlgorithm', '')
                kms_key_id = sse.get('KMSMasterKeyID', '')
                details.append({
                    "SSEAlgorithm": algorithm,
                    "KMSMasterKeyID": kms_key_id
                })
            return {"EncryptionDetails": details} if details else {}
        except ClientError:
            return {}

    def check_versioning(self, bucket_name: str) -> bool:
        try:
            vers = self.s3_client.get_bucket_versioning(Bucket=bucket_name)
            return vers.get('Status', '') == 'Enabled'
        except ClientError:
            return False

    def check_access_logging(self, bucket_name: str) -> bool:
        try:
            log = self.s3_client.get_bucket_logging(Bucket=bucket_name)
            return 'LoggingEnabled' in log
        except ClientError:
            return False

    def check_bucket_policy(self, bucket_name: str) -> str:
        try:
            policy = self.s3_client.get_bucket_policy(Bucket=bucket_name)
            return policy['Policy']
        except ClientError:
            return ""

    def check_cors(self, bucket_name: str) -> list:
        try:
            cors = self.s3_client.get_bucket_cors(Bucket=bucket_name)
            return cors.get('CORSRules', [])
        except ClientError:
            return []

    def check_bucket_tagging(self, bucket_name: str) -> dict:
        try:
            tagging = self.s3_client.get_bucket_tagging(Bucket=bucket_name)
            tags = tagging.get('TagSet', [])
            tag_dict = {tag['Key']: tag['Value'] for tag in tags}
            return tag_dict
        except ClientError:
            return {}

    def check_lifecycle(self, bucket_name: str) -> list:
        try:
            lifecycle = self.s3_client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
            return lifecycle.get('Rules', [])
        except ClientError:
            return []

    def check_object_tagging(self, bucket_name: str, object_key: str) -> dict:
        try:
            tagging = self.s3_client.get_object_tagging(Bucket=bucket_name, Key=object_key)
            tags = tagging.get('TagSet', [])
            tag_dict = {tag['Key']: tag['Value'] for tag in tags}
            return tag_dict
        except ClientError:
            return {}

    def get_object_storage_class(self, bucket_name: str, object_key: str) -> str:
        try:
            response = self.s3_client.head_object(Bucket=bucket_name, Key=object_key)
            return response.get('StorageClass', '')
        except ClientError:
            return ""

    def analyze_access_logs(self, bucket_name: str, log_prefix: str = "") -> dict:
        """
        分析AWS S3的访问日志文件。
        返回包含统计信息的字典。
        """
        import re
        from collections import defaultdict

        log_objects = self.list_objects(bucket_name, prefix=log_prefix)
        if not log_objects:
            return {}

        total_requests = 0
        ip_counter = defaultdict(int)
        object_counter = defaultdict(int)
        suspicious_ips = set()
        high_frequency_objects = set()
        FREQUENCY_THRESHOLD = 100

        for log_obj in log_objects[:10]:  # 分析最近的10个日志文件
            try:
                log_content = self.download_object_to_string(bucket_name, log_obj)
                for line in log_content.splitlines():
                    parts = line.split()
                    if len(parts) < 10:
                        continue
                    ip = parts[3]
                    object_key = parts[6]
                    total_requests += 1
                    ip_counter[ip] += 1
                    object_counter[object_key] += 1
            except Exception:
                continue

        for ip, count in ip_counter.items():
            if count > FREQUENCY_THRESHOLD:
                suspicious_ips.add(ip)

        for obj, count in object_counter.items():
            if count > FREQUENCY_THRESHOLD:
                high_frequency_objects.add(obj)

        return {
            "total_requests": total_requests,
            "unique_ips": len(ip_counter),
            "suspicious_ips": list(suspicious_ips),
            "high_frequency_objects": list(high_frequency_objects)
        }

    def list_buckets(self) -> list:
        try:
            response = self.s3_client.list_buckets()
            buckets = [b['Name'] for b in response.get('Buckets', [])]
            return buckets
        except ClientError:
            return []

    def list_objects(self, bucket_name: str, prefix: str = "") -> list:
        objects = []
        kwargs = {
            'Bucket': bucket_name,
            'Prefix': prefix
        }
        try:
            while True:
                resp = self.s3_client.list_objects_v2(**kwargs)
                for obj in resp.get('Contents', []):
                    objects.append(obj['Key'])
                if resp.get('IsTruncated'):
                    kwargs['ContinuationToken'] = resp['NextContinuationToken']
                else:
                    break
        except ClientError:
            return []
        return objects

    def search_sensitive_info(self, bucket_name: str, prefix: str = "", keywords: list = None) -> dict:
        if keywords is None:
            keywords = []
        matched = {}
        all_objects = self.list_objects(bucket_name, prefix)
        for obj_key in all_objects:
            try:
                content = self.download_object_to_string(bucket_name, obj_key)
                found = [kw for kw in keywords if kw in content]
                if found:
                    matched[obj_key] = found
            except Exception:
                pass
        return {"matched_objects": matched} if matched else {}

    def get_object_url(self, bucket_name: str, object_key: str) -> str:
        region = self.s3_client.meta.region_name
        return f"https://{bucket_name}.s3.{region}.amazonaws.com/{object_key}"
    
class HuaweiHandler(BaseCloudHandler):
    """华为云OBS实现。"""
    def __init__(self, ak, sk, token, endpoint):
        super().__init__(ak, sk, token, endpoint)
        if self.token:
            self.obsClient = ObsClient(
                access_key_id=self.ak,
                secret_access_key=self.sk,
                server=self.endpoint,
                security_token=self.token
            )
        else:
            self.obsClient = ObsClient(
                access_key_id=self.ak,
                secret_access_key=self.sk,
                server=self.endpoint
            )

    def check_credentials_valid(self) -> bool:
        try:
            resp = self.obsClient.listBuckets()
            return (resp.status // 100) == 2
        except ObsException:
            return False

    def does_bucket_exist(self, bucket_name: str) -> bool:
        try:
            resp = self.obsClient.headBucket(bucket_name)
            return (resp.status // 100) == 2
        except ObsException:
            return False

    def upload_object_from_string(self, bucket_name: str, object_key: str, content: str) -> dict:
        try:
            resp = self.obsClient.putObject(bucket_name, object_key, content)
            if (resp.status // 100) == 2:
                return {
                    "etag": resp.etag,
                    "status": resp.status,
                    "request_id": resp.requestId
                }
            else:
                return {}
        except ObsException as e:
            return {}

    def download_object_to_string(self, bucket_name: str, object_key: str) -> str:
        try:
            resp = self.obsClient.getObject(bucket_name, object_key)
            if resp.status == 200:
                content_bytes = resp.body.response['body']
                data = b''.join(content_bytes)
                return data.decode('utf-8', errors='replace')
            else:
                return ""
        except ObsException:
            return ""

    def does_object_exist(self, bucket_name: str, object_key: str) -> bool:
        try:
            resp = self.obsClient.headObject(bucket_name, object_key)
            return (resp.status // 100) == 2
        except ObsException:
            return False

    def check_permissions(self, bucket_name: str, object_key: str) -> bool:
        try:
            resp = self.obsClient.getObjectAcl(bucket_name, object_key)
            return (resp.status // 100) == 2
        except ObsException:
            return False

    def check_encryption(self, bucket_name: str) -> bool:
        try:
            resp = self.obsClient.getBucketEncryption(bucket_name)
            # 若成功获取加密配置则表示启用
            return (resp.status // 100) == 2
        except ObsException:
            return False

    def get_encryption_details(self, bucket_name: str) -> dict:
        try:
            resp = self.obsClient.getBucketEncryption(bucket_name)
            # 根据返回结构解析加密详情
            # 假设返回包含加密算法和KMS密钥ID
            rules = resp.body.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])
            details = []
            for rule in rules:
                sse = rule.get('ServerSideEncryptionByDefault', {})
                algorithm = sse.get('SSEAlgorithm', '')
                kms_key_id = sse.get('KMSMasterKeyID', '')
                details.append({
                    "SSEAlgorithm": algorithm,
                    "KMSMasterKeyID": kms_key_id
                })
            return {"EncryptionDetails": details} if details else {}
        except ObsException:
            return {}

    def check_versioning(self, bucket_name: str) -> bool:
        try:
            resp = self.obsClient.getBucketVersioning(bucket_name)
            # resp.body.VersionStatus == 'Enabled'表示开启
            return resp.body.get('VersionStatus', '') == 'Enabled'
        except ObsException:
            return False

    def check_access_logging(self, bucket_name: str) -> bool:
        try:
            resp = self.obsClient.getBucketLogging(bucket_name)
            # 若resp.body.LoggingEnabled不为空，则表示已开启日志
            return (resp.status // 100) == 2 and resp.body.get('LoggingEnabled') is not None
        except ObsException:
            return False

    def check_bucket_policy(self, bucket_name: str) -> str:
        try:
            resp = self.obsClient.getBucketPolicy(bucket_name)
            if (resp.status // 100) == 2 and resp.body and resp.body.get('Policy'):
                return resp.body['Policy']
            return ""
        except ObsException:
            return ""

    def check_cors(self, bucket_name: str) -> list:
        try:
            resp = self.obsClient.getBucketCORS(bucket_name)
            cors_rules = resp.body.get('CORSRules', [])
            return cors_rules
        except ObsException:
            return []

    def check_bucket_tagging(self, bucket_name: str) -> dict:
        try:
            resp = self.obsClient.getBucketTagging(bucket_name)
            tags = resp.body.get('TagSet', [])
            tag_dict = {tag['Key']: tag['Value'] for tag in tags}
            return tag_dict
        except ObsException:
            return {}

    def check_lifecycle(self, bucket_name: str) -> list:
        try:
            resp = self.obsClient.getBucketLifecycle(bucket_name)
            rules = resp.body.get('Rules', [])
            return rules
        except ObsException:
            return []

    def check_object_tagging(self, bucket_name: str, object_key: str) -> dict:
        try:
            resp = self.obsClient.getObjectTagging(bucket_name, object_key)
            tags = resp.body.get('TagSet', [])
            tag_dict = {tag['Key']: tag['Value'] for tag in tags}
            return tag_dict
        except ObsException:
            return {}

    def get_object_storage_class(self, bucket_name: str, object_key: str) -> str:
        try:
            resp = self.obsClient.getObjectMetaData(bucket_name, object_key)
            return resp.body.get('x-obs-storage-class', '')
        except ObsException:
            return ""

    def analyze_access_logs(self, bucket_name: str, log_prefix: str = "") -> dict:
        """
        分析华为云OBS的访问日志文件。
        返回包含统计信息的字典。
        """
        import re
        from collections import defaultdict

        log_objects = self.list_objects(bucket_name, prefix=log_prefix)
        if not log_objects:
            return {}

        total_requests = 0
        ip_counter = defaultdict(int)
        object_counter = defaultdict(int)
        suspicious_ips = set()
        high_frequency_objects = set()
        FREQUENCY_THRESHOLD = 100

        for log_obj in log_objects[:10]:  # 只分析最近的10个日志文件，避免耗时
            try:
                log_content = self.download_object_to_string(bucket_name, log_obj)
                for line in log_content.splitlines():
                    # 根据实际日志格式进行解析，以下为假设格式
                    parts = line.split()
                    if len(parts) < 10:
                        continue
                    ip = parts[3]
                    object_key = parts[6]
                    total_requests += 1
                    ip_counter[ip] += 1
                    object_counter[object_key] += 1
            except Exception:
                continue

        for ip, count in ip_counter.items():
            if count > FREQUENCY_THRESHOLD:
                suspicious_ips.add(ip)

        for obj, count in object_counter.items():
            if count > FREQUENCY_THRESHOLD:
                high_frequency_objects.add(obj)

        return {
            "total_requests": total_requests,
            "unique_ips": len(ip_counter),
            "suspicious_ips": list(suspicious_ips),
            "high_frequency_objects": list(high_frequency_objects)
        }

    def list_buckets(self) -> list:
        try:
            resp = self.obsClient.listBuckets()
            if (resp.status // 100) == 2:
                return [b['Name'] for b in resp.body.get('Buckets', [])]
            return []
        except ObsException:
            return []

    def list_objects(self, bucket_name: str, prefix: str = "") -> list:
        objects = []
        marker = None
        try:
            while True:
                resp = self.obsClient.listObjects(bucket_name, prefix=prefix, marker=marker, max_keys=1000)
                if resp.status == 200 and 'Contents' in resp.body:
                    for obj in resp.body['Contents']:
                        objects.append(obj['Key'])
                    if resp.body.get('IsTruncated', False):
                        marker = resp.body.get('NextMarker', '')
                    else:
                        break
                else:
                    break
        except ObsException:
            pass
        return objects

    def search_sensitive_info(self, bucket_name: str, prefix: str = "", keywords: list = None) -> dict:
        if keywords is None:
            keywords = []
        matched = {}
        all_objects = self.list_objects(bucket_name, prefix)
        for obj_key in all_objects:
            try:
                content = self.download_object_to_string(bucket_name, obj_key)
                found = [kw for kw in keywords if kw in content]
                if found:
                    matched[obj_key] = found
            except Exception:
                pass
        return {"matched_objects": matched} if matched else {}

    def get_object_url(self, bucket_name: str, object_key: str) -> str:
        return f"https://{bucket_name}.{self.endpoint}/{object_key}"
    
def get_cloud_handler(provider: str, ak: str, sk: str, token: str, endpoint: str) -> BaseCloudHandler:
    provider = provider.lower()
    if provider == "baidu":
        return BosHandler(ak, sk, token, endpoint)
    elif provider == "aliyun":
        return AliyunHandler(ak, sk, token, endpoint)
    elif provider == "tencent":
        return TencentHandler(ak, sk, token, endpoint)
    elif provider == "aws":
        return AWSHandler(ak, sk, token, endpoint)
    elif provider == "huawei":
        return HuaweiHandler(ak, sk, token, endpoint)
    else:
        raise ValueError("Unsupported provider. Please choose from 'Baidu', 'Aliyun', 'Tencent', 'AWS', 'Huawei'.")