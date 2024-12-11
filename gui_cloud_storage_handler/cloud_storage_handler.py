# -*- coding: utf-8 -*-
"""
cloud_storage_handler.py
-------------------------
对多家云存储厂商的通用检测手段，并提供相应的Handler类。

BaseCloudHandler: 抽象基类，定义通用方法和说明。
未来可扩展，内含方法注释和实现参考。
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
from obs import ObsClient


class BaseCloudHandler(ABC):
    """
    抽象基类，为不同云厂商的对象存储服务提供统一的接口定义。
    子类需要实现下述抽象方法，以确保在不同云服务下都能进行统一的操作。
    """

    def __init__(self, ak: str, sk: str, token: str, endpoint: str):
        """
        初始化云存储操作的基础参数。

        :param ak: Access Key，访问云资源的认证凭据之一
        :param sk: Secret Key，与AK搭配使用的密钥，用于签名请求
        :param token: 对于STS临时凭据场景使用的安全令牌（可空字符串）
        :param endpoint: 对象存储服务的终端节点（域名或URL）
        """
        self.ak = ak
        self.sk = sk
        self.token = token
        self.endpoint = endpoint

    @abstractmethod
    def check_credentials_valid(self) -> bool:
        """
        检测凭据有效性。
        
        实现方式参考：
        - 可以调用列出存储桶的接口(list_buckets或类似)。
          如果凭据无效、权限不足或过期，通常会返回认证错误或权限错误。
        - 成功调用并返回期望结果则说明凭据有效。
        
        :return: True表示凭据有效，False或抛出异常表示无效。
        """
        pass

    @abstractmethod
    def does_bucket_exist(self, bucket_name: str) -> bool:
        """
        检测指定的Bucket是否存在。
        
        实现方式参考：
        - 调用head_bucket或does_bucket_exist等原生API（名称因云厂商而异）
        - 返回True表示Bucket存在且可访问，否则False表示不存在或无权限。

        :param bucket_name: 待检测的Bucket名称
        :return: True表示存在，False表示不存在或无访问权限
        """
        pass

    @abstractmethod
    def upload_object_from_string(self, bucket_name: str, object_key: str, content: str) -> dict:
        """
        将字符串内容上传为指定对象。

        实现方式参考：
        - 使用put_object或put_object_from_string等接口将`content`上传到指定的bucket和object_key中。
        - 上传成功后，返回响应信息的字典（例如metadata或ETag）。
        - 如果上传失败则抛出异常。

        :param bucket_name: 目标Bucket名称
        :param object_key: 对象键名（文件名/路径）
        :param content: 要上传的字符串内容
        :return: 请求响应的字典形式，可包含metadata等信息
        """
        pass

    @abstractmethod
    def download_object_to_string(self, bucket_name: str, object_key: str) -> str:
        """
        下载对象内容并以字符串形式返回。

        实现方式参考：
        - 使用get_object或get_object_as_string等API获取对象内容。
        - 如果对象不存在或无权限访问，会抛出异常。
        - 成功则返回对象内容字符串。

        :param bucket_name: 目标Bucket名称
        :param object_key: 对象键名
        :return: 对象内容的字符串
        """
        pass

    @abstractmethod
    def does_object_exist(self, bucket_name: str, object_key: str) -> bool:
        """
        检测指定对象是否存在。

        实现方式参考：
        - 使用head_object、get_object_metadata或does_object_exist等API
        - 对象存在且可访问则返回True，否则返回False。

        :param bucket_name: Bucket名称
        :param object_key: 对象键名
        :return: True表示对象存在，False表示不存在或无权限
        """
        pass

    @abstractmethod
    def check_permissions(self, bucket_name: str, object_key: str) -> bool:
        """
        检查访问特定对象的权限（ACL等）。
        
        实现方式参考：
        - 获取对象ACL或Bucket ACL，如果无权限则会报错。
        - 如果可成功获取ACL则说明有相应权限，返回True。
        
        :param bucket_name: Bucket名称
        :param object_key: 对象键名
        :return: True表示有权限，False表示无权限
        """
        pass


class BosHandler(BaseCloudHandler):
    """BOS(Baidu Object Storage)的实现示例。"""

    def __init__(self, ak: str, sk: str, token: str, endpoint: str):
        super().__init__(ak, sk, token, endpoint)
        config = BceClientConfiguration(
            credentials=BceCredentials(self.ak, self.sk),
            endpoint=self.endpoint,
            security_token=self.token
        )
        self.client = BosClient(config)

    def check_credentials_valid(self) -> bool:
        """通过列举bucket测试权限和凭据有效性。"""
        try:
            self.client.list_buckets()
            return True
        except bos_exception.BceBaseException:
            return False

    def does_bucket_exist(self, bucket_name: str) -> bool:
        """使用BOS的does_bucket_exist接口检查bucket存在性。"""
        return self.client.does_bucket_exist(bucket_name)

    def upload_object_from_string(self, bucket_name: str, object_key: str, content: str) -> dict:
        """使用put_object_from_string上传字符串内容。"""
        res = self.client.put_object_from_string(bucket_name, object_key, content)
        return res.__dict__ if res else {}

    def download_object_to_string(self, bucket_name: str, object_key: str) -> str:
        """使用get_object_as_string下载对象内容。"""
        response = self.client.get_object_as_string(bucket_name, object_key)
        return response

    def does_object_exist(self, bucket_name: str, object_key: str) -> bool:
        """尝试获取对象元数据判断对象是否存在。"""
        try:
            self.client.get_object_meta_data(bucket_name, object_key)
            return True
        except bos_exception.BceHttpClientError:
            return False

    def check_permissions(self, bucket_name: str, object_key: str) -> bool:
        """尝试获取对象ACL来验证权限。"""
        try:
            self.client.get_object_acl(bucket_name, object_key)
            return True
        except bos_exception.BceBaseException:
            return False


class AliyunHandler(BaseCloudHandler):
    """
    使用阿里云OSS的Python SDK (oss2) 实现各项操作。

    参考文档:
    https://help.aliyun.com/document_detail/32009.html  (Python SDK 使用文档)
    """

    def __init__(self, ak: str, sk: str, token: str, endpoint: str):
        super().__init__(ak, sk, token, endpoint)
        
        # 根据是否有token决定使用STS临时凭证还是常规凭证
        if self.token:
            self.auth = oss2.StsAuth(self.ak, self.sk, self.token)
        else:
            self.auth = oss2.Auth(self.ak, self.sk)

        # Service对象用于列举可访问的bucket等操作
        self.service = oss2.Service(self.auth, self.endpoint)

    def check_credentials_valid(self) -> bool:
        """
        检测凭据有效性:
        尝试列举可访问的Bucket列表。如果凭据无效或权限不足，会抛出异常。
        """
        try:
            # 列出bucket，如果正常返回说明凭据有效
            _ = self.service.list_buckets()
            return True
        except oss2.exceptions.OssError:
            return False

    def does_bucket_exist(self, bucket_name: str) -> bool:
        """
        检测Bucket是否存在:
        使用head_bucket检查Bucket存在性。如果不存在或无权限，会抛出异常。
        不抛异常则说明bucket存在且可访问。
        """
        bucket = oss2.Bucket(self.auth, self.endpoint, bucket_name)
        try:
            bucket.head_bucket()
            return True
        except oss2.exceptions.NoSuchBucket:
            return False
        except oss2.exceptions.OssError:
            # 其他错误，如无权限，也视为不存在
            return False

    def upload_object_from_string(self, bucket_name: str, object_key: str, content: str) -> dict:
        """
        上传字符串作为对象:
        使用bucket.put_object(object_key, content)上传字符串内容。
        成功返回PutObjectResult，可从中获取ETag等信息返回给调用者。
        """
        bucket = oss2.Bucket(self.auth, self.endpoint, bucket_name)
        try:
            result = bucket.put_object(object_key, content)
            # result中包含状态码、ETag等信息
            return {
                "etag": result.etag,
                "status": result.status,
                "request_id": result.request_id
            }
        except oss2.exceptions.OssError as e:
            # 上传失败抛出异常，调用者可以捕获处理
            raise e

    def download_object_to_string(self, bucket_name: str, object_key: str) -> str:
        """
        下载对象内容为字符串:
        使用bucket.get_object(object_key)获取对象文件句柄，然后read()为字符串。
        """
        bucket = oss2.Bucket(self.auth, self.endpoint, bucket_name)
        try:
            result = bucket.get_object(object_key)
            # result是一个可读文件流对象
            content = result.read()
            if isinstance(content, bytes):
                content = content.decode('utf-8', errors='replace')  # 根据实际编码需要调整
            return content
        except oss2.exceptions.NoSuchKey:
            # 对象不存在
            raise FileNotFoundError(f"Object '{object_key}' not found in bucket '{bucket_name}'.")
        except oss2.exceptions.OssError as e:
            raise e

    def does_object_exist(self, bucket_name: str, object_key: str) -> bool:
        """
        检测对象是否存在:
        使用head_object来判断对象是否存在。如果对象不存在会抛出NoSuchKey异常。
        """
        bucket = oss2.Bucket(self.auth, self.endpoint, bucket_name)
        try:
            bucket.head_object(object_key)
            return True
        except oss2.exceptions.NoSuchKey:
            return False
        except oss2.exceptions.OssError:
            # 其他异常，可能是权限问题，这里也视为不存在
            return False

    def check_permissions(self, bucket_name: str, object_key: str) -> bool:
        """
        检查ACL、权限:
        阿里云OSS允许对对象获取ACL：bucket.get_object_acl(object_key)
        如果无权限则会报错，有权限则返回ACL信息。
        """
        bucket = oss2.Bucket(self.auth, self.endpoint, bucket_name)
        try:
            acl_result = bucket.get_object_acl(object_key)
            # 正常返回说明有权限访问ACL
            # acl_result.acl 是 'private'、'public-read'、'public-read-write' 之一
            # 根据需要可进一步判断权限类型，这里只要能获取就代表有权限
            return True
        except oss2.exceptions.OssError:
            # 无权限或其他错误
            return False

class TencentHandler(BaseCloudHandler):
    """
    使用腾讯云COS的Python SDK (qcloud_cos) 实现各项操作。

    参考文档:
    https://cloud.tencent.com/document/product/436/37796 (COS Python SDK 使用文档)
    """

    def __init__(self, ak: str, sk: str, token: str, endpoint: str):
        super().__init__(ak, sk, token, endpoint)

        # endpoint一般格式为 "https://<bucket>.cos.<region>.myqcloud.com"
        # 但这里仅能获取endpoint，需要用户事先正确传入endpoint或region信息。
        # 若需要region，可由用户提供并拼接endpoint。
        # 这里假设用户已在endpoint中提供适当的域名。
        
        # endpoint形如 "https://cos.ap-beijing.myqcloud.com"
        # 从endpoint提取region的简单例子（如果endpoint遵守cos.*.myqcloud.com格式）：
        # 解析域名获取region，只适用于标准域名。如果endpoint自定义，请直接提供region给此类。
        region = None
        # 简单尝试从endpoint中获取region信息（可根据实际需求修改）
        # endpoint like: https://cos.ap-beijing.myqcloud.com
        # 切分后['https:', '', 'cos.ap-beijing.myqcloud.com']
        parts = endpoint.replace("https://", "").replace("http://", "").split('.')
        # parts可能为["cos", "ap-beijing", "myqcloud", "com"]则parts[1]是region
        if len(parts) >= 2 and parts[0] == "cos":
            region = parts[1]  # ap-beijing

        # 如果无法自动提取region，则需要用户在外部提供region或直接使用特定API初始化
        if not region:
            # 如果无法自动从endpoint提取region，请用户修改代码为固定值或外部传入
            raise ValueError("Unable to determine region from endpoint. Please provide a proper endpoint or modify code.")

        # 配置对象
        config_params = {
            'Region': region,
            'SecretId': self.ak,
            'SecretKey': self.sk
        }

        # 如果是临时密钥，则加入Token
        if self.token:
            config_params['Token'] = self.token

        config = CosConfig(**config_params)
        self.client = CosS3Client(config)

    def check_credentials_valid(self) -> bool:
        """
        检测凭据有效性:
        尝试列出可访问的Buckets列表。如果凭据无效或权限不足，会抛出CosServiceError或CosClientError。
        """
        try:
            # 列出buckets
            response = self.client.list_buckets()
            # 若成功列出说明凭据有效
            return True
        except (CosServiceError, CosClientError):
            return False

    def does_bucket_exist(self, bucket_name: str) -> bool:
        """
        检测Bucket是否存在:
        使用head_bucket检查Bucket存在性，如果不存在或无权限则会抛出异常。
        """
        try:
            self.client.head_bucket(Bucket=bucket_name)
            return True
        except CosServiceError as e:
            # 若返回404表示不存在，403表示无权限，也可统一为False
            if e.get_status_code() == 404:
                return False
            return False
        except CosClientError:
            return False

    def upload_object_from_string(self, bucket_name: str, object_key: str, content: str) -> dict:
        """
        上传字符串对象:
        使用put_object(Bucket=bucket_name, Key=object_key, Body=content)上传字符串。
        成功返回ETag等信息。
        """
        try:
            response = self.client.put_object(
                Bucket=bucket_name,
                Key=object_key,
                Body=content.encode('utf-8')  # 将字符串编码为bytes
            )
            # response typically contains {'ETag': '"xxx"'}
            return {
                "etag": response.get("ETag", ""),
                "status": response.get("ResponseMetadata", {}).get("HTTPStatusCode", 200)
            }
        except (CosServiceError, CosClientError) as e:
            raise e

    def download_object_to_string(self, bucket_name: str, object_key: str) -> str:
        """
        下载对象内容:
        使用get_object获取对象流，然后read()为bytes，再解码为字符串。
        """
        try:
            response = self.client.get_object(
                Bucket=bucket_name,
                Key=object_key
            )
            # get_object返回一个dict，其中 'Body' 是 StreamingBody类型，可read()
            body = response['Body'].read()
            # 将bytes解码为str
            return body.decode('utf-8', errors='replace')
        except CosServiceError as e:
            if e.get_status_code() == 404:
                # 对象不存在
                raise FileNotFoundError(f"Object '{object_key}' not found in bucket '{bucket_name}'.")
            raise e
        except CosClientError as e:
            raise e

    def does_object_exist(self, bucket_name: str, object_key: str) -> bool:
        """
        判断对象是否存在:
        使用head_object检查。如果不存在会抛出404错误。
        """
        try:
            self.client.head_object(Bucket=bucket_name, Key=object_key)
            return True
        except CosServiceError as e:
            if e.get_status_code() == 404:
                return False
            return False
        except CosClientError:
            return False

    def check_permissions(self, bucket_name: str, object_key: str) -> bool:
        """
        检查对象ACL权限:
        使用get_object_acl获取ACL，如果无权限会抛出异常。
        成功获取ACL说明有相应权限。
        """
        try:
            acl_response = self.client.get_object_acl(Bucket=bucket_name, Key=object_key)
            # 正常返回ACL说明有权限
            # acl_response中有Owner, Grants等信息，可根据需要进一步分析权限
            return True
        except (CosServiceError, CosClientError):
            return False

class AWSHandler(BaseCloudHandler):
    """
    使用 AWS S3 的 Python SDK (boto3) 实现各项操作。

    官方文档参考：
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3.html
    """

    def __init__(self, ak: str, sk: str, token: str, endpoint: str):
        super().__init__(ak, sk, token, endpoint)

        # 提取region逻辑（可选）：如果endpoint是标准的AWS S3域名，可尝试从中解析region。
        # 不过官方推荐直接在配置中指定 region_name。
        # 这里如果用户未给region，可从endpoint解析或直接写死region。
        # 假设用户提供的endpoint为标准S3 endpoint: "https://s3.us-west-2.amazonaws.com"
        # 则可从URL中提取 "us-west-2" 作为region。
        
        region = None
        # 简单解析region（只适用于标准模式），实际情况请根据你使用的endpoint进行逻辑调整。
        # endpoint可能是："https://s3.us-west-2.amazonaws.com" -> region = us-west-2
        import re
        match = re.search(r"s3[.-]([a-z0-9-]+)\.amazonaws\.com", self.endpoint)
        if match:
            region = match.group(1)
        # 如果没匹配到region，也可以使用默认region或让用户指定
        if not region:
            # 如果无法从endpoint提取region，可以设一个默认值或者要求用户传入。
            region = "us-east-1"

        session_kwargs = {
            "aws_access_key_id": self.ak,
            "aws_secret_access_key": self.sk,
            "region_name": region
        }
        if self.token:
            session_kwargs["aws_session_token"] = self.token

        # 如果endpoint是自定义S3兼容服务（如非官方AWS S3），可通过endpoint_url指定
        # 如果是官方AWS S3，请注释掉 or 判断是否需要endpoint_url
        # boto3默认会根据region选择正确的S3服务URL，如果想强制使用endpoint，请解注以下行：
        # session_kwargs["endpoint_url"] = self.endpoint
        
        self.s3_client = boto3.client('s3', **session_kwargs)

    def check_credentials_valid(self) -> bool:
        """
        检测凭据有效性：
        尝试列出可访问的Bucket列表。如果凭据无效会抛出NoCredentialsError或ClientError。
        """
        try:
            self.s3_client.list_buckets()
            return True
        except (NoCredentialsError, ClientError):
            return False

    def does_bucket_exist(self, bucket_name: str) -> bool:
        """
        检测Bucket是否存在：
        使用head_bucket，如果Bucket不存在或无权限，会抛出ClientError。
        """
        try:
            self.s3_client.head_bucket(Bucket=bucket_name)
            return True
        except ClientError as e:
            # 404表示不存在, 403表示无权限访问，也可统一为False
            return False

    def upload_object_from_string(self, bucket_name: str, object_key: str, content: str) -> dict:
        """
        上传字符串对象：
        使用put_object接口上传字符串内容。成功后返回ETag等信息。
        """
        try:
            response = self.s3_client.put_object(
                Bucket=bucket_name,
                Key=object_key,
                Body=content.encode('utf-8')
            )
            # response中包含ETag等信息
            return {
                "etag": response.get("ETag", ""),
                "status": response["ResponseMetadata"].get("HTTPStatusCode", 200)
            }
        except ClientError as e:
            raise e

    def download_object_to_string(self, bucket_name: str, object_key: str) -> str:
        """
        下载对象内容为字符串：
        使用get_object下载对象并.read()。
        """
        try:
            response = self.s3_client.get_object(Bucket=bucket_name, Key=object_key)
            body = response['Body'].read()
            return body.decode('utf-8', errors='replace')
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchKey':
                raise FileNotFoundError(f"Object '{object_key}' not found in bucket '{bucket_name}'.")
            raise e

    def does_object_exist(self, bucket_name: str, object_key: str) -> bool:
        """
        检测对象是否存在：
        使用head_object判断，如果对象不存在会抛出404错误。
        """
        try:
            self.s3_client.head_object(Bucket=bucket_name, Key=object_key)
            return True
        except ClientError as e:
            if e.response['Error']['Code'] == '404':
                return False
            return False

    def check_permissions(self, bucket_name: str, object_key: str) -> bool:
        """
        检查权限（ACL）：
        使用get_object_acl，如果无权限会抛出ClientError。
        能获取ACL说明至少有读ACL权限。
        """
        try:
            acl_response = self.s3_client.get_object_acl(Bucket=bucket_name, Key=object_key)
            # acl_response包含Owner和Grants等信息，如果能成功获取说明有权限
            return True
        except ClientError:
            return False

class HuaweiHandler(BaseCloudHandler):
    """
    使用华为云OBS的Python SDK (esdk-obs-python) 实现各项操作。

    官方文档参考：
    https://support.huaweicloud.com/sdk-python-devg-obs/obs_26_1004.html
    """

    def __init__(self, ak: str, sk: str, token: str, endpoint: str):
        super().__init__(ak, sk, token, endpoint)

        # 初始化ObsClient，支持临时凭证
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
        """
        检测凭据有效性:
        尝试列出Bucket列表。如果无权限或凭据无效，会返回非200的状态码或抛出异常。
        """
        try:
            resp = self.obsClient.listBuckets()
            # resp.status是HTTP状态码，2xx表示成功
            return (resp.status // 100) == 2
        except ObsException:
            return False

    def does_bucket_exist(self, bucket_name: str) -> bool:
        """
        检测Bucket是否存在:
        使用headBucket检查。如果Bucket不存在或无权限访问，通常会返回非200的status。
        """
        try:
            resp = self.obsClient.headBucket(bucket_name)
            return (resp.status // 100) == 2
        except ObsException:
            # 抛出异常则视为不存在或无权限
            return False

    def upload_object_from_string(self, bucket_name: str, object_key: str, content: str) -> dict:
        """
        上传字符串为对象:
        使用putObject，成功返回status为200或201，ETag等信息可在resp中获取。
        """
        try:
            resp = self.obsClient.putObject(bucket_name, object_key, content)
            if (resp.status // 100) == 2:
                return {
                    "etag": resp.etag,
                    "status": resp.status,
                    "request_id": resp.requestId
                }
            else:
                raise ObsException(f"Upload failed with status {resp.status}")
        except ObsException as e:
            raise e

    def download_object_to_string(self, bucket_name: str, object_key: str) -> str:
        """
        下载对象内容为字符串:
        使用getObject下载对象的内容，然后read()获取字节流，解码为UTF-8字符串。
        """
        try:
            resp = self.obsClient.getObject(bucket_name, object_key)
            if resp.status == 200:
                content_bytes = resp.body.response['body']
                # content_bytes是一个可迭代对象，需要一次性读取：
                data = b''.join(content_bytes)
                return data.decode('utf-8', errors='replace')
            else:
                raise ObsException(f"Download failed with status {resp.status}")
        except ObsException as e:
            if "NoSuchKey" in str(e):
                raise FileNotFoundError(f"Object '{object_key}' not found in bucket '{bucket_name}'.")
            raise e

    def does_object_exist(self, bucket_name: str, object_key: str) -> bool:
        """
        检测对象是否存在:
        使用headObject判断，如果对象不存在或无权限，status将非2xx或抛异常。
        """
        try:
            resp = self.obsClient.headObject(bucket_name, object_key)
            return (resp.status // 100) == 2
        except ObsException:
            return False

    def check_permissions(self, bucket_name: str, object_key: str) -> bool:
        """
        检查权限（ACL）:
        尝试getObjectAcl，如果无权限访问ACL将报错或返回非2xx。
        成功则说明有权限。
        """
        try:
            resp = self.obsClient.getObjectAcl(bucket_name, object_key)
            return (resp.status // 100) == 2
        except ObsException:
            return False
def get_cloud_handler(provider: str, ak: str, sk: str, token: str, endpoint: str) -> BaseCloudHandler:
    """
    根据选择的云服务厂商返回对应的 Handler 实例。
    若厂商尚未实现对应的类，会抛出NotImplementedError。
    
    :param provider: 云厂商名称，可选值：Baidu、Aliyun、Tencent、AWS、Huawei（不区分大小写）
    :param ak: Access Key
    :param sk: Secret Key
    :param token: 临时Token或空字符串
    :param endpoint: 对象存储服务的endpoint
    :return: 对应云厂商的Handler实例
    """
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