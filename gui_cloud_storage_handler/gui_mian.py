# -*- coding: utf-8 -*-
"""
gui_main.py
-----------
GUI 主程序：通过 Tkinter 提供图形界面输入 AK、SK、Token、Endpoint、Bucket 名称，以及云服务提供商。
点击 "检测" 按钮后，会尝试执行通用检测手段，并在界面显示结果。

检测步骤：
1. 凭据有效性校验（尝试列出存储桶或其他简单操作）。
2. Bucket存在性检测。
3. 上传和下载测试文件。
4. 对象存在性检测（可选，示例可在上传后再次查询）。
5. 权限/ACL检测（若支持）。

未实现的云服务会提示相应错误，可未来扩展。
"""

import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import json
from cloud_storage_handler import get_cloud_handler, BaseCloudHandler

class CloudGuiApp:
    def __init__(self, root):
        self.root = root
        self.root.title("多云存储检测工具")
        self.root.geometry("1000x500")

        self._create_widgets()

    def _create_widgets(self):
        tk.Label(self.root, text="AK:").grid(row=0, column=0, sticky="W")
        self.entry_ak = tk.Entry(self.root, width=80)
        self.entry_ak.grid(row=0, column=1, sticky="W")

        tk.Label(self.root, text="SK:").grid(row=1, column=0, sticky="W")
        self.entry_sk = tk.Entry(self.root, width=80)
        self.entry_sk.grid(row=1, column=1, sticky="W")

        tk.Label(self.root, text="Token (可选):").grid(row=2, column=0, sticky="W")
        self.entry_token = tk.Entry(self.root, width=80)
        self.entry_token.grid(row=2, column=1, sticky="W")

        tk.Label(self.root, text="Endpoint:").grid(row=3, column=0, sticky="W")
        self.entry_endpoint = tk.Entry(self.root, width=80)
        self.entry_endpoint.grid(row=3, column=1, sticky="W")

        tk.Label(self.root, text="Bucket Name:").grid(row=4, column=0, sticky="W")
        self.entry_bucket_name = tk.Entry(self.root, width=80)
        self.entry_bucket_name.grid(row=4, column=1, sticky="W")

        tk.Label(self.root, text="Provider:").grid(row=5, column=0, sticky="W")
        self.provider_var = tk.StringVar()
        self.combobox_provider = ttk.Combobox(self.root, textvariable=self.provider_var, state='readonly', width=20)
        self.combobox_provider['values'] = ("Baidu", "Aliyun", "Tencent", "AWS", "Huawei")
        self.combobox_provider.current(0)
        self.combobox_provider.grid(row=5, column=1, sticky="W")

        tk.Label(self.root, text="输出结果:").grid(row=6, column=0, sticky="W")
        self.text_output = tk.Text(self.root, width=80, height=15)
        self.text_output.grid(row=7, column=0, columnspan=2, sticky="W")

        self.btn_detect = tk.Button(self.root, text="检测", width=10, height=2, command=self._on_detect_click)
        self.btn_detect.grid(row=8, column=1, sticky="W")

    def _on_detect_click(self):
        ak = self.entry_ak.get().strip()
        sk = self.entry_sk.get().strip()
        token = self.entry_token.get().strip()
        endpoint = self.entry_endpoint.get().strip()
        bucket_name = self.entry_bucket_name.get().strip()
        provider = self.provider_var.get().strip()

        self.text_output.delete("1.0", tk.END)

        if not ak or not sk or not endpoint or not bucket_name:
            self._append_output("请填写完整信息(AK, SK, Endpoint, Bucket Name)！\n")
            return

        # 初始化云处理类
        try:
            handler = get_cloud_handler(provider, ak, sk, token, endpoint)
        except Exception as e:
            self._append_output(f"初始化云存储处理类失败: {e}\n")
            return

        # 1. 凭据有效性校验
        self._append_output("1. 凭据有效性校验...\n")
        try:
            if handler.check_credentials_valid():
                self._append_output("   凭据有效，访问正常。\n")
            else:
                self._append_output("   凭据无效或无访问权限。\n")
                return
        except NotImplementedError:
            self._append_output("   凭据检测尚未实现。\n")
            return
        except Exception as e:
            self._append_output(f"   凭据检测失败：{e}\n")
            return

        # 2. Bucket存在性检测
        self._append_output("2. Bucket存在性检测...\n")
        try:
            exists = handler.does_bucket_exist(bucket_name)
            if exists:
                self._append_output(f"   Bucket '{bucket_name}' 存在。\n")
            else:
                self._append_output(f"   Bucket '{bucket_name}' 不存在。\n")
                return
        except NotImplementedError:
            self._append_output("   Bucket存在性检测尚未实现。\n")
            return
        except Exception as e:
            self._append_output(f"   检测Bucket存在性失败：{e}\n")
            return

        # 3. 上传与下载测试
        object_key = "test_detection_object.txt"
        test_content = "This is a test content."
        self._append_output("3. 上传与下载测试...\n")
        try:
            # 上传
            upload_res = handler.upload_object_from_string(bucket_name, object_key, test_content)
            self._append_output("   上传成功！\n")
            self._append_output(f"   上传结果Metadata: {json.dumps(upload_res.get('metadata', {}), ensure_ascii=False, indent=2)}\n")

            # 下载
            downloaded = handler.download_object_to_string(bucket_name, object_key)
            if downloaded == test_content:
                self._append_output("   下载验证成功，内容一致。\n")
            else:
                self._append_output("   下载内容与原始内容不一致。\n")
        except NotImplementedError:
            self._append_output("   上传或下载测试尚未实现。\n")
            return
        except Exception as e:
            self._append_output(f"   上传/下载测试失败：{e}\n")
            return

        # 4. 对象存在性检测
        self._append_output("4. 对象存在性检测...\n")
        try:
            obj_exists = handler.does_object_exist(bucket_name, object_key)
            self._append_output(f"   对象'{object_key}'存在性：{obj_exists}\n")
        except NotImplementedError:
            self._append_output("   对象存在性检测尚未实现。\n")
        except Exception as e:
            self._append_output(f"   检测对象存在性失败：{e}\n")

        # 5. 权限与ACL检测（可选）
        self._append_output("5. 权限与ACL检测（示例）...\n")
        try:
            perm_ok = handler.check_permissions(bucket_name, object_key)
            if perm_ok:
                self._append_output("   权限检测通过。\n")
            else:
                self._append_output("   权限检测未通过，可能ACL或Policy存在问题。\n")
        except NotImplementedError:
            self._append_output("   权限检测尚未实现。\n")
        except Exception as e:
            self._append_output(f"   权限检测失败：{e}\n")


    def _append_output(self, msg: str):
        self.text_output.insert(tk.END, msg)

if __name__ == "__main__":
    root = tk.Tk()
    app = CloudGuiApp(root)
    root.mainloop()