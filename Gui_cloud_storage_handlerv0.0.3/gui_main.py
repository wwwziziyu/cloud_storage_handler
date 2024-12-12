# -*- coding: utf-8 -*-
"""
gui_main.py
-----------
功能概述：
- 用户输入AK/SK/Token/Endpoint/Bucket Name及云厂商选择。
- 点击"开始检测"执行多云存储检测流程。
- 检测过程包括凭据有效性、Bucket存在性、上传下载、对象存在性、权限检测等。

备注：
- 请确保已安装所需SDK和环境依赖。
"""

import tkinter as tk
from tkinter import ttk, messagebox
import json
import threading
import queue
from cloud_storage_handler import get_cloud_handler, BaseCloudHandler  # 确保此模块存在并正确

class CloudGuiApp:
    def __init__(self, root):
        self.root = root
        self.root.title("多云存储检测工具")
        self.root.geometry("1000x900")  # 调整高度以适应日志输出
        self.root.resizable(False, False)

        # 设定背景颜色与主题
        self.root.configure(background="#ECEFF4")
        style = ttk.Style(self.root)
        style.theme_use("default")

        # 全局字体与颜色
        # 标题标签样式
        style.configure("Title.TLabel", font=("Arial", 20, "bold"), background="#ECEFF4", foreground="#2E3440")
        # 子标题或说明标签样式
        style.configure("SubTitle.TLabel", font=("Arial", 12), background="#ECEFF4", foreground="#4C566A")

        # 普通标签、输入框
        style.configure("TLabel", background="#ECEFF4", foreground="#2E3440", font=("Arial", 11))
        style.configure("TEntry", foreground="#2E3440", fieldbackground="#D8DEE9", font=("Arial", 11))
        style.configure("TCombobox", foreground="#2E3440", fieldbackground="#D8DEE9", font=("Arial", 11))
        
        # 按钮样式
        style.configure("TButton", font=("Arial", 11, "bold"), foreground="#FFFFFF", background="#5E81AC")
        style.map("TButton", background=[("active", "#81A1C1")])

        # 框架样式
        style.configure("Custom.TLabelframe", background="#ECEFF4", foreground="#2E3440", borderwidth=2, relief="groove")
        style.configure("Custom.TLabelframe.Label", background="#ECEFF4", foreground="#2E3440", font=("Arial", 12, "bold"))

        # 创建顶部标题栏
        self._create_title_bar()

        # 创建输入和输出区域
        self._create_input_output_frames()

        # 创建底部按钮和进度条区域
        self._create_bottom_bar()

        # 初始化消息队列
        self.queue = queue.Queue()

        # 启动队列检查
        self.root.after(100, self.process_queue)

        # 初始化分页标记
        self.current_marker = None

        # 初始化当前处理器和存储桶名
        self.current_handler = None
        self.current_bucket_name = None

    def _create_title_bar(self):
        # 标题区Frame
        title_frame = ttk.Frame(self.root, style="Title.TFrame")
        title_frame.pack(side="top", fill="x")

        title_label = ttk.Label(title_frame, text="多云存储检测工具", style="Title.TLabel")
        title_label.pack(side="top", fill="x", pady=10)

        subtitle_label = ttk.Label(title_frame, text="支持Baidu、Aliyun、Tencent、AWS、Huawei多家云存储服务的基础检测", style="SubTitle.TLabel")
        subtitle_label.pack(side="top", fill="x")

    def _create_input_output_frames(self):
        # 创建一个 PanedWindow 来分隔检测结果和日志输出
        paned = ttk.PanedWindow(self.root, orient=tk.VERTICAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        # 输入参数框架
        input_frame = ttk.LabelFrame(paned, text="输入参数", padding=10, style="Custom.TLabelframe")
        paned.add(input_frame, weight=1)

        # 使用grid布局输入区域
        ttk.Label(input_frame, text="Access Key (AK)：").grid(row=0, column=0, sticky="E", padx=5, pady=5)
        self.entry_ak = ttk.Entry(input_frame, width=60)
        self.entry_ak.grid(row=0, column=1, sticky="W")

        ttk.Label(input_frame, text="Secret Key (SK)：").grid(row=1, column=0, sticky="E", padx=5, pady=5)
        self.entry_sk = ttk.Entry(input_frame, width=60, show="*")
        self.entry_sk.grid(row=1, column=1, sticky="W")

        ttk.Label(input_frame, text="Security Token(可选)：").grid(row=2, column=0, sticky="E", padx=5, pady=5)
        self.entry_token = ttk.Entry(input_frame, width=60)
        self.entry_token.grid(row=2, column=1, sticky="W")

        ttk.Label(input_frame, text="Endpoint：").grid(row=3, column=0, sticky="E", padx=5, pady=5)
        self.entry_endpoint = ttk.Entry(input_frame, width=60)
        self.entry_endpoint.grid(row=3, column=1, sticky="W")

        ttk.Label(input_frame, text="Bucket Name：").grid(row=4, column=0, sticky="E", padx=5, pady=5)
        self.entry_bucket_name = ttk.Entry(input_frame, width=30)
        self.entry_bucket_name.grid(row=4, column=1, sticky="W")

        ttk.Label(input_frame, text="Provider：").grid(row=5, column=0, sticky="E", padx=5, pady=5)
        self.provider_var = tk.StringVar()
        self.combobox_provider = ttk.Combobox(input_frame, textvariable=self.provider_var, state='readonly', width=20)
        self.combobox_provider['values'] = ("Baidu", "Aliyun", "Tencent", "AWS", "Huawei")
        self.combobox_provider.current(0)
        self.combobox_provider.grid(row=5, column=1, sticky="W")

        # 输出结果框架
        output_frame = ttk.LabelFrame(paned, text="检测结果输出", padding=10, style="Custom.TLabelframe")
        paned.add(output_frame, weight=3)

        # 使用Treeview显示对象列表
        self.tree_output = ttk.Treeview(output_frame, columns=("Object"), show='headings')
        self.tree_output.heading("Object", text="Object Key")
        self.tree_output.pack(side="left", fill="both", expand=True)

        scrollbar = ttk.Scrollbar(output_frame, command=self.tree_output.yview)
        self.tree_output.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")

        # 添加Text小部件用于日志输出，放在一个单独的 Frame 下方
        self.log_frame = ttk.LabelFrame(self.root, text="日志输出", padding=10, style="Custom.TLabelframe")
        self.log_frame.pack(side="bottom", fill="x", padx=20, pady=10)

        self.text_output = tk.Text(self.log_frame, wrap="word", font=("Arial", 11), foreground="#2E3440", background="#E5E9F0", height=10)
        self.text_output.pack(side="left", fill="x", expand=True)

        log_scrollbar = ttk.Scrollbar(self.log_frame, command=self.text_output.yview)
        self.text_output.configure(yscrollcommand=log_scrollbar.set)
        log_scrollbar.pack(side="right", fill="y")

    def _create_bottom_bar(self):
        button_frame = ttk.Frame(self.root)
        button_frame.pack(side="bottom", fill="x", padx=20, pady=10)

        # 进度条
        self.progress_bar = ttk.Progressbar(button_frame, mode='indeterminate')
        self.progress_bar.pack(side="left", fill="x", expand=True, padx=5)

        # 按钮
        self.btn_clear = ttk.Button(button_frame, text="清空输出", command=self._on_clear_output)
        self.btn_clear.pack(side="right", padx=5)

        self.btn_detect = ttk.Button(button_frame, text="开始检测", command=self._on_detect_click)
        self.btn_detect.pack(side="right", padx=5)

        self.btn_list_objects = ttk.Button(button_frame, text="列出存储桶内容", command=self._on_list_objects_click)
        self.btn_list_objects.pack(side="right", padx=5)
        self.btn_list_objects.pack_forget()  # 初始隐藏

        self.btn_collect_info = ttk.Button(button_frame, text="搜集敏感信息", command=self._on_collect_info_click)
        self.btn_collect_info.pack(side="right", padx=5)
        self.btn_collect_info.pack_forget()  # 初始隐藏

        # “下一页”按钮，初始隐藏
        self.btn_next_page = ttk.Button(button_frame, text="下一页", command=self._on_next_page_click)
        self.btn_next_page.pack(side="right", padx=5)
        self.btn_next_page.pack_forget()  # 初始隐藏

    def _on_clear_output(self):
        # 清空Treeview内容
        for item in self.tree_output.get_children():
            self.tree_output.delete(item)
        # 清空日志输出
        self.text_output.delete("1.0", tk.END)

    def _on_detect_click(self):
        # 读取用户输入
        ak = self.entry_ak.get().strip()
        sk = self.entry_sk.get().strip()
        token = self.entry_token.get().strip()
        endpoint = self.entry_endpoint.get().strip()
        bucket_name = self.entry_bucket_name.get().strip()
        provider = self.provider_var.get().strip()

        # 基础校验
        if not ak or not sk or not endpoint or not bucket_name:
            messagebox.showwarning("输入不完整", "请确保AK、SK、Endpoint、Bucket Name均已填写！")
            return

        # 清空输出并开始检测
        self._on_clear_output()
        self.queue.put({'type': 'log', 'content': "正在启动检测，请稍候...\n"})

        # 禁用“开始检测”按钮以防重复点击
        self.btn_detect.config(state='disabled')

        # 启动进度条
        self.progress_bar.start()

        # 使用线程避免阻塞界面
        def detect():
            self.queue.put({'type': 'log', 'content': "--- 检测流程开始 ---\n"})
            self.queue.put({'type': 'log', 'content': "初始化云存储处理类...\n"})
            try:
                handler = get_cloud_handler(provider, ak, sk, token, endpoint)  # 获取handler
                self.queue.put({'type': 'log', 'content': "   云存储处理类初始化成功。\n"})
            except Exception as e:
                self.queue.put({'type': 'log', 'content': f"   初始化失败：{e}\n"})
                self.queue.put({'type': 'control', 'command': 'enable_detect_button'})
                self.queue.put({'type': 'control', 'command': 'stop_progress'})
                return

            # 将handler和bucket_name保存，供后续按钮使用
            self.current_handler = handler
            self.current_bucket_name = bucket_name

            # 1. 凭据有效性校验
            self.queue.put({'type': 'log', 'content': "\n1. 凭据有效性校验...\n"})
            try:
                if handler.check_credentials_valid():
                    self.queue.put({'type': 'log', 'content': "   凭据有效，访问正常。\n"})
                else:
                    self.queue.put({'type': 'log', 'content': "   凭据无效或权限不足。\n"})
                    self.queue.put({'type': 'control', 'command': 'enable_detect_button'})
                    self.queue.put({'type': 'control', 'command': 'stop_progress'})
                    return
            except NotImplementedError:
                self.queue.put({'type': 'log', 'content': "   凭据检测尚未实现。\n"})
                self.queue.put({'type': 'control', 'command': 'enable_detect_button'})
                self.queue.put({'type': 'control', 'command': 'stop_progress'})
                return
            except Exception as e:
                self.queue.put({'type': 'log', 'content': f"   凭据检测失败：{e}\n"})
                self.queue.put({'type': 'control', 'command': 'enable_detect_button'})
                self.queue.put({'type': 'control', 'command': 'stop_progress'})
                return

            # 2. Bucket存在性检测
            self.queue.put({'type': 'log', 'content': "\n2. Bucket存在性检测...\n"})
            try:
                exists = handler.does_bucket_exist(bucket_name)
                if exists:
                    self.queue.put({'type': 'log', 'content': f"   Bucket '{bucket_name}' 存在，可访问。\n"})
                else:
                    self.queue.put({'type': 'log', 'content': f"   Bucket '{bucket_name}' 不存在或无访问权限。\n"})
                    self.queue.put({'type': 'control', 'command': 'enable_detect_button'})
                    self.queue.put({'type': 'control', 'command': 'stop_progress'})
                    return
            except NotImplementedError:
                self.queue.put({'type': 'log', 'content': "   Bucket存在性检测尚未实现。\n"})
                self.queue.put({'type': 'control', 'command': 'enable_detect_button'})
                self.queue.put({'type': 'control', 'command': 'stop_progress'})
                return
            except Exception as e:
                self.queue.put({'type': 'log', 'content': f"   检测Bucket存在性失败：{e}\n"})
                self.queue.put({'type': 'control', 'command': 'enable_detect_button'})
                self.queue.put({'type': 'control', 'command': 'stop_progress'})
                return

            # 3. 上传与下载测试
            self.queue.put({'type': 'log', 'content': "\n3. 上传与下载测试...\n"})
            object_key = "test_detection_object.txt"
            test_content = "This is a test content."
            try:
                # 上传
                upload_res = handler.upload_object_from_string(bucket_name, object_key, test_content)
                self.queue.put({'type': 'log', 'content': "   上传成功！上传返回信息：\n"})
                self.queue.put({'type': 'log', 'content': json.dumps(upload_res, ensure_ascii=False, indent=2) + "\n"})
                
                # 将上传的对象插入到Treeview
                self.queue.put({'type': 'result', 'content': object_key})

                # 下载
                downloaded = handler.download_object_to_string(bucket_name, object_key)
                if downloaded == test_content:
                    self.queue.put({'type': 'log', 'content': "   下载并验证成功，内容与上传一致。\n"})
                else:
                    self.queue.put({'type': 'log', 'content': "   下载内容与原始内容不一致，请检查存储完整性。\n"})
            except NotImplementedError:
                self.queue.put({'type': 'log', 'content': "   上传或下载测试尚未实现。\n"})
                self.queue.put({'type': 'control', 'command': 'enable_detect_button'})
                self.queue.put({'type': 'control', 'command': 'stop_progress'})
                return
            except Exception as e:
                self.queue.put({'type': 'log', 'content': f"   上传/下载测试失败：{e}\n"})
                self.queue.put({'type': 'control', 'command': 'enable_detect_button'})
                self.queue.put({'type': 'control', 'command': 'stop_progress'})
                return

            # 4. 对象存在性检测
            self.queue.put({'type': 'log', 'content': "\n4. 对象存在性检测...\n"})
            try:
                obj_exists = handler.does_object_exist(bucket_name, object_key)
                if obj_exists:
                    self.queue.put({'type': 'log', 'content': f"   对象'{object_key}'确认存在。\n"})
                else:
                    self.queue.put({'type': 'log', 'content': f"   对象'{object_key}'不存在或不可访问。\n"})
            except NotImplementedError:
                self.queue.put({'type': 'log', 'content': "   对象存在性检测尚未实现。\n"})
            except Exception as e:
                self.queue.put({'type': 'log', 'content': f"   检测对象存在性失败：{e}\n"})

            # 5. 权限与ACL检测
            self.queue.put({'type': 'log', 'content': "\n5. 权限与ACL检测...\n"})
            try:
                perm_ok = handler.check_permissions(bucket_name, object_key)
                if perm_ok:
                    self.queue.put({'type': 'log', 'content': "   权限检测通过，ACL访问正常。\n"})
                else:
                    self.queue.put({'type': 'log', 'content': "   权限检测未通过，可能存在ACL或Policy配置问题。\n"})
            except NotImplementedError:
                self.queue.put({'type': 'log', 'content': "   权限检测尚未实现。\n"})
            except Exception as e:
                self.queue.put({'type': 'log', 'content': f"   权限检测失败：{e}\n"})

            # 返回公共请求链接
            self.queue.put({'type': 'log', 'content': "\n获取对象URL...\n"})
            try:
                url = handler.get_object_url(bucket_name, object_key)
                self.queue.put({'type': 'log', 'content': f"对象URL（如公共访问权限已配置）：\n{url}\n"})
            except NotImplementedError:
                self.queue.put({'type': 'log', 'content': "对象URL获取尚未实现。\n"})
            except Exception as e:
                self.queue.put({'type': 'log', 'content': f"获取对象URL失败：{e}\n"})

            self.queue.put({'type': 'log', 'content': "\n--- 检测流程结束 ---\n"})
            self.queue.put({'type': 'log', 'content': "检测已完成，请查看上方结果。\n"})

            # 检测成功后显示“列出存储桶内容”、“搜集敏感信息”按钮
            self.queue.put({'type': 'control', 'command': 'enable_buttons'})

            # 重新启用“开始检测”按钮并停止进度条
            self.queue.put({'type': 'control', 'command': 'enable_detect_button'})
            self.queue.put({'type': 'control', 'command': 'stop_progress'})

        t = threading.Thread(target=detect)
        t.daemon = True
        t.start()

    def process_queue(self):
        '''处理消息队列中的任务'''
        try:
            while not self.queue.empty():
                task = self.queue.get_nowait()
                self.update_gui_with_task_result(task)
        except Exception as e:
            messagebox.showerror('Error', f'处理队列时出错: {str(e)}')
        finally:
            self.root.after(100, self.process_queue)  # 继续检查队列

    def update_gui_with_task_result(self, task):
        '''根据任务结果更新GUI元素'''
        task_type = task.get('type')
        content = task.get('content')
        command = task.get('command')

        if task_type == "control":
            if command == "enable_buttons":
                self._show_additional_buttons()
            elif command == "show_next_page":
                self.btn_next_page.pack(side="right", padx=5)
            elif command == "hide_next_page":
                self.btn_next_page.pack_forget()
            elif command == "enable_detect_button":
                self.btn_detect.config(state='normal')
            elif command == "stop_progress":
                self.progress_bar.stop()
        elif task_type == "log":
            self._append_output(content)
        elif task_type == "result":
            # 将结果插入到Treeview
            self.tree_output.insert("", "end", values=(content,))
        else:
            # 未知类型，默认作为日志处理
            self._append_output(content)

    def _append_output(self, msg: str):
        '''在日志输出区域追加消息'''
        self.text_output.insert(tk.END, msg)
        self.text_output.see(tk.END)

    def _show_additional_buttons(self):
        '''显示“列出存储桶内容”和“搜集敏感信息”按钮'''
        self.btn_list_objects.pack(side="right", padx=5)
        self.btn_collect_info.pack(side="right", padx=5)

    def _on_list_objects_click(self):
        if hasattr(self, 'current_handler') and hasattr(self, 'current_bucket_name'):
            # 启动一个新线程来列出存储桶内容
            def list_objects():
                self.queue.put({'type': 'log', 'content': "\n--- 列出存储桶内容 ---\n"})
                try:
                    objects, next_marker = self.current_handler.list_objects(
                        self.current_bucket_name,
                        max_keys=100,
                        marker=self.current_marker
                    )
                    if objects:
                        self.queue.put({'type': 'log', 'content': "以下是存储桶中对象列表（最多100个）：\n"})
                        for obj in objects:
                            self.queue.put({'type': 'result', 'content': obj})
                    else:
                        self.queue.put({'type': 'log', 'content': "存储桶中没有对象或无权限访问。\n"})

                    self.current_marker = next_marker
                    if self.current_marker:
                        self.queue.put({'type': 'control', 'command': 'show_next_page'})
                    else:
                        self.queue.put({'type': 'control', 'command': 'hide_next_page'})
                except Exception as e:
                    self.queue.put({'type': 'log', 'content': f"列出对象失败：{e}\n"})

            t = threading.Thread(target=list_objects)
            t.daemon = True
            t.start()
        else:
            self.queue.put({'type': 'log', 'content': "无法列出对象，请先进行检测。\n"})

    def _on_collect_info_click(self):
        if hasattr(self, 'current_handler') and hasattr(self, 'current_bucket_name'):
            # 启动一个新线程来搜集敏感信息
            def collect_info():
                self.queue.put({'type': 'log', 'content': "\n--- 搜集敏感信息 ---\n"})
                keywords = ["password", "secret", "key"]  # 示例关键词
                try:
                    result = self.current_handler.search_sensitive_info(self.current_bucket_name, prefix="", keywords=keywords)
                    if result.get("matched_objects"):
                        self.queue.put({'type': 'log', 'content': "发现可能包含敏感信息的对象：\n"})
                        for obj in result.get("matched_objects"):
                            self.queue.put({'type': 'result', 'content': obj})
                        self.queue.put({'type': 'log', 'content': json.dumps(result, ensure_ascii=False, indent=2) + "\n"})
                    else:
                        self.queue.put({'type': 'log', 'content': "未发现匹配的敏感信息。\n"})
                except Exception as e:
                    self.queue.put({'type': 'log', 'content': f"敏感信息搜集失败：{e}\n"})

            t = threading.Thread(target=collect_info)
            t.daemon = True
            t.start()
        else:
            self.queue.put({'type': 'log', 'content': "无法搜集信息，请先进行检测。\n"})

    def _on_next_page_click(self):
        if hasattr(self, 'current_handler') and hasattr(self, 'current_bucket_name'):
            # 启动一个新线程来获取下一页的对象
            def fetch_next_page():
                self.queue.put({'type': 'log', 'content': "\n--- 获取下一页对象 ---\n"})
                try:
                    objects, next_marker = self.current_handler.list_objects(
                        self.current_bucket_name,
                        max_keys=100,
                        marker=self.current_marker
                    )
                    if objects:
                        self.queue.put({'type': 'log', 'content': "以下是存储桶中对象列表（下一页）：\n"})
                        for obj in objects:
                            self.queue.put({'type': 'result', 'content': obj})
                    else:
                        self.queue.put({'type': 'log', 'content': "没有更多对象。\n"})

                    self.current_marker = next_marker
                    if self.current_marker:
                        self.queue.put({'type': 'control', 'command': 'show_next_page'})
                    else:
                        self.queue.put({'type': 'control', 'command': 'hide_next_page'})
                except Exception as e:
                    self.queue.put({'type': 'log', 'content': f"获取下一页对象失败：{e}\n"})

            t = threading.Thread(target=fetch_next_page)
            t.daemon = True
            t.start()
        else:
            self.queue.put({'type': 'log', 'content': "无法获取下一页对象，请先进行检测。\n"})

if __name__ == "__main__":
    root = tk.Tk()
    app = CloudGuiApp(root)
    root.mainloop()