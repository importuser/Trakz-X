# Copyright (c) import user
# ----------------------------------------------------------
# TrakzX is an advanced HTTPS request and diagnostics toolkit
# that reveals deep and often unseen information about websites.
# 
# With built-in bypass layers and compatibility with many
# HTTP/HTTPS methods and protocols, TrakzX is designed for
# powerful analysis and tracking — all in one UI.
# 
# This project took a lot of effort to build. If you use it
# or share it, please consider giving proper credit.
# It would truly make my day. Thank you — and enjoy TrakzX!
# ----------------------------------------------------------
# Installation (Linux/macOS/Windows):
# pip install requests httpx whois PySide6 psutil

import sys
import os
import socket
import ssl
import json
import random
import string
import time
import requests
import httpx
import whois
import psutil
import subprocess

from PySide6.QtCore import Qt, QThread, Signal, QTimer
from urllib.parse import urlparse, quote
from concurrent.futures import ThreadPoolExecutor
from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QTextEdit, QTabWidget, QProgressBar,
    QPlainTextEdit, QTableWidget, QTableWidgetItem, QHeaderView,
     QListWidget, QInputDialog
)

# --- Utilities ---


def random_user_agent():
    agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/115.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/605.1.15 Version/16.5 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/116.0",
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "curl/7.68.0",
        "Wget/1.20.3 (linux-gnu)",
        "Mozilla/5.0 (Linux; Android 9; SM-G960U) AppleWebKit/537.36 Chrome/91.0 Mobile Safari/537.36",
    ]
    return random.choice(agents)


def safe_request(method, url, **kwargs):
    try:
        resp = requests.request(method, url, timeout=10, **kwargs)
        return resp.status_code, resp.text[:2000]
    except Exception as e:
        return None, f"Request error: {e}"


# --- Bypass Methods ---


def bypass_x_http_method_override(url, method):
    headers = {"X-HTTP-Method-Override": method.upper(), "User-Agent": random_user_agent()}
    return safe_request("POST", url, headers=headers)


def bypass_chunked_transfer(url, method):
    headers = {"Transfer-Encoding": "chunked", "User-Agent": random_user_agent()}
    return safe_request(method, url, headers=headers)


def bypass_random_headers(url, method):
    headers = {
        "User-Agent": random_user_agent(),
        "X-Custom-Header": ''.join(random.choices(string.ascii_letters + string.digits, k=12)),
        "X-Request-ID": ''.join(random.choices(string.ascii_letters + string.digits, k=16)),
        "Accept": "*/*",
        "Connection": "keep-alive",
        "Cache-Control": "no-cache",
    }
    return safe_request(method, url, headers=headers, data={"dummy": "data"} if method == "POST" else None)


def bypass_http_param_pollution(url, method):
    sep = '&' if '?' in url else '?'
    polluted_url = f"{url}{sep}v=1&v=2"
    return safe_request(method, polluted_url)


def bypass_fake_options(url, method):
    safe_request("OPTIONS", url)
    return safe_request(method, url)


def bypass_malformed_headers(url, method):
    headers = {
        "User-Agent": random_user_agent() + "  ",
        "X-Test-Header": "value\r\nInjected-Header: bad",
    }
    return safe_request(method, url, headers=headers)


def bypass_slow_post(url, method):
    if method != "POST":
        return None, "Skipped slow post: not POST method"
    try:
        session = requests.Session()
        req = requests.Request("POST", url, headers={"User-Agent": random_user_agent()}, data="a" * 10)
        prepped = session.prepare_request(req)
        resp = session.send(prepped, timeout=10, stream=True)
        return resp.status_code, resp.text[:2000]
    except Exception as e:
        return None, f"Error: {e}"


def bypass_alt_content_type(url, method):
    headers = {"Content-Type": random.choice(["text/plain", "application/xml"]), "User-Agent": random_user_agent()}
    return safe_request(method, url, headers=headers)


def bypass_force_http_1_0(url, method):
    try:
        parsed = urlparse(url)
        import http.client

        conn = http.client.HTTPConnection(parsed.hostname, parsed.port or 80, timeout=10)
        path = parsed.path or "/"
        conn.request(method, path, headers={"User-Agent": random_user_agent()})
        resp = conn.getresponse()
        return resp.status, resp.read().decode('utf-8', 'ignore')[:2000]
    except Exception as e:
        return None, f"Error: {e}"


def bypass_encoded_path(url, method):
    parsed = urlparse(url)
    encoded_path = quote(parsed.path or "/")
    new_url = f"{parsed.scheme}://{parsed.netloc}{encoded_path}"
    return safe_request(method, new_url)


def bypass_referer_spoof(url, method):
    headers = {
        "Referer": "https://google.com",
        "User-Agent": random_user_agent()
    }
    return safe_request(method, url, headers=headers)


def bypass_accept_encoding_variations(url, method):
    encodings = ["gzip", "deflate", "br", "identity"]
    headers = {
        "Accept-Encoding": random.choice(encodings),
        "User-Agent": random_user_agent()
    }
    return safe_request(method, url, headers=headers)


def bypass_raw_tcp_socket(url, method):
    # Only GET supported here for simplicity
    if method != "GET":
        return None, "Raw TCP socket bypass only supports GET"
    try:
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or 80
        path = parsed.path or "/"
        request_line = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {random_user_agent()}\r\nConnection: close\r\n\r\n"
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((host, port))
        sock.sendall(request_line.encode())
        response = b""
        while True:
            data = sock.recv(4096)
            if not data:
                break
            response += data
        sock.close()
        # Return status line + first 2000 bytes
        response_text = response.decode(errors='ignore')
        status_line = response_text.splitlines()[0] if response_text else "No response"
        return status_line, response_text[:2000]
    except Exception as e:
        return None, f"Raw TCP socket error: {e}"


def http2_request(url, method):
    try:
        with httpx.Client(http2=True, timeout=10) as client:
            r = client.request(method, url)
            return r.status_code, r.text[:2000]
    except Exception as e:
        return None, f"HTTP/2 error: {e}"


# --- SOCKS5 / TOR Support ---


def socks_request(url, proxy_addr="127.0.0.1", port=9050, method="GET"):
    proxies = {
        "http": f"socks5h://{proxy_addr}:{port}",
        "https": f"socks5h://{proxy_addr}:{port}"
    }
    try:
        r = requests.request(method, url, proxies=proxies, timeout=10)
        return r.status_code, r.text[:2000]
    except Exception as e:
        return None, f"SOCKS proxy error: {e}"


# --- Diagnostics ---


def get_ip(url):
    try:
        hostname = urlparse(url).hostname
        ip = socket.gethostbyname(hostname)
        return ip
    except Exception as e:
        return f"IP resolution error: {e}"


def whois_data(domain):
    try:
        data = whois.whois(domain)
        return json.dumps(data, default=str, indent=2)
    except Exception as e:
        return f"WHOIS error: {e}"


def traceroute(domain):
    try:
        import platform
        cmd = "tracert" if platform.system().lower() == "windows" else "traceroute"
        output = os.popen(f"{cmd} {domain}").read()
        return output
    except Exception as e:
        return f"Traceroute error: {e}"


def geoip(ip):
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}")
        return json.dumps(res.json(), indent=2)
    except Exception as e:
        return f"GeoIP error: {e}"


def ssl_info(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return json.dumps(cert, indent=2)
    except Exception as e:
        return f"SSL error: {e}"


def dns_info(domain):
    try:
        data = socket.getaddrinfo(domain, None)
        return json.dumps(data, indent=2, default=str)
    except Exception as e:
        return f"DNS info error: {e}"


def http_headers(url, method):
    try:
        r = requests.request(method, url, timeout=10)
        return json.dumps(dict(r.headers), indent=2)
    except Exception as e:
        return f"Headers error: {e}"


def http_methods_fuzzer(url):
    methods = ["GET", "POST", "OPTIONS", "HEAD", "TRACE", "PUT", "PATCH"]
    results = ""
    for method in methods:
        try:
            r = requests.request(method, url, timeout=10)
            results += f"{method}: {r.status_code}\n"
        except Exception as e:
            results += f"{method}: Error {e}\n"
    return results


# --- Worker Thread ---


class RequestWorker(QThread):
    progress = Signal(int)
    finished = Signal(dict)

    def __init__(self, url, method):
        super().__init__()
        self.url = url
        self.method = method.upper()

    def run(self):
        results = {}
        self.progress.emit(5)

        # Normal request with retries
        retries = 10
        normal_result = None
        for i in range(retries):
            code, text = safe_request(self.method, self.url)
            if code is not None:
                normal_result = (code, text)
                break
            time.sleep(0.5)
        if normal_result is None:
            normal_result = (None, "Failed after 10 retries")

        results["normal"] = normal_result
        self.progress.emit(15)

        # Bypass methods concurrently
        bypass_methods = [
            bypass_x_http_method_override,
            bypass_chunked_transfer,
            bypass_random_headers,
            bypass_http_param_pollution,
            bypass_fake_options,
            bypass_malformed_headers,
            bypass_slow_post,
            bypass_alt_content_type,
            bypass_force_http_1_0,
            bypass_encoded_path,
            bypass_referer_spoof,
            bypass_accept_encoding_variations,
            bypass_raw_tcp_socket,
            http2_request,
        ]

        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(fn, self.url, self.method) for fn in bypass_methods]
            bypass_results = [f.result() for f in futures]
        results["bypass"] = bypass_results
        self.progress.emit(40)

        # SOCKS5 / TOR requests with retries and port fallback
        tor_ports = [9050, 9150]
        tor_result = None
        for port in tor_ports:
            for _ in range(3):  # 3 tries per port
                code, text = socks_request(self.url, port=port, method=self.method)
                if code is not None:
                    tor_result = (code, text)
                    break
                time.sleep(1)
            if tor_result is not None:
                break
        if tor_result is None:
            tor_result = (None, "Failed to connect via SOCKS proxy after retries")

        results["tor"] = tor_result
        self.progress.emit(60)

        # Diagnostics
        domain = urlparse(self.url).hostname
        ip = get_ip(self.url)
        diagnostics = {}

        diagnostics["ip"] = ip
        diagnostics["geoip"] = geoip(ip) if ip and not ip.startswith("IP resolution") else "GeoIP skipped due to IP error"
        diagnostics["whois"] = whois_data(domain)
        diagnostics["ssl"] = ssl_info(domain)
        diagnostics["dns"] = dns_info(domain)
        diagnostics["traceroute"] = traceroute(domain)
        diagnostics["headers"] = http_headers(self.url, self.method)
        diagnostics["http_methods"] = http_methods_fuzzer(self.url)

        results["diagnostics"] = diagnostics
        self.progress.emit(100)
        self.finished.emit(results)


# --- Additional Tabs Implementation ---


class SystemMonitorTab(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        self.cpu_label = QLabel("CPU Usage:")
        self.mem_label = QLabel("Memory Usage:")
        self.cpu_progress = QProgressBar()
        self.mem_progress = QProgressBar()
        layout.addWidget(self.cpu_label)
        layout.addWidget(self.cpu_progress)
        layout.addWidget(self.mem_label)
        layout.addWidget(self.mem_progress)

        self.timer = QTimer()
        self.timer.timeout.connect(self.update_stats)
        self.timer.start(1000)

    def update_stats(self):
        cpu = psutil.cpu_percent()
        mem = psutil.virtual_memory().percent
        self.cpu_progress.setValue(int(cpu))
        self.mem_progress.setValue(int(mem))
        self.cpu_label.setText(f"CPU Usage: {cpu}%")
        self.mem_label.setText(f"Memory Usage: {mem}%")


class ProcessViewerTab(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["PID", "Name", "User", "Status", "Memory %"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.table)

        self.timer = QTimer()
        self.timer.timeout.connect(self.update_processes)
        self.timer.start(2000)
        self.update_processes()

    def update_processes(self):
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'username', 'status', 'memory_percent']):
            try:
                processes.append(proc.info)
            except Exception:
                pass
        self.table.setRowCount(len(processes))
        for row, proc in enumerate(processes):
            self.table.setItem(row, 0, QTableWidgetItem(str(proc.get('pid', ''))))
            self.table.setItem(row, 1, QTableWidgetItem(proc.get('name', '')))
            self.table.setItem(row, 2, QTableWidgetItem(proc.get('username', '')))
            self.table.setItem(row, 3, QTableWidgetItem(proc.get('status', '')))
            mem_pct = proc.get('memory_percent', 0.0)
            self.table.setItem(row, 4, QTableWidgetItem(f"{mem_pct:.2f}"))


class FileViewerTab(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        self.path_input = QLineEdit(placeholderText="Enter file path")
        self.load_btn = QPushButton("Load File")
        self.text_area = QPlainTextEdit()
        self.text_area.setReadOnly(True)

        hl = QHBoxLayout()
        hl.addWidget(self.path_input)
        hl.addWidget(self.load_btn)

        layout.addLayout(hl)
        layout.addWidget(self.text_area)

        self.load_btn.clicked.connect(self.load_file)

    def load_file(self):
        path = self.path_input.text().strip()
        if not os.path.isfile(path):
            self.text_area.setPlainText("File does not exist.")
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            self.text_area.setPlainText(content)
        except Exception as e:
            self.text_area.setPlainText(f"Failed to read file: {e}")


# New tabs for Network Monitor, Task Scheduler, and System Logs Viewer


class NetworkMonitorTab(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)

        self.net_stats_label = QLabel("Network I/O Stats:")
        self.net_stats_text = QTextEdit()
        self.net_stats_text.setReadOnly(True)

        layout.addWidget(self.net_stats_label)
        layout.addWidget(self.net_stats_text)

        self.timer = QTimer()
        self.timer.timeout.connect(self.update_net_stats)
        self.timer.start(2000)

    def update_net_stats(self):
        net_io = psutil.net_io_counters(pernic=False)
        text = (
            f"Bytes Sent: {net_io.bytes_sent}\n"
            f"Bytes Received: {net_io.bytes_recv}\n"
            f"Packets Sent: {net_io.packets_sent}\n"
            f"Packets Received: {net_io.packets_recv}\n"
            f"Errors In: {net_io.errin}\n"
            f"Errors Out: {net_io.errout}\n"
            f"Drop In: {net_io.dropin}\n"
            f"Drop Out: {net_io.dropout}\n"
        )
        self.net_stats_text.setPlainText(text)


class TaskSchedulerTab(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)

        self.task_list = QListWidget()
        self.refresh_btn = QPushButton("Refresh Tasks")
        self.add_btn = QPushButton("Add Task")
        self.remove_btn = QPushButton("Remove Selected Task")

        hl = QHBoxLayout()
        hl.addWidget(self.refresh_btn)
        hl.addWidget(self.add_btn)
        hl.addWidget(self.remove_btn)

        layout.addLayout(hl)
        layout.addWidget(self.task_list)

        self.refresh_btn.clicked.connect(self.load_tasks)
        self.add_btn.clicked.connect(self.add_task)
        self.remove_btn.clicked.connect(self.remove_task)

        self.load_tasks()

    def load_tasks(self):
        self.task_list.clear()
        try:
            cron = subprocess.check_output("crontab -l", shell=True, stderr=subprocess.STDOUT).decode()
            for line in cron.splitlines():
                if line.strip() and not line.startswith("#"):
                    self.task_list.addItem(line)
        except subprocess.CalledProcessError:
            self.task_list.addItem("No crontab for current user or crontab command not available.")

    def add_task(self):
        task, ok = QInputDialog.getText(self, "Add Cron Task", "Enter cron schedule and command:")
        if ok and task.strip():
            try:
                current = subprocess.check_output("crontab -l", shell=True, stderr=subprocess.STDOUT).decode()
            except subprocess.CalledProcessError:
                current = ""
            new_cron = current + "\n" + task.strip() + "\n"
            p = subprocess.Popen(['crontab'], stdin=subprocess.PIPE)
            p.communicate(input=new_cron.encode())
            self.load_tasks()

    def remove_task(self):
        selected = self.task_list.currentItem()
        if not selected:
            return
        task_text = selected.text()
        try:
            current = subprocess.check_output("crontab -l", shell=True, stderr=subprocess.STDOUT).decode()
            lines = [line for line in current.splitlines() if line.strip() != task_text]
            new_cron = "\n".join(lines) + "\n"
            p = subprocess.Popen(['crontab'], stdin=subprocess.PIPE)
            p.communicate(input=new_cron.encode())
            self.load_tasks()
        except subprocess.CalledProcessError:
            pass


class SystemLogsTab(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)

        self.log_path_input = QLineEdit(placeholderText="Enter log file path")
        self.load_btn = QPushButton("Load Log File")
        self.log_text = QPlainTextEdit()
        self.log_text.setReadOnly(True)

        hl = QHBoxLayout()
        hl.addWidget(self.log_path_input)
        hl.addWidget(self.load_btn)

        layout.addLayout(hl)
        layout.addWidget(self.log_text)

        self.load_btn.clicked.connect(self.load_log)

    def load_log(self):
        path = self.log_path_input.text().strip()
        if not os.path.isfile(path):
            self.log_text.setPlainText("Log file does not exist.")
            return
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            self.log_text.setPlainText(content)
        except Exception as e:
            self.log_text.setPlainText(f"Failed to read log file: {e}")


# --- Main Window ---


class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("TrakzX")
        self.resize(1100, 800)

        main_layout = QVBoxLayout(self)

        title = QLabel("TrakzX - web tracker V1")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("font-weight: bold; font-size: 40px;")
        main_layout.addWidget(title)

        # Input area
        input_layout = QHBoxLayout()
        self.url_input = QLineEdit(placeholderText="Enter URL (http:// or https://)")
        self.method_input = QLineEdit(placeholderText= ("Methods: Get, Post, Options, Head, Put, Patch, and Trace"))
        self.method_input.setMaxLength(6)
        input_layout.addWidget(self.url_input)
        input_layout.addWidget(self.method_input)
        main_layout.addLayout(input_layout)

        # Buttons and progress
        btn_layout = QHBoxLayout()
        self.start_btn = QPushButton("Start")
        self.start_btn.clicked.connect(self.start)
        self.loading_label = QLabel("Running...")
        self.loading_label.setVisible(False)
        btn_layout.addWidget(self.start_btn)
        btn_layout.addWidget(self.loading_label)
        main_layout.addLayout(btn_layout)

        self.progress = QProgressBar()
        main_layout.addWidget(self.progress)

        # Tabs
        self.tabs = QTabWidget()

        # HTTP tabs
        self.tab_normal = QTextEdit(readOnly=True)
        self.tab_bypass = QTextEdit(readOnly=True)
        self.tab_tor = QTextEdit(readOnly=True)
        self.tab_diagnostics = QTextEdit(readOnly=True)

        self.tabs.addTab(self.tab_normal, "Normal Response")
        self.tabs.addTab(self.tab_bypass, "Bypass Attempts")
        self.tabs.addTab(self.tab_tor, "Tor/SOCKS5 Proxy")
        self.tabs.addTab(self.tab_diagnostics, "Diagnostics")

        # System tabs
        self.tab_sysmon = SystemMonitorTab()
        self.tab_procs = ProcessViewerTab()
        self.tab_fileviewer = FileViewerTab()

        self.tabs.addTab(self.tab_procs, "Process Viewer")

        # New additional tabs
        self.tab_netmon = NetworkMonitorTab()
        self.tab_tasks = TaskSchedulerTab()
        self.tab_syslogs = SystemLogsTab()

        self.tabs.addTab(self.tab_netmon, "Network Monitor")
        self.tabs.addTab(self.tab_tasks, "Task Scheduler")
        self.tabs.addTab(self.tab_syslogs, "System Logs Viewer")

        main_layout.addWidget(self.tabs)

    def start(self):
        url = self.url_input.text().strip()
        method = self.method_input.text().strip().upper()
        valid_methods = ("GET", "POST", "OPTIONS", "HEAD", "PUT", "PATCH", "TRACE")
        if not url.startswith("http") or method not in valid_methods:
            self.tab_normal.setPlainText("Invalid URL or HTTP method. Use GET, POST, OPTIONS, HEAD, PUT, PATCH, TRACE.")
            return

        self.progress.setValue(0)
        self.start_btn.setEnabled(False)
        self.loading_label.setVisible(True)

        self.worker = RequestWorker(url, method)
        self.worker.progress.connect(self.progress.setValue)
        self.worker.finished.connect(self.done)
        self.worker.start()

    def done(self, results):
        self.start_btn.setEnabled(True)
        self.loading_label.setVisible(False)
        self.progress.setValue(100)

        # Normal response
        code, text = results.get("normal", (None, "No normal response"))
        self.tab_normal.setPlainText(f"Status: {code}\n\n{text}")

        # Bypass attempts
        bypasses = results.get("bypass", [])
        report = f"Successful bypass attempts: {sum(1 for c, _ in bypasses if c and c != 501)}/{len(bypasses)}\n\n"
        for i, (code, text) in enumerate(bypasses, 1):
            report += f"== Attempt #{i} ==\nStatus: {code}\n{text}\n\n"
        self.tab_bypass.setPlainText(report)

        # Tor/SOCKS5 proxy
        tcode, ttext = results.get("tor", (None, "No tor/socks5 response"))
        self.tab_tor.setPlainText(f"Status: {tcode}\n\n{ttext}")

        # Diagnostics
        diag = results.get("diagnostics", {})
        diag_text = ""
        for key, val in diag.items():
            diag_text += f"--- {key.upper()} ---\n{val}\n\n"
        self.tab_diagnostics.setPlainText(diag_text)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
