import csv
import socket
import asyncio
import threading
import subprocess
import platform
import sqlite3
import datetime

from folium import plugins
from ping3 import ping
from geopy.geocoders import Nominatim
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import folium
import webbrowser

from ping3.errors import PingError

# Конфигурация геолокатора
geolocator = Nominatim(user_agent="dns_ping_tool")

# Функция для создания таблицы, если она не существует
def initialize_db():
    conn = sqlite3.connect('ping_history.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ping_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            dns TEXT,
            ip TEXT,
            min_ping REAL,
            avg_ping REAL,
            max_ping REAL,
            packet_loss REAL,
            jitter REAL,
            traceroute TEXT,
            location TEXT,
            error TEXT
        )
    ''')
    conn.commit()
    conn.close()

# Инициализация базы данных
initialize_db()

def is_ipv6_address(address):
    """Проверяет, является ли адрес IPv6."""
    try:
        socket.inet_pton(socket.AF_INET6, address)
        return True
    except socket.error:
        return False

def supports_ipv6():
    """Проверяет, поддерживает ли система IPv6."""
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect(("google.com", 80))
        sock.close()
        return True
    except OSError:
        return False

def traceroute_host(ip, max_hops=30, timeout=2):
    """
    Выполняет traceroute до указанного IP-адреса.

    :param ip: IP-адрес назначения.
    :param max_hops: Максимальное количество прыжков.
    :param timeout: Таймаут для каждого запроса.
    :return: Строка с результатами traceroute.
    """
    system = platform.system()
    traceroute_result = ""
    try:
        if system == "Windows":
            cmd = ["tracert", "-d", ip]
        elif system in ("Linux", "Darwin"):
            cmd = ["traceroute", "-n", ip]
        else:
            return "Unsupported OS for traceroute."

        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = proc.communicate(timeout=60)
        if proc.returncode == 0:
            traceroute_result = stdout
        else:
            traceroute_result = stderr
    except subprocess.TimeoutExpired:
        proc.kill()
        traceroute_result = "Traceroute timed out."
    except Exception as e:
        traceroute_result = f"Traceroute failed: {e}"
    return traceroute_result

def ping_host(name, ip, count=10, timeout=2):
    """
    Пингует хост несколько раз и собирает статистику.

    :param name: Название сервера.
    :param ip: IP-адрес сервера.
    :param count: Количество попыток пинга.
    :param timeout: Таймаут для каждого пинга в секундах.
    :return: Словарь со статистикой пинга и traceroute.
    """
    min_time = None
    max_time = None
    avg_time = 0
    packet_loss = 0
    success_times = []
    jitters = []

    last_response = None

    for i in range(count):
        try:
            response = ping(ip, timeout=timeout, unit='ms')
            if response is not None:
                if response > 0:
                    success_times.append(response)
                    if min_time is None or response < min_time:
                        min_time = response
                    if max_time is None or response > max_time:
                        max_time = response
                    avg_time += response
                    if last_response is not None:
                        jitter = abs(response - last_response)
                        jitters.append(jitter)
                    last_response = response
                else:
                    packet_loss += 1
            else:
                packet_loss += 1
        except PingError:
            packet_loss += 1
        except Exception:
            packet_loss += 1

    total_pings = count
    received_pings = len(success_times)
    packet_loss_percent = (packet_loss / total_pings) * 100

    if received_pings > 0:
        avg_time = avg_time / received_pings
        avg_jitter = sum(jitters) / len(jitters) if jitters else 0
    else:
        avg_time = None
        min_time = None
        max_time = None
        avg_jitter = None

    # Выполнение traceroute
    traceroute_result = traceroute_host(ip)

    # Геолокация сервера
    try:
        location = geolocator.geocode(ip, timeout=10)
        if location:
            latitude = location.latitude
            longitude = location.longitude
            geo_info = f"{location.address} (Lat: {latitude}, Lon: {longitude})"
        else:
            geo_info = "Unknown Location"
    except Exception:
        geo_info = "Geolocation Failed"

    # Сохранение результатов в базу данных (отдельное соединение)
    try:
        conn = sqlite3.connect('ping_history.db')
        cursor = conn.cursor()
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute('''
            INSERT INTO ping_results (timestamp, dns, ip, min_ping, avg_ping, max_ping, packet_loss, jitter, traceroute, location, error)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (timestamp, name, ip, min_time, avg_time, max_time, packet_loss_percent, avg_jitter, traceroute_result, geo_info, 'None' if received_pings > 0 else 'All pings failed.'))
        conn.commit()
    except Exception as e:
        print(f"Ошибка при сохранении результатов в базу данных: {e}")
    finally:
        conn.close()

    return {
        'DNS': name,
        'IP': ip,
        'Location': geo_info,
        'Min Ping (ms)': f"{min_time:.2f}" if min_time is not None else 'N/A',
        'Avg Ping (ms)': f"{avg_time:.2f}" if avg_time is not None else 'N/A',
        'Max Ping (ms)': f"{max_time:.2f}" if max_time is not None else 'N/A',
        'Packet Loss (%)': f"{packet_loss_percent:.2f}",
        'Jitter (ms)': f"{avg_jitter:.2f}" if avg_jitter is not None else 'N/A',
        'Traceroute': traceroute_result,
        'Error': 'None' if received_pings > 0 else 'All pings failed.'
    }

class PingApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Game DNS Ping Tool")
        self.root.geometry("1400x900")

        # Параметры пинга
        self.ping_count = tk.IntVar(value=10)
        self.ping_timeout = tk.IntVar(value=2)

        # Создание интерфейса
        self.create_widgets()

        # Список серверов (предустановленные и пользовательские)
        self.dns_servers = {
        "Google": "8.8.8.8",
        "Google (2)": "8.8.4.4",
        "Google (IPv6)": "2001:4860:4860::8888",
        "Google (IPv6 2)": "2001:4860:4860::8844",

        "Cloudflare": "1.1.1.1",
        "Cloudflare (2)": "1.0.0.1",
        "Cloudflare (IPv6)": "2606:4700:4700::1111",
        "Cloudflare (IPv6 2)": "2606:4700:4700::1001",

        "Quad9": "9.9.9.9",
        "Quad9 (2)": "149.112.112.112",
        "Quad9 (IPv6)": "2620:fe::fe",
        "Quad9 (IPv6 2)": "2620:fe::9",

        "OpenDNS": "208.67.222.222",
        "OpenDNS (2)": "208.67.220.220",
        "OpenDNS FamilyShield": "208.67.222.123",
        "OpenDNS FamilyShield (2)": "208.67.220.123",
        "OpenDNS (IPv6)": "2620:0:ccc::2",
        "OpenDNS (IPv6 2)": "2620:0:ccd::2",

        "Yandex": "77.88.8.8",
        "Yandex (2)": "77.88.8.1",
        "Yandex (IPv6)": "2a02:6b8::feed:0ff",
        "Yandex (IPv6 2)": "2a02:6b8::feed:0ff",

        "Level3": "4.2.2.2",
        "Level3 (2)": "4.2.2.1",
        "Level3 (IPv6)": "2001:4860:4860::8844",
        "Level3 (IPv6 2)": "2001:4860:4860::8888",

        "Comodo Secure DNS": "8.26.56.26",
        "Comodo Secure DNS (2)": "8.20.247.20",
        "Comodo Secure DNS (IPv6)": "2001:41d0:2::5",
        "Comodo Secure DNS (IPv6 2)": "2001:41d0:2::6",

        "AdGuard DNS": "94.140.14.14",
        "AdGuard DNS (2)": "94.140.15.15",
        "AdGuard DNS Family": "94.140.14.15",
        "AdGuard DNS Family (2)": "94.140.15.16",
        "AdGuard DNS (IPv6)": "2a10:50c0::ad1:ff",
        "AdGuard DNS (IPv6 2)": "2a10:50c0::ad2:ff",

        "Neustar DNS": "156.154.70.1",
        "Neustar DNS (2)": "156.154.71.1",
        "Neustar DNS (IPv6)": "2620:74:1b::1:1",
        "Neustar DNS (IPv6 2)": "2620:74:1c::1:1",

        "DNS.WATCH": "84.200.69.80",
        "DNS.WATCH (2)": "84.200.70.40",
        "DNS.WATCH (IPv6)": "2001:1608:10:25::1c04:b12f",
        "DNS.WATCH (IPv6 2)": "2001:1608:10:25::9249:d69b",

        "CleanBrowsing": "185.228.168.9",
        "CleanBrowsing (2)": "185.228.169.9",
        "CleanBrowsing Family": "185.228.168.10",
        "CleanBrowsing Family (2)": "185.228.169.11",
        "CleanBrowsing Adult": "185.228.168.10",
        "CleanBrowsing Adult (2)": "185.228.169.11",
        "CleanBrowsing (IPv6)": "2a0d:2a00:1::",
        "CleanBrowsing (IPv6 2)": "2a0d:2a00:2::",

        "FreeDNS": "37.235.1.174",
        "FreeDNS (2)": "37.235.1.177",
        "FreeDNS (IPv6)": "2a10:50c0::ad1:ff",
        "FreeDNS (IPv6 2)": "2a10:50c0::ad2:ff",

        "Freenom World": "80.80.80.80",
        "Freenom World (2)": "80.80.81.81",
        "Freenom World (IPv6)": "2001:67c:28e8::",
        "Freenom World (IPv6 2)": "2001:67c:28e9::",

        "OpenNIC": "185.121.177.177",
        "OpenNIC (2)": "169.239.202.202",
        "OpenNIC (IPv6)": "2001:470:20::2",
        "OpenNIC (IPv6 2)": "2001:470:20::1",

        "UncensoredDNS": "91.239.100.100",
        "UncensoredDNS (2)": "89.233.43.71",
        "UncensoredDNS (IPv6)": "2001:67c:28e8::",
        "UncensoredDNS (IPv6 2)": "2001:67c:28e9::",

        "Dyn (Oracle)": "216.146.35.35",
        "Dyn (Oracle) (2)": "216.146.36.36",
        "Dyn (Oracle) (IPv6)": "2620:0:ccc::2:2",
        "Dyn (Oracle) (IPv6 2)": "2620:0:ccd::2:2",

        "Alternate DNS": "198.101.242.72",
        "Alternate DNS (2)": "23.253.163.53",
        "Alternate DNS (IPv6)": "2001:19f0:fe::1",
        "Alternate DNS (IPv6 2)": "2001:19f0:fe::2",

        "SafeDNS": "195.46.39.39",
        "SafeDNS (2)": "195.46.39.40",
        "SafeDNS (IPv6)": "2001:4860:4860::8888",
        "SafeDNS (IPv6 2)": "2001:4860:4860::8844",

        "Verisign": "64.6.64.6",
        "Verisign (2)": "64.6.65.6",
        "Verisign (IPv6)": "2620:74:1b::1:1",
        "Verisign (IPv6 2)": "2620:74:1c::1:1",

        "IBM Quad9": "9.9.9.10",
        "IBM Quad9 (2)": "149.112.112.10",
        "IBM Quad9 (IPv6)": "2620:fe::10",
        "IBM Quad9 (IPv6 2)": "2620:fe::fe10",

        "NextDNS": "45.90.28.0",
        "NextDNS (2)": "45.90.30.0",
        "NextDNS (IPv6)": "2a07:a8c0::",
        "NextDNS (IPv6 2)": "2a07:a8c1::",
            # Добавьте другие серверы или игровые серверы здесь
        }

        # Поддержка IPv6
        self.ipv6_supported = supports_ipv6()

    def create_widgets(self):
        # Параметры пинга
        params_frame = ttk.LabelFrame(self.root, text="Параметры пинга")
        params_frame.pack(fill="x", padx=10, pady=5)

        ttk.Label(params_frame, text="Количество пингов:").grid(row=0, column=0, padx=5, pady=5, sticky='e')
        ttk.Entry(params_frame, textvariable=self.ping_count, width=10).grid(row=0, column=1, padx=5, pady=5, sticky='w')

        ttk.Label(params_frame, text="Таймаут (сек):").grid(row=1, column=0, padx=5, pady=5, sticky='e')
        ttk.Entry(params_frame, textvariable=self.ping_timeout, width=10).grid(row=1, column=1, padx=5, pady=5, sticky='w')

        # Кнопки
        buttons_frame = ttk.Frame(self.root)
        buttons_frame.pack(fill="x", padx=10, pady=5)

        self.start_button = ttk.Button(buttons_frame, text="Начать пинг", command=self.start_ping)
        self.start_button.pack(side="left", padx=5)

        self.add_server_button = ttk.Button(buttons_frame, text="Добавить сервер", command=self.add_server)
        self.add_server_button.pack(side="left", padx=5)

        self.load_servers_button = ttk.Button(buttons_frame, text="Загрузить сервера", command=self.load_servers)
        self.load_servers_button.pack(side="left", padx=5)

        self.save_servers_button = ttk.Button(buttons_frame, text="Сохранить сервера", command=self.save_servers)
        self.save_servers_button.pack(side="left", padx=5)

        self.save_button = ttk.Button(buttons_frame, text="Сохранить результаты", command=self.save_results, state='disabled')
        self.save_button.pack(side="left", padx=5)

        self.auto_select_button = ttk.Button(buttons_frame, text="Авто-выбор лучшего DNS", command=self.auto_select_dns, state='disabled')
        self.auto_select_button.pack(side="left", padx=5)

        # Прогрессбар
        self.progress = ttk.Progressbar(self.root, orient='horizontal', mode='determinate')
        self.progress.pack(fill="x", padx=10, pady=5)

        # Таблица результатов
        columns = ('DNS', 'IP', 'Location', 'Min Ping (ms)', 'Avg Ping (ms)', 'Max Ping (ms)', 'Packet Loss (%)', 'Jitter (ms)', 'Error')
        self.tree = ttk.Treeview(self.root, columns=columns, show='headings')
        for col in columns:
            self.tree.heading(col, text=col)
            if col in ['DNS', 'IP', 'Location']:
                self.tree.column(col, width=200, anchor='center')
            else:
                self.tree.column(col, width=100, anchor='center')
        self.tree.pack(fill="both", expand=True, padx=10, pady=5)

        # Кнопка для отображения графика
        self.plot_button = ttk.Button(self.root, text="Показать график", command=self.show_plot, state='disabled')
        self.plot_button.pack(pady=5)

        # Кнопка для отображения карты
        self.map_button = ttk.Button(self.root, text="Показать карту серверов", command=self.show_map, state='disabled')
        self.map_button.pack(pady=5)

    def add_server(self):
        """Позволяет пользователю добавить новый сервер."""
        name = simpledialog.askstring("Добавить сервер", "Введите название сервера:")
        if not name:
            return
        ip = simpledialog.askstring("Добавить сервер", "Введите IP-адрес сервера:")
        if not ip:
            return
        # Проверка валидности IP
        try:
            socket.inet_aton(ip)
        except socket.error:
            try:
                socket.inet_pton(socket.AF_INET6, ip)
            except socket.error:
                messagebox.showerror("Ошибка", "Введен некорректный IP-адрес.")
                return
        self.dns_servers[name] = ip
        messagebox.showinfo("Успех", f"Сервер '{name}' с IP {ip} добавлен.")

    def load_servers(self):
        """Загружает список серверов из CSV-файла."""
        file_path = filedialog.askopenfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")],
            title="Загрузить список серверов"
        )
        if file_path:
            try:
                with open(file_path, 'r', newline='', encoding='utf-8') as csvfile:
                    reader = csv.DictReader(csvfile)
                    for row in reader:
                        name = row.get('DNS')
                        ip = row.get('IP')
                        if name and ip:
                            self.dns_servers[name] = ip
                messagebox.showinfo("Загрузка", f"Серверы успешно загружены из '{file_path}'.")
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось загрузить файл:\n{e}")

    def save_servers(self):
        """Сохраняет список серверов в CSV-файл."""
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")],
            title="Сохранить список серверов"
        )
        if file_path:
            try:
                with open(file_path, 'w', newline='', encoding='utf-8') as csvfile:
                    fieldnames = ['DNS', 'IP']
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

                    writer.writeheader()
                    for name, ip in self.dns_servers.items():
                        writer.writerow({'DNS': name, 'IP': ip})
                messagebox.showinfo("Сохранение", f"Серверы успешно сохранены в '{file_path}'.")
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось сохранить файл:\n{e}")

    def start_ping(self):
        self.start_button.config(state='disabled')
        self.save_button.config(state='disabled')
        self.plot_button.config(state='disabled')
        self.map_button.config(state='disabled')
        self.auto_select_button.config(state='disabled')
        self.tree.delete(*self.tree.get_children())
        self.results = {}
        self.progress['value'] = 0
        self.total = len(self.dns_servers)
        self.current = 0

        # Проверка поддержки IPv6
        self.ipv6_supported = supports_ipv6()

        # Запуск пинга в отдельном потоке, чтобы не блокировать GUI
        threading.Thread(target=self.run_ping).start()

    def run_ping(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(self.ping_all())
        loop.close()
        self.root.after(0, self.on_ping_complete)

    async def ping_all(self):
        tasks = []
        for name, ip in self.dns_servers.items():
            is_ipv6 = is_ipv6_address(ip)
            if is_ipv6 and not self.ipv6_supported:
                continue
            tasks.append(asyncio.to_thread(self.ping_and_update, name, ip))
        await asyncio.gather(*tasks)

    def ping_and_update(self, name, ip):
        stats = ping_host(name, ip, count=self.ping_count.get(), timeout=self.ping_timeout.get())
        self.results[name] = stats
        self.current += 1
        self.root.after(0, self.update_progress)

    def update_progress(self):
        progress_percent = (self.current / self.total) * 100
        self.progress['value'] = progress_percent

    def on_ping_complete(self):
        self.populate_tree()
        self.start_button.config(state='normal')
        self.save_button.config(state='normal')
        self.plot_button.config(state='normal')
        self.map_button.config(state='normal')
        self.auto_select_button.config(state='normal')
        messagebox.showinfo("Завершено", "Пинг завершен!")

    def populate_tree(self):
        # Сортировка результатов по средней задержке
        sorted_results = sorted(
            self.results.values(),
            key=lambda x: float(x['Avg Ping (ms)']) if x['Avg Ping (ms)'] != 'N/A' else float('inf')
        )
        for stats in sorted_results:
            self.tree.insert('', tk.END, values=(
                stats['DNS'],
                stats['IP'],
                stats['Location'],
                stats['Min Ping (ms)'],
                stats['Avg Ping (ms)'],
                stats['Max Ping (ms)'],
                stats['Packet Loss (%)'],
                stats['Jitter (ms)'],
                stats['Error']
            ))
        if sorted_results:
            best_dns = sorted_results[0]
            message = (
                f"Лучший сервер: {best_dns['DNS']} ({best_dns['IP']})\n"
                f"Средний пинг: {best_dns['Avg Ping (ms)']} ms\n"
                f"Jitter: {best_dns['Jitter (ms)']} ms\n"
                f"Потери пакетов: {best_dns['Packet Loss (%)']}%"
            )
            messagebox.showinfo("Результаты", message)
        else:
            messagebox.showwarning("Результаты", "Не удалось получить результаты пинга для всех серверов.")

    def save_results(self):
        if not self.results:
            messagebox.showwarning("Сохранение", "Нет результатов для сохранения.")
            return
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")],
            title="Сохранить результаты"
        )
        if file_path:
            try:
                with open(file_path, 'w', newline='', encoding='utf-8') as csvfile:
                    fieldnames = ['DNS', 'IP', 'Location', 'Min Ping (ms)', 'Avg Ping (ms)', 'Max Ping (ms)', 'Packet Loss (%)', 'Jitter (ms)', 'Error', 'Traceroute']
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

                    writer.writeheader()
                    for stats in self.results.values():
                        writer.writerow({
                            'DNS': stats['DNS'],
                            'IP': stats['IP'],
                            'Location': stats['Location'],
                            'Min Ping (ms)': stats['Min Ping (ms)'],
                            'Avg Ping (ms)': stats['Avg Ping (ms)'],
                            'Max Ping (ms)': stats['Max Ping (ms)'],
                            'Packet Loss (%)': stats['Packet Loss (%)'],
                            'Jitter (ms)': stats['Jitter (ms)'],
                            'Error': stats['Error'],
                            'Traceroute': stats['Traceroute']
                        })
                messagebox.showinfo("Сохранение", f"Результаты успешно сохранены в '{file_path}'.")
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось сохранить файл:\n{e}")

    def show_plot(self):
        if not self.results:
            messagebox.showwarning("График", "Нет данных для отображения графика.")
            return

        # Создание нового окна для графика
        plot_window = tk.Toplevel(self.root)
        plot_window.title("График задержек")

        fig, ax = plt.subplots(figsize=(12, 8))

        names = []
        avg_pings = []
        jitters = []
        for name, stats in self.results.items():
            avg_ping = float(stats['Avg Ping (ms)']) if stats['Avg Ping (ms)'] != 'N/A' else 0
            jitter = float(stats['Jitter (ms)']) if stats['Jitter (ms)'] != 'N/A' else 0
            names.append(name)
            avg_pings.append(avg_ping)
            jitters.append(jitter)

        x = range(len(names))
        ax.bar(x, avg_pings, width=0.4, label='Средний Ping (ms)', align='center')
        ax.bar([i + 0.4 for i in x], jitters, width=0.4, label='Jitter (ms)', align='center')

        ax.set_xlabel('Серверы')
        ax.set_ylabel('Значения (ms)')
        ax.set_title('Средний Ping и Jitter по серверам')
        ax.set_xticks([i + 0.2 for i in x])
        ax.set_xticklabels(names, rotation=90)
        ax.legend()
        ax.grid(axis='y', linestyle='--', alpha=0.7)
        plt.tight_layout()

        canvas = FigureCanvasTkAgg(fig, master=plot_window)
        canvas.draw()
        canvas.get_tk_widget().pack(fill='both', expand=True)

    def show_map(self):
        if not self.results:
            messagebox.showwarning("Карта", "Нет данных для отображения карты.")
            return

        # Создание карты
        map_center = [20, 0]  # Центр карты
        m = folium.Map(location=map_center, zoom_start=2)

        for stats in self.results.values():
            try:
                # Использование геолокации
                if "Unknown" in stats['Location'] or "Failed" in stats['Location']:
                    continue
                # Извлечение координат из строки геолокации
                parts = stats['Location'].split("Lat:")
                if len(parts) < 2:
                    continue
                lat_lon = parts[1].split("),")
                if len(lat_lon) < 1:
                    continue
                lat = float(lat_lon[0].strip())
                lon = float(lat_lon[1].replace("Lon:", "").strip().rstrip(')'))
                folium.Marker(
                    [lat, lon],
                    popup=f"{stats['DNS']} ({stats['IP']})\nPing: {stats['Avg Ping (ms)']} ms",
                    tooltip=stats['DNS']
                ).add_to(m)
            except Exception:
                continue

        # Добавление плагина для кластеризации маркеров
        plugins.MarkerCluster().add_to(m)

        # Сохранение карты во временный HTML-файл
        map_file = "server_map.html"
        m.save(map_file)

        # Отображение карты в веб-браузере
        webbrowser.open(map_file)

    def auto_select_dns(self):
        if not self.results:
            messagebox.showwarning("Авто-выбор", "Нет результатов для анализа.")
            return

        # Найти сервер с минимальным средним ping и минимальным jitter
        best_dns = None
        min_ping = float('inf')
        min_jitter = float('inf')

        for stats in self.results.values():
            if stats['Avg Ping (ms)'] != 'N/A' and stats['Jitter (ms)'] != 'N/A':
                avg_ping = float(stats['Avg Ping (ms)'])
                jitter = float(stats['Jitter (ms)'])
                if avg_ping < min_ping or (avg_ping == min_ping and jitter < min_jitter):
                    min_ping = avg_ping
                    min_jitter = jitter
                    best_dns = stats

        if best_dns:
            confirm = messagebox.askyesno("Авто-выбор",
                                          f"Лучший сервер: {best_dns['DNS']} ({best_dns['IP']})\n"
                                          f"Средний пинг: {best_dns['Avg Ping (ms)']} ms\n"
                                          f"Jitter: {best_dns['Jitter (ms)']} ms\n"
                                          f"Потери пакетов: {best_dns['Packet Loss (%)']}%\n\n"
                                          f"Хотите использовать этот DNS-сервер?")
            if confirm:
                self.set_system_dns(best_dns['IP'])
        else:
            messagebox.showwarning("Авто-выбор", "Не удалось определить лучший сервер.")

    def set_system_dns(self, dns_ip):
        try:
            system = platform.system()
            if system == "Windows":
                # Получение имени сетевого подключения
                output = subprocess.check_output("netsh interface show interface", shell=True).decode()
                lines = output.splitlines()
                connection_name = None
                for line in lines:
                    if "Connected" in line:
                        parts = line.split()
                        # Имя подключения может содержать пробелы
                        connection_name = ' '.join(parts[3:])
                        break
                if not connection_name:
                    messagebox.showerror("Ошибка", "Не удалось определить активное сетевое подключение.")
                    return

                # Установка DNS
                cmd = f"netsh interface ip set dns name=\"{connection_name}\" static {dns_ip}"
                subprocess.check_call(cmd, shell=True)
                messagebox.showinfo("Успех", f"Системный DNS успешно изменен на {dns_ip}.")
            elif system == "Linux":
                # Реализация для Linux (пример для систем с NetworkManager)
                # Требует прав администратора
                messagebox.showinfo("Информация", "Автоматическое изменение DNS для Linux требует настройки вручную.")
            elif system == "Darwin":
                # Реализация для macOS
                # Требует прав администратора
                # Пример для Wi-Fi интерфейса
                cmd = f"networksetup -setdnsservers Wi-Fi {dns_ip}"
                subprocess.check_call(cmd, shell=True)
                messagebox.showinfo("Успех", f"Системный DNS успешно изменен на {dns_ip}.")
            else:
                messagebox.showerror("Ошибка", f"Неподдерживаемая ОС: {system}")
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Ошибка", f"Не удалось изменить DNS:\n{e}")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Произошла ошибка:\n{e}")

def main():
    root = tk.Tk()
    app = PingApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
