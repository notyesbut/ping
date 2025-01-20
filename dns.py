import csv
import socket
import asyncio
import threading
from ping3 import ping
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from ping3.errors import PingError


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
        # Попытка создать IPv6-сокет и подключиться к известному адресу
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect(("google.com", 80))
        sock.close()
        return True
    except OSError:
        return False

def ping_host(name, ip, count=10, timeout=2):
    """
    Пингует хост несколько раз и собирает статистику.

    :param name: Название сервера.
    :param ip: IP-адрес сервера.
    :param count: Количество попыток пинга.
    :param timeout: Таймаут для каждого пинга в секундах.
    :return: Словарь со статистикой пинга.
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

    return {
        'DNS': name,
        'IP': ip,
        'Min Ping (ms)': f"{min_time:.2f}" if min_time is not None else 'N/A',
        'Avg Ping (ms)': f"{avg_time:.2f}" if avg_time is not None else 'N/A',
        'Max Ping (ms)': f"{max_time:.2f}" if max_time is not None else 'N/A',
        'Packet Loss (%)': f"{packet_loss_percent:.2f}",
        'Jitter (ms)': f"{avg_jitter:.2f}" if avg_jitter is not None else 'N/A',
        'Error': 'None' if received_pings > 0 else 'All pings failed.'
    }

class PingApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Game Server Ping Tool")
        self.root.geometry("1200x800")

        # Параметры пинга
        self.ping_count = tk.IntVar(value=10)
        self.ping_timeout = tk.IntVar(value=2)

        # Создание интерфейса
        self.create_widgets()

        # Список серверов (предустановленные и пользовательские)
        self.dns_servers = {
            "Google": "8.8.8.8",
            "Google (2)": "8.8.4.4",
            "Cloudflare": "1.1.1.1",
            "Cloudflare (2)": "1.0.0.1",
            "Quad9": "9.9.9.9",
            "Quad9 (2)": "149.112.112.112",
            "OpenDNS": "208.67.222.222",
            "OpenDNS (2)": "208.67.220.220",
            "Yandex": "77.88.8.8",
            "Yandex (2)": "77.88.8.1",
            # Добавьте другие сервера или игровые серверы здесь
        }

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

        # Прогрессбар
        self.progress = ttk.Progressbar(self.root, orient='horizontal', mode='determinate')
        self.progress.pack(fill="x", padx=10, pady=5)

        # Таблица результатов
        columns = ('DNS', 'IP', 'Min Ping (ms)', 'Avg Ping (ms)', 'Max Ping (ms)', 'Packet Loss (%)', 'Jitter (ms)', 'Error')
        self.tree = ttk.Treeview(self.root, columns=columns, show='headings')
        for col in columns:
            self.tree.heading(col, text=col)
            if col == 'DNS' or col == 'IP':
                self.tree.column(col, width=150, anchor='center')
            else:
                self.tree.column(col, width=100, anchor='center')
        self.tree.pack(fill="both", expand=True, padx=10, pady=5)

        # Кнопка для отображения графика
        self.plot_button = ttk.Button(self.root, text="Показать график", command=self.show_plot, state='disabled')
        self.plot_button.pack(pady=5)

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
                messagebox.showinfo("Загрузка", f"Сервера успешно загружены из '{file_path}'.")
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
                messagebox.showinfo("Сохранение", f"Сервера успешно сохранены в '{file_path}'.")
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось сохранить файл:\n{e}")

    def start_ping(self):
        self.start_button.config(state='disabled')
        self.save_button.config(state='disabled')
        self.plot_button.config(state='disabled')
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
                    fieldnames = ['DNS', 'IP', 'Min Ping (ms)', 'Avg Ping (ms)', 'Max Ping (ms)', 'Packet Loss (%)', 'Jitter (ms)', 'Error']
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

                    writer.writeheader()
                    for stats in self.results.values():
                        writer.writerow(stats)
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

        fig, ax = plt.subplots(figsize=(10, 6))

        names = []
        avg_pings = []
        for name, stats in self.results.items():
            avg_ping = float(stats['Avg Ping (ms)']) if stats['Avg Ping (ms)'] != 'N/A' else 0
            names.append(name)
            avg_pings.append(avg_ping)

        ax.bar(names, avg_pings, color='skyblue')
        ax.set_xlabel('Серверы')
        ax.set_ylabel('Средний Ping (ms)')
        ax.set_title('Средний Ping по серверам')
        ax.tick_params(axis='x', rotation=90)
        ax.grid(axis='y', linestyle='--', alpha=0.7)
        plt.tight_layout()

        canvas = FigureCanvasTkAgg(fig, master=plot_window)
        canvas.draw()
        canvas.get_tk_widget().pack(fill='both', expand=True)

    def load_servers_from_file(self, filepath):
        """Загружает список серверов из CSV-файла."""
        try:
            with open(filepath, 'r', newline='', encoding='utf-8') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    name = row.get('DNS')
                    ip = row.get('IP')
                    if name and ip:
                        self.dns_servers[name] = ip
            messagebox.showinfo("Загрузка", f"Сервера загружены из '{filepath}'.")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось загрузить файл:\n{e}")

    def save_servers_to_file(self, filepath):
        """Сохраняет список серверов в CSV-файл."""
        try:
            with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = ['DNS', 'IP']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

                writer.writeheader()
                for name, ip in self.dns_servers.items():
                    writer.writerow({'DNS': name, 'IP': ip})
            messagebox.showinfo("Сохранение", f"Сервера сохранены в '{filepath}'.")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось сохранить файл:\n{e}")

def main():
    root = tk.Tk()
    app = PingApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
