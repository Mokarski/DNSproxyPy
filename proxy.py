import socket
import struct
import threading
import time

CACHE = {}
CACHE_TTL = 300  # Время жизни кэша в секундах
DNS_SERVER = "8.8.8.8"  # Используем Google DNS
DNS_PORT = 53
LOG_FILE = "dns_proxy.log"
BLACKLIST_FILE = "blacklist.txt"
BLACKLIST = set()
BLACKLIST_UPDATE_INTERVAL = 60  # Интервал обновления blacklist в секундах

def log_message(message):
    with open(LOG_FILE, "a") as log_file:
        log_file.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}\n")

def load_blacklist():
    """Загружает список заблокированных доменов."""
    global BLACKLIST
    try:
        with open(BLACKLIST_FILE, "r") as f:
            BLACKLIST = set(line.strip().lower() for line in f if line.strip())
        log_message("Blacklist updated.")
    except FileNotFoundError:
        BLACKLIST = set()

def update_blacklist_periodically():
    """Обновляет черный список каждые BLACKLIST_UPDATE_INTERVAL секунд."""
    while True:
        load_blacklist()
        time.sleep(BLACKLIST_UPDATE_INTERVAL)

def resolve_dns(request):
    """Отправляет запрос на реальный DNS-сервер и возвращает ответ с обработкой ошибок"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(5)  # Таймаут 5 секунд
            sock.sendto(request, (DNS_SERVER, DNS_PORT))
            response, _ = sock.recvfrom(512)  # Максимальный размер DNS-ответа
        return response
    except (socket.timeout, ConnectionResetError) as e:
        log_message(f"DNS resolution error: {e}")
        return None  # Возвращаем None в случае ошибки

def handle_client(data, addr, server_socket):
    """Обрабатывает входящий DNS-запрос"""
    transaction_id = data[:2]
    domain_name = extract_domain_name(data[12:])
    
    if domain_name in BLACKLIST:
        log_message(f"Blocked request: {domain_name}")
        response = transaction_id + b'\x81\x83' + b'\x00' * (512 - 4)  # Код ошибки REFUSED
    elif domain_name in CACHE and time.time() - CACHE[domain_name]['timestamp'] < CACHE_TTL:
        log_message(f"Cache hit: {domain_name}")
        response = transaction_id + CACHE[domain_name]['response'][2:]
    else:
        log_message(f"Resolving: {domain_name}")
        response = resolve_dns(data)
        if response:
            CACHE[domain_name] = {'response': response, 'timestamp': time.time()}
        else:
            response = transaction_id + b'\x81\x82' + b'\x00' * (512 - 4)  # Код ошибки SERVFAIL
    
    server_socket.sendto(response, addr)

def extract_domain_name(query):
    """Извлекает доменное имя из DNS-запроса"""
    domain_parts = []
    i = 0
    while query[i] != 0:
        length = query[i]
        domain_parts.append(query[i + 1:i + 1 + length].decode("utf-8"))
        i += length + 1
    return ".".join(domain_parts).lower()

def start_proxy():
    """Запускает DNS-прокси сервер"""
    load_blacklist()
    
    # Запуск потока обновления черного списка
    threading.Thread(target=update_blacklist_periodically, daemon=True).start()
    
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server_socket:
        server_socket.bind(("0.0.0.0", 53))
        log_message("DNS Proxy Server started on port 53")
        
        while True:
            try:
                data, addr = server_socket.recvfrom(512)
                threading.Thread(target=handle_client, args=(data, addr, server_socket)).start()
            except ConnectionResetError as e:
                log_message(f"Connection error: {e}")
                continue  # Игнорируем ошибку и продолжаем работать

if __name__ == "__main__":
    start_proxy()
