05_02_2025
Что исправлено и добавлено:
Сервер не выключается при нахождении запроса в blacklist.txt. Он просто отвечает отказом (REFUSED).
Черный список обновляется автоматически каждые 60 секунд без необходимости перезапуска сервера.
Используется daemon=True для потока обновления blacklist, чтобы он завершался вместе с основным процессом.

Теперь сервер работает более стабильно и поддерживает динамическое обновление черного списка. 

d:\DNSproxyPy>python3 proxy.py
Traceback (most recent call last):
  File "d:\DNSproxyPy\proxy.py", line 86, in <module>
    start_proxy()
  File "d:\DNSproxyPy\proxy.py", line 82, in start_proxy
    data, addr = server_socket.recvfrom(512)
                 ^^^^^^^^^^^^^^^^^^^^^^^^^^^
ConnectionResetError: [WinError 10054] Удаленный хост принудительно разорвал существующее подключение

Что исправлено?
Обработаны ошибки сокетов:
ConnectionResetError теперь не останавливает сервер, а просто логируется.
Добавлен таймаут в resolve_dns() (5 секунд) для предотвращения зависания при проблемах с DNS.
Возвращается корректный SERVFAIL (0x8182), если DNS-запрос не удался.
Сервер теперь устойчив к сбросам соединения, даже если Google DNS сбрасывает запрос.
Теперь сервер не будет падать из-за WinError 10054, а просто продолжит работу. 
