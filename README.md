# otdiag

1. В код включены все функии оригинала. 
2. Все неиспользующиеся функции закомментированы. По возможности, ко всем даны русскоязычные комментарии.
3. Фрагменты кода, где искать пример добавления результата выполнения команды из консоли во временный файл. Временный файл потом добавляется в диаг:
```
# Сбор конфигурации сети.
def networkConfig():
...
...
    # Файл, в который будет собираться системная информация
    sysinfo_filename = None
    ...
    ...
    # Добавляем system_info в диаг
    try:
        add_file_to_diag(sysinfo_filename, SYSINFO_FILE)
        print(sysinfo_filename, SYSINFO_FILE)
    finally:
        os.unlink(sysinfo_filename)
...
```

4. Фрагменты кода, где искать пример добавления файла  в диаг:
```
# Добавление файла в диаг
def add_file_to_diag(file_path, diag_path, add_diag_name=True):
```
5. Фрагменты кода, где искать пример добавления строки  в диаг:
```
# Добавление строки в diag
def add_string_to_diag(content, diag_path):
```
6. Запуск:
Просто без опций:
```
[root@otsupport-spark1 otpdiag]#/opt/splunk/bin/python3 cmd python /opt/splunk/lib/python3.7/site-packages/splunk/clilib/otpdiag/otpdiag.py --help
```
Исключить сбор конфигов:
```
[root@otsupport-spark1 otpdiag]#/opt/splunk/bin/python3 cmd python /opt/splunk/lib/python3.7/site-packages/splunk/clilib/otpdiag/otpdiag.py --disable=configs
```
Получить хелп:
```
[root@otsupport-spark1 otpdiag]#/opt/splunk/bin/python3 cmd python /opt/splunk/lib/python3.7/site-packages/splunk/clilib/otpdiag/otpdiag.py --help
```

