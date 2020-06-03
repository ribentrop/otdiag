# otdiag
## Добавление результата выпонения команды в диаг

На примере networkConfig()

## Добавление файлов в диаг

Добавлять можно на примере:
```
    # === TEMPLATE FOR ADDING FILE TO DIAG ===

    file_to_add = "/opt/file_to_add"
    filename_in_diag = "added_file"
    try:
        add_file_to_diag(file_to_add, filename_in_diag)
        print(file_to_add, filename_in_diag)
    finally:
        os.unlink(file_to_add)
    # ==================================================
    ```
    Где:
    file_to_add - файл для добвавления (имеющийся в платформе или специально созданный)
    filename_in_diag - file_to_add будет переименован в filename_in_diag после добавления 
