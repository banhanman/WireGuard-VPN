### Описание для GitHub (README.md)

```markdown
# 🤖 WireGuard VPN Manager Bot

Telegram-бот для управления WireGuard VPN с расширенными функциями. Бот позволяет создавать, распределять и управлять VPN-конфигурациями через Telegram.

## 🌟 Особенности
- **Приватный доступ** по ID Telegram
- **Автоматическая генерация** конфигов WireGuard
- **Управление конфигурациями**: 
  - Создание/удаление конфигов
  - Переименование конфигураций
  - Включение/отключение доступа
  - Ограничение скорости
- **Автоматическая интеграция** с сервером WireGuard
- **Безопасная выгрузка** конфигурационных файлов
- **Интуитивный интерфейс** с интерактивными кнопками

## 🛠 Технологии
- Python 3.8+
- python-telegram-bot 13.x
- SQLite3 для хранения данных
- WireGuard для VPN
- Systemd для управления сервисом

## ⚙️ Установка

### Предварительные требования
- Сервер с Ubuntu 20.04+
- Установленный и настроенный WireGuard
- Python 3.8+

1. **Установите зависимости**:
```bash
sudo apt update
sudo apt install python3-pip python3-venv
```

2. **Создайте виртуальное окружение**:
```bash
python3 -m venv wgbot-env
source wgbot-env/bin/activate
```

3. **Установите Python-зависимости**:
```bash
pip install python-telegram-bot
```

4. **Настройте бота**:
```bash
git clone https://github.com/banhanman/WireGuard-VPN
cd wireguard-bot
cp config.example.py config.py
nano config.py  # Отредактируйте параметры
```

5. **Настройте WireGuard**:
```bash
sudo nano /etc/wireguard/wg0.conf
```
Добавьте в конец файла:
```ini
[Peer]
# Этот раздел будет автоматически заполняться ботом
```

6. **Создайте systemd-сервис**:
```bash
sudo nano /etc/systemd/system/wireguard-bot.service
```
```ini
[Unit]
Description=WireGuard Telegram Bot
After=network.target

[Service]
User=root
WorkingDirectory=/path/to/wireguard-bot
ExecStart=/path/to/wireguard-bot/wgbot-env/bin/python /path/to/wireguard-bot/bot.py
Restart=always
Environment="PYTHONUNBUFFERED=1"

[Install]
WantedBy=multi-user.target
```

7. **Запустите бота**:
```bash
sudo systemctl daemon-reload
sudo systemctl start wireguard-bot
sudo systemctl enable wireguard-bot
```

## 🖥 Использование
1. Начните с команды `/start`
2. Используйте интерактивные кнопки:
   - **Создать конфиг**: Генерация новой VPN-конфигурации
   - **Мои конфиги**: Просмотр и управление существующими конфигурациями
   - **Скачать**: Получить файл .conf для подключения
   - **Переименовать**: Изменить имя конфигурации
   - **Включить/Отключить**: Управление доступом
   - **Ограничить скорость**: Установить лимит скорости

## 🔒 Безопасность
- Доступ только для авторизованных пользователей
- Конфигурации хранятся в зашифрованном виде
- Автоматическое обновление конфигов сервера
- Изоляция процессов

## 📈 Расширенные функции
1. **Ограничение скорости**:
   - Реализовано через `tc` (traffic control)
   - Автоматическое применение при создании/изменении
2. **Статистика использования**:
   - Просмотр трафика по конфигурациям
   - История подключений
3. **Мультисерверная поддержка**:
   - Управление несколькими VPN-серверами
   - Балансировка нагрузки

## ⚠️ Важные замечания
1. Бот должен запускаться с правами root для управления WireGuard
2. Сервер WireGuard должен быть предварительно настроен
3. Регулярно делайте бэкап базы данных
4. Используйте firewall для ограничения доступа к серверу
