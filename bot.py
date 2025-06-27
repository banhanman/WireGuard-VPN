import os
import logging
import sqlite3
import subprocess
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Updater, CommandHandler, CallbackQueryHandler, CallbackContext, 
    MessageHandler, Filters
)
from uuid import uuid4
from config import TOKEN, ADMIN_IDS, WG_DIR, WG_SERVER_IP, WG_SERVER_PORT

# Настройка логирования
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Проверка директории для конфигов
os.makedirs(WG_DIR, exist_ok=True)

# Инициализация БД
def init_db():
    conn = sqlite3.connect('wireguard_bot.db')
    cursor = conn.cursor()
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        telegram_id INTEGER UNIQUE,
        username TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS configs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        config_name TEXT DEFAULT 'default',
        config_path TEXT UNIQUE,
        private_key TEXT,
        public_key TEXT,
        ip_address TEXT,
        enabled BOOLEAN DEFAULT 1,
        speed_limit INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    ''')
    
    conn.commit()
    conn.close()

init_db()

# Генерация ключей WireGuard
def generate_keys():
    private_key = subprocess.check_output("wg genkey", shell=True).decode('utf-8').strip()
    public_key = subprocess.check_output(f"echo '{private_key}' | wg pubkey", shell=True).decode('utf-8').strip()
    return private_key, public_key

# Создание конфигурации
def create_config(user_id, config_name="default"):
    # Проверяем существование пользователя
    conn = sqlite3.connect('wireguard_bot.db')
    cursor = conn.cursor()
    
    # Регистрируем пользователя, если не существует
    cursor.execute("INSERT OR IGNORE INTO users (telegram_id) VALUES (?)", (user_id,))
    conn.commit()
    
    # Генерируем ключи
    private_key, public_key = generate_keys()
    
    # Генерируем уникальный IP (простая реализация)
    cursor.execute("SELECT MAX(ip_address) FROM configs")
    last_ip = cursor.fetchone()[0]
    ip_address = "10.0.0.2" if not last_ip else f"10.0.0.{int(last_ip.split('.')[-1]) + 1}"
    
    # Создаем файл конфигурации
    config_id = str(uuid4())
    config_path = os.path.join(WG_DIR, f"{config_id}.conf")
    
    config_content = f"""[Interface]
PrivateKey = {private_key}
Address = {ip_address}/24
DNS = 8.8.8.8

[Peer]
PublicKey = SERVER_PUBLIC_KEY
AllowedIPs = 0.0.0.0/0
Endpoint = {WG_SERVER_IP}:{WG_SERVER_PORT}
PersistentKeepalive = 25
"""
    with open(config_path, 'w') as f:
        f.write(config_content)
    
    # Добавляем в базу данных
    cursor.execute(
        "INSERT INTO configs (user_id, config_name, config_path, private_key, public_key, ip_address) "
        "VALUES ((SELECT id FROM users WHERE telegram_id = ?), ?, ?, ?, ?, ?)",
        (user_id, config_name, config_path, private_key, public_key, ip_address)
    )
    conn.commit()
    conn.close()
    
    # Добавляем пир на сервере (требует прав root)
    os.system(f"wg set wg0 peer {public_key} allowed-ips {ip_address}/32")
    
    return config_path

# Обновление конфигурации сервера
def update_server_config():
    os.system("wg-quick save wg0 > /etc/wireguard/wg0.conf")

# Команда /start
def start(update: Update, context: CallbackContext) -> None:
    user_id = update.effective_user.id
    
    if user_id not in ADMIN_IDS:
        update.message.reply_text("❌ Доступ запрещен. Ваш ID не в списке разрешенных.")
        return
    
    keyboard = [
        [InlineKeyboardButton("➕ Создать конфиг", callback_data='create_config')],
        [InlineKeyboardButton("📋 Мои конфиги", callback_data='list_configs')],
        [InlineKeyboardButton("⚙️ Настройки сервера", callback_data='server_settings')]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    update.message.reply_text(
        "🔐 Добро пожаловать в WireGuard VPN Manager!\n\n"
        "Выберите действие:",
        reply_markup=reply_markup
    )

# Обработчик кнопок
def button_handler(update: Update, context: CallbackContext) -> None:
    query = update.callback_query
    query.answer()
    user_id = query.from_user.id
    
    if user_id not in ADMIN_IDS:
        query.edit_message_text("❌ Доступ запрещен")
        return
    
    data = query.data
    
    if data == 'create_config':
        context.user_data['action'] = 'create_config'
        query.edit_message_text("Введите имя для новой конфигурации:")
    
    elif data == 'list_configs':
        conn = sqlite3.connect('wireguard_bot.db')
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, config_name, enabled FROM configs "
            "WHERE user_id = (SELECT id FROM users WHERE telegram_id = ?)",
            (user_id,)
        )
        configs = cursor.fetchall()
        conn.close()
        
        if not configs:
            query.edit_message_text("У вас пока нет конфигураций.")
            return
        
        keyboard = []
        for config_id, name, enabled in configs:
            status = "🟢" if enabled else "🔴"
            keyboard.append(
                [InlineKeyboardButton(f"{status} {name}", callback_data=f"config_{config_id}")]
            )
        
        keyboard.append([InlineKeyboardButton("🔙 Назад", callback_data='back_to_main')])
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        query.edit_message_text("📋 Ваши конфигурации:", reply_markup=reply_markup)
    
    elif data.startswith('config_'):
        config_id = data.split('_')[1]
        context.user_data['selected_config'] = config_id
        
        conn = sqlite3.connect('wireguard_bot.db')
        cursor = conn.cursor()
        cursor.execute(
            "SELECT config_name, enabled, speed_limit, ip_address FROM configs WHERE id = ?",
            (config_id,)
        )
        config_data = cursor.fetchone()
        conn.close()
        
        if not config_data:
            query.edit_message_text("Конфигурация не найдена.")
            return
        
        name, enabled, speed_limit, ip = config_data
        status = "активна" if enabled else "отключена"
        
        keyboard = [
            [InlineKeyboardButton("📥 Скачать конфиг", callback_data=f'download_{config_id}')],
            [InlineKeyboardButton("✏️ Переименовать", callback_data=f'rename_{config_id}')],
            [InlineKeyboardButton("🚫 Удалить", callback_data=f'delete_{config_id}')],
            [InlineKeyboardButton("🔌 Включить" if not enabled else "🔴 Отключить", 
             callback_data=f'toggle_{config_id}')],
            [InlineKeyboardButton("⏱ Ограничить скорость", callback_data=f'limit_{config_id}')],
            [InlineKeyboardButton("🔙 Назад", callback_data='list_configs')]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        query.edit_message_text(
            f"⚙️ Конфигурация: {name}\n"
            f"Статус: {status}\n"
            f"IP: {ip}\n"
            f"Ограничение скорости: {speed_limit} Mbps\n\n"
            "Выберите действие:",
            reply_markup=reply_markup
        )
    
    elif data.startswith('download_'):
        config_id = data.split('_')[1]
        conn = sqlite3.connect('wireguard_bot.db')
        cursor = conn.cursor()
        cursor.execute("SELECT config_path FROM configs WHERE id = ?", (config_id,))
        config_path = cursor.fetchone()[0]
        conn.close()
        
        if os.path.exists(config_path):
            with open(config_path, 'rb') as f:
                context.bot.send_document(
                    chat_id=query.message.chat_id,
                    document=f,
                    filename=os.path.basename(config_path),
                    caption="Ваш конфигурационный файл"
                )
        else:
            query.edit_message_text("❌ Файл конфигурации не найден")
    
    elif data.startswith('toggle_'):
        config_id = data.split('_')[1]
        conn = sqlite3.connect('wireguard_bot.db')
        cursor = conn.cursor()
        
        # Получаем текущий статус
        cursor.execute("SELECT enabled, public_key FROM configs WHERE id = ?", (config_id,))
        enabled, public_key = cursor.fetchone()
        new_status = not enabled
        
        # Обновляем статус в БД
        cursor.execute("UPDATE configs SET enabled = ? WHERE id = ?", (new_status, config_id))
        conn.commit()
        conn.close()
        
        # Обновляем на сервере
        if new_status:
            os.system(f"wg set wg0 peer {public_key} allowed-ips 0.0.0.0/0")
        else:
            os.system(f"wg set wg0 peer {public_key} remove")
        
        update_server_config()
        query.edit_message_text(f"✅ Статус изменен: {'активна' if new_status else 'отключена'}")
    
    elif data == 'back_to_main':
        start(update, context)

# Обработчик текстовых сообщений
def text_handler(update: Update, context: CallbackContext) -> None:
    user_id = update.effective_user.id
    text = update.message.text
    
    if 'action' not in context.user_data:
        update.message.reply_text("Пожалуйста, используйте кнопки для управления.")
        return
    
    action = context.user_data['action']
    
    if action == 'create_config':
        config_name = text.strip()
        if not config_name:
            update.message.reply_text("Некорректное имя конфигурации.")
            return
        
        try:
            config_path = create_config(user_id, config_name)
            with open(config_path, 'rb') as f:
                update.message.reply_document(
                    document=f,
                    caption=f"✅ Конфигурация '{config_name}' создана!"
                )
        except Exception as e:
            logger.error(f"Ошибка создания конфига: {e}")
            update.message.reply_text("❌ Ошибка при создании конфигурации.")
        
        del context.user_data['action']
    
    elif action == 'rename_config':
        if 'selected_config' not in context.user_data:
            update.message.reply_text("Ошибка: конфигурация не выбрана.")
            return
        
        config_id = context.user_data['selected_config']
        new_name = text.strip()
        
        if not new_name:
            update.message.reply_text("Некорректное имя.")
            return
        
        conn = sqlite3.connect('wireguard_bot.db')
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE configs SET config_name = ? WHERE id = ?",
            (new_name, config_id)
        conn.commit()
        conn.close()
        
        update.message.reply_text(f"✅ Конфигурация переименована в '{new_name}'")
        del context.user_data['action']
        del context.user_data['selected_config']

# Обработчик для ограничения скорости
def speed_limit_handler(update: Update, context: CallbackContext) -> None:
    query = update.callback_query
    query.answer()
    
    if 'selected_config' not in context.user_data:
        query.edit_message_text("Ошибка: конфигурация не выбрана.")
        return
    
    config_id = context.user_data['selected_config']
    context.user_data['action'] = 'set_speed_limit'
    
    query.edit_message_text("Введите ограничение скорости в Mbps (0 = без ограничений):")

def main() -> None:
    updater = Updater(TOKEN)
    dispatcher = updater.dispatcher

    # Обработчики команд
    dispatcher.add_handler(CommandHandler("start", start))
    dispatcher.add_handler(CallbackQueryHandler(button_handler))
    dispatcher.add_handler(MessageHandler(Filters.text & ~Filters.command, text_handler))

    # Запуск бота
    updater.start_polling()
    updater.idle()

if __name__ == '__main__':
    main()
