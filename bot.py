import asyncio
import json
import logging
import sqlite3
import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass
from enum import Enum

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, MessageHandler, CallbackQueryHandler, filters, ContextTypes
from telegram.constants import ParseMode

class SecurityLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class SecurityEvent:
    timestamp: datetime.datetime
    user_id: int
    user_name: str
    event_type: str
    description: str
    level: SecurityLevel
    chat_id: Optional[int] = None
    message_id: Optional[int] = None

class XillenSecurityBot:
    def __init__(self):
        self.config = self.load_config()
        self.security_events: List[SecurityEvent] = []
        self.suspicious_users: Dict[int, Dict] = {}
        self.db = Database()
        self.logger = self.setup_logging()
        
        self.application = Application.builder().token(self.config["token"]).build()
        self.setup_handlers()
        
    def load_config(self) -> dict:
        try:
            with open('config.json', 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            config = {
                "token": "YOUR_BOT_TOKEN_HERE",
                "owner_id": 123456789,
                "log_chat_id": None,
                "security_level": "medium",
                "auto_moderation": True,
                "suspicious_threshold": 3,
                "welcome_message": True,
                "blocked_words": ["hack", "cheat", "exploit", "crack", "bypass", "ddos", "bot", "script", "auto", "macro"],
                "spam_threshold": 5,
                "spam_timeout": 10
            }
            with open('config.json', 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
            return config
    
    def setup_logging(self) -> logging.Logger:
        logger = logging.getLogger('XillenSecurityBot')
        logger.setLevel(logging.INFO)
        
        handler = logging.FileHandler('xillen_telegram_security.log', encoding='utf-8')
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        return logger
    
    def setup_handlers(self):
        self.application.add_handler(CommandHandler("start", self.start_command))
        self.application.add_handler(CommandHandler("help", self.help_command))
        self.application.add_handler(CommandHandler("security", self.security_command))
        self.application.add_handler(CommandHandler("scan", self.scan_command))
        self.application.add_handler(CommandHandler("warn", self.warn_command))
        self.application.add_handler(CommandHandler("ban", self.ban_command))
        self.application.add_handler(CommandHandler("unban", self.unban_command))
        self.application.add_handler(CommandHandler("logs", self.logs_command))
        self.application.add_handler(CommandHandler("stats", self.stats_command))
        self.application.add_handler(CommandHandler("reload", self.reload_command))
        
        self.application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, self.handle_message))
        self.application.add_handler(MessageHandler(filters.ALL, self.handle_all_messages))
        
        self.application.add_handler(CallbackQueryHandler(self.handle_callback))
    
    async def start_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        user = update.effective_user
        chat = update.effective_chat
        
        if chat.type == "private":
            await self.send_private_welcome(update, context)
        else:
            await self.send_group_welcome(update, context)
        
        await self.log_security_event(
            SecurityEvent(
                timestamp=datetime.datetime.now(),
                user_id=user.id,
                user_name=user.first_name,
                event_type="START_COMMAND",
                description=f"User started bot in {chat.type}",
                level=SecurityLevel.LOW,
                chat_id=chat.id
            )
        )
    
    async def send_private_welcome(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        welcome_text = (
            "╔══════════════════════════════════════════════════════════════╗\n"
            "║                    XILLEN Security Bot                      ║\n"
            "║                        v2.0 by @Bengamin_Button            ║\n"
            "╚══════════════════════════════════════════════════════════════╝\n\n"
            "🛡️ Добро пожаловать в бота безопасности XILLEN!\n\n"
            "Доступные команды:\n"
            "• /help - показать справку\n"
            "• /security - статус безопасности\n"
            "• /scan @user - просканировать пользователя\n"
            "• /logs - показать логи\n"
            "• /stats - статистика\n\n"
            "Бот автоматически отслеживает безопасность чата и уведомляет о подозрительной активности."
        )
        
        await update.message.reply_text(welcome_text, parse_mode=ParseMode.HTML)
    
    async def send_group_welcome(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        welcome_text = (
            "🛡️ XILLEN Security Bot активирован!\n\n"
            "Бот будет автоматически отслеживать безопасность чата.\n"
            "Используйте /security для проверки статуса."
        )
        
        await update.message.reply_text(welcome_text)
    
    async def help_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        help_text = (
            "📚 <b>Справка по командам XILLEN Security Bot</b>\n\n"
            "<b>Основные команды:</b>\n"
            "• /start - запуск бота\n"
            "• /help - эта справка\n"
            "• /security - статус безопасности\n\n"
            "<b>Модерация:</b>\n"
            "• /scan @user - просканировать пользователя\n"
            "• /warn @user [причина] - предупреждение\n"
            "• /ban @user [причина] - забанить\n"
            "• /unban @user - разбанить\n\n"
            "<b>Мониторинг:</b>\n"
            "• /logs [тип] [лимит] - логи безопасности\n"
            "• /stats - статистика\n\n"
            "<b>Администрирование:</b>\n"
            "• /reload - перезагрузить конфигурацию\n\n"
            "<b>Автоматические функции:</b>\n"
            "• Детекция подозрительного контента\n"
            "• Анти-спам защита\n"
            "• Мониторинг новых пользователей\n"
            "• Логирование всех событий"
        )
        
        await update.message.reply_text(help_text, parse_mode=ParseMode.HTML)
    
    async def security_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not await self.check_permissions(update, context):
            return
        
        chat = update.effective_chat
        total_events = len(self.security_events)
        suspicious_users = len(self.suspicious_users)
        
        security_text = (
            f"🛡️ <b>Статус безопасности чата</b>\n\n"
            f"📊 <b>Общая статистика:</b>\n"
            f"• Всего событий: {total_events}\n"
            f"• Подозрительных пользователей: {suspicious_users}\n"
            f"• Уровень безопасности: {self.config.get('security_level', 'medium')}\n\n"
            f"⚙️ <b>Настройки:</b>\n"
            f"• Автомодерация: {'✅ Включена' if self.config.get('auto_moderation', True) else '❌ Выключена'}\n"
            f"• Порог подозрений: {self.config.get('suspicious_threshold', 3)}\n"
            f"• Анти-спам: {self.config.get('spam_threshold', 5)} сообщений за {self.config.get('spam_timeout', 10)} сек\n\n"
            f"🔍 <b>Последние события:</b>\n"
        )
        
        recent_events = self.security_events[-5:] if self.security_events else []
        if recent_events:
            for event in recent_events:
                security_text += f"• {event.event_type}: {event.description[:50]}...\n"
        else:
            security_text += "• Событий не найдено\n"
        
        await update.message.reply_text(security_text, parse_mode=ParseMode.HTML)
    
    async def scan_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not await self.check_permissions(update, context):
            return
        
        if not context.args:
            await update.message.reply_text("❌ Укажите пользователя для сканирования: /scan @username")
            return
        
        username = context.args[0].replace("@", "")
        user_data = self.suspicious_users.get(username, {})
        total_points = user_data.get("total_points", 0)
        
        scan_text = (
            f"🔍 <b>Результат сканирования</b>\n\n"
            f"👤 <b>Пользователь:</b> @{username}\n"
            f"⚠️ <b>Очки подозрений:</b> {total_points}\n"
        )
        
        if total_points == 0:
            scan_text += "✅ <b>Статус:</b> Безопасен"
        elif total_points < 3:
            scan_text += "⚠️ <b>Статус:</b> Подозрителен"
        else:
            scan_text += "🚨 <b>Статус:</b> Опасен"
        
        if user_data.get("reasons"):
            reasons = [r["reason"] for r in user_data["reasons"][-3:]]
            scan_text += f"\n\n📝 <b>Последние причины:</b>\n• " + "\n• ".join(reasons)
        
        await update.message.reply_text(scan_text, parse_mode=ParseMode.HTML)
    
    async def warn_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not await self.check_permissions(update, context):
            return
        
        if len(context.args) < 1:
            await update.message.reply_text("❌ Укажите пользователя: /warn @username [причина]")
            return
        
        username = context.args[0].replace("@", "")
        reason = " ".join(context.args[1:]) if len(context.args) > 1 else "Причина не указана"
        
        await self.add_suspicion(username, "manual_warning", 2)
        
        warn_text = (
            f"⚠️ <b>Предупреждение выдано</b>\n\n"
            f"👤 <b>Пользователь:</b> @{username}\n"
            f"👮 <b>Модератор:</b> {update.effective_user.first_name}\n"
            f"📝 <b>Причина:</b> {reason}\n\n"
            f"⚠️ Очки подозрений увеличены на 2"
        )
        
        await update.message.reply_text(warn_text, parse_mode=ParseMode.HTML)
    
    async def ban_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not await self.check_admin_permissions(update, context):
            return
        
        if len(context.args) < 1:
            await update.message.reply_text("❌ Укажите пользователя: /ban @username [причина]")
            return
        
        username = context.args[0].replace("@", "")
        reason = " ".join(context.args[1:]) if len(context.args) > 1 else "Причина не указана"
        
        await self.add_suspicion(username, "manual_ban", 5)
        
        ban_text = (
            f"🚫 <b>Пользователь заблокирован</b>\n\n"
            f"👤 <b>Пользователь:</b> @{username}\n"
            f"👮 <b>Администратор:</b> {update.effective_user.first_name}\n"
            f"📝 <b>Причина:</b> {reason}\n\n"
            f"⚠️ Очки подозрений увеличены на 5"
        )
        
        await update.message.reply_text(ban_text, parse_mode=ParseMode.HTML)
    
    async def unban_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not await self.check_admin_permissions(update, context):
            return
        
        if not context.args:
            await update.message.reply_text("❌ Укажите пользователя: /unban @username")
            return
        
        username = context.args[0].replace("@", "")
        
        if username in self.suspicious_users:
            del self.suspicious_users[username]
            await update.message.reply_text(f"✅ Подозрения для @{username} очищены")
        else:
            await update.message.reply_text(f"ℹ️ У @{username} нет подозрений")
    
    async def logs_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not await self.check_permissions(update, context):
            return
        
        event_type = context.args[0] if context.args else "all"
        limit = int(context.args[1]) if len(context.args) > 1 else 10
        
        if limit > 25:
            limit = 25
        
        events = self.security_events
        
        if event_type != "all":
            events = [e for e in events if e.event_type == event_type.upper()]
        
        if not events:
            await update.message.reply_text("📝 Логи не найдены")
            return
        
        logs_text = f"📋 <b>Логи безопасности</b> ({len(events)} событий)\n\n"
        
        recent_events = events[-limit:]
        for event in recent_events:
            logs_text += (
                f"<b>[{event.event_type}] {event.user_name}</b>\n"
                f"{event.description}\n"
                f"⏰ {event.timestamp.strftime('%H:%M:%S')}\n\n"
            )
        
        await update.message.reply_text(logs_text, parse_mode=ParseMode.HTML)
    
    async def stats_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not await self.check_permissions(update, context):
            return
        
        total_events = len(self.security_events)
        event_types = {}
        
        for event in self.security_events:
            event_types[event.event_type] = event_types.get(event.event_type, 0) + 1
        
        stats_text = (
            f"📊 <b>Статистика безопасности</b>\n\n"
            f"📈 <b>Общие показатели:</b>\n"
            f"• Всего событий: {total_events}\n"
            f"• Подозрительных пользователей: {len(self.suspicious_users)}\n\n"
            f"📋 <b>Типы событий:</b>\n"
        )
        
        for event_type, count in sorted(event_types.items(), key=lambda x: x[1], reverse=True)[:5]:
            stats_text += f"• {event_type}: {count}\n"
        
        await update.message.reply_text(stats_text, parse_mode=ParseMode.HTML)
    
    async def reload_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not await self.check_admin_permissions(update, context):
            return
        
        self.config = self.load_config()
        await update.message.reply_text("✅ Конфигурация перезагружена")
    
    async def handle_message(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        message = update.message
        user = message.from_user
        chat = message.chat
        
        if chat.type == "private":
            return
        
        content = message.text.lower()
        user_id = user.id
        
        await self.process_message(message)
        await self.log_message_event(message)
    
    async def handle_all_messages(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        message = update.message
        user = message.from_user
        chat = message.chat
        
        if chat.type == "private":
            return
        
        if user.is_bot:
            return
        
        await self.check_new_user(user, chat)
    
    async def process_message(self, message):
        content = message.text.lower()
        user_id = message.from_user.id
        username = message.from_user.username or str(user_id)
        
        if await self.is_suspicious_content(content):
            await self.handle_suspicious_message(message)
            await self.add_suspicion(username, "suspicious_content", 1)
        
        if await self.is_spam(message):
            await self.handle_spam(message)
            await self.add_suspicion(username, "spam", 2)
    
    async def is_suspicious_content(self, content: str) -> bool:
        blocked_words = self.config.get("blocked_words", [])
        return any(word in content for word in blocked_words)
    
    async def is_spam(self, message) -> bool:
        user_id = message.from_user.id
        username = message.from_user.username or str(user_id)
        
        if username not in self.suspicious_users:
            return False
        
        user_data = self.suspicious_users[username]
        recent_messages = user_data.get("recent_messages", [])
        
        now = datetime.datetime.now()
        recent_messages = [msg for msg in recent_messages if (now - msg).seconds < self.config.get("spam_timeout", 10)]
        
        if len(recent_messages) >= self.config.get("spam_threshold", 5):
            return True
        
        recent_messages.append(now)
        user_data["recent_messages"] = recent_messages
        return False
    
    async def handle_suspicious_message(self, message):
        embed_text = (
            f"⚠️ <b>Подозрительное сообщение</b>\n\n"
            f"👤 <b>Автор:</b> {message.from_user.first_name}\n"
            f"💬 <b>Чат:</b> {message.chat.title}\n"
            f"📝 <b>Сообщение:</b> {message.text[:100]}{'...' if len(message.text) > 100 else ''}\n\n"
            f"⏰ Время: {datetime.datetime.now().strftime('%H:%M:%S')}"
        )
        
        await self.send_security_alert(embed_text)
    
    async def handle_spam(self, message):
        embed_text = (
            f"🚫 <b>Спам обнаружен</b>\n\n"
            f"👤 <b>Автор:</b> {message.from_user.first_name}\n"
            f"💬 <b>Чат:</b> {message.chat.title}\n\n"
            f"⏰ Время: {datetime.datetime.now().strftime('%H:%M:%S')}"
        )
        
        await self.send_security_alert(embed_text)
        
        if self.config.get("auto_moderation", True):
            await self.add_suspicion(
                message.from_user.username or str(message.from_user.id),
                "spam_detection",
                2
            )
    
    async def add_suspicion(self, username: str, reason: str, points: int):
        if username not in self.suspicious_users:
            self.suspicious_users[username] = {
                "total_points": 0,
                "reasons": [],
                "recent_messages": []
            }
        
        user_data = self.suspicious_users[username]
        user_data["total_points"] += points
        user_data["reasons"].append({
            "reason": reason,
            "points": points,
            "timestamp": datetime.datetime.now()
        })
        
        if user_data["total_points"] >= self.config.get("suspicious_threshold", 3):
            await self.handle_high_suspicion(username, user_data)
    
    async def handle_high_suspicion(self, username: str, user_data: dict):
        embed_text = (
            f"🚨 <b>Высокий уровень подозрений</b>\n\n"
            f"👤 <b>Пользователь:</b> @{username}\n"
            f"⚠️ <b>Очки подозрений:</b> {user_data['total_points']}\n\n"
            f"📝 <b>Последние причины:</b>\n"
        )
        
        reasons = [r["reason"] for r in user_data["reasons"][-5:]]
        embed_text += "• " + "\n• ".join(reasons)
        
        await self.send_security_alert(embed_text)
    
    async def send_security_alert(self, text: str):
        log_chat_id = self.config.get("log_chat_id")
        if log_chat_id:
            try:
                await self.application.bot.send_message(
                    chat_id=log_chat_id,
                    text=text,
                    parse_mode=ParseMode.HTML
                )
            except Exception as e:
                self.logger.error(f"Failed to send security alert: {e}")
    
    async def check_new_user(self, user, chat):
        if user.username:
            username = user.username
        else:
            username = str(user.id)
        
        account_age = datetime.datetime.now() - user.date
        
        if account_age.days < 7:
            embed_text = (
                f"🆕 <b>Новый аккаунт</b>\n\n"
                f"👤 <b>Пользователь:</b> {user.first_name}\n"
                f"💬 <b>Чат:</b> {chat.title}\n"
                f"📅 <b>Возраст аккаунта:</b> {account_age.days} дней\n\n"
                f"⏰ Время: {datetime.datetime.now().strftime('%H:%M:%S')}"
            )
            
            await self.send_security_alert(embed_text)
    
    async def log_security_event(self, event: SecurityEvent):
        self.security_events.append(event)
        await self.db.log_event(event)
        
        if len(self.security_events) > 1000:
            self.security_events = self.security_events[-1000:]
    
    async def log_message_event(self, message):
        await self.db.log_message(
            message.message_id,
            message.from_user.id,
            message.from_user.first_name,
            message.chat.id,
            message.text,
            message.date
        )
    
    async def check_permissions(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
        user = update.effective_user
        chat = update.effective_chat
        
        if chat.type == "private":
            return True
        
        member = await chat.get_member(user.id)
        return member.status in ["creator", "administrator"] or member.can_restrict_members
    
    async def check_admin_permissions(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
        user = update.effective_user
        chat = update.effective_chat
        
        if chat.type == "private":
            return user.id == self.config.get("owner_id")
        
        member = await chat.get_member(user.id)
        return member.status in ["creator", "administrator"]
    
    async def handle_callback(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
    
    async def run(self):
        await self.db.init()
        self.logger.info("Database initialized")
        
        print("╔══════════════════════════════════════════════════════════════╗")
        print("║                    XILLEN Security Bot                      ║")
        print("║                        v2.0 by @Bengamin_Button            ║")
        print("╚══════════════════════════════════════════════════════════════╝")
        print("Bot is starting...")
        
        await self.application.initialize()
        await self.application.start()
        await self.application.updater.start_polling()
        
        print("Bot is running! Press Ctrl+C to stop.")
        
        try:
            await self.application.updater.idle()
        except KeyboardInterrupt:
            print("\nBot is stopping...")
        finally:
            await self.application.stop()
            await self.application.shutdown()

class Database:
    def __init__(self):
        self.db_path = "xillen_telegram_security.db"
    
    async def init(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                user_name TEXT NOT NULL,
                event_type TEXT NOT NULL,
                description TEXT NOT NULL,
                level TEXT NOT NULL,
                chat_id INTEGER,
                message_id INTEGER
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL,
                user_name TEXT NOT NULL,
                chat_id INTEGER NOT NULL,
                content TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )
        ''')
        
        conn.commit()
        conn.close()
    
    async def log_event(self, event: SecurityEvent):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO security_events 
            (timestamp, user_id, user_name, event_type, description, level, chat_id, message_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            event.timestamp.isoformat(),
            event.user_id,
            event.user_name,
            event.event_type,
            event.description,
            event.level.value,
            event.chat_id,
            event.message_id
        ))
        
        conn.commit()
        conn.close()
    
    async def log_message(self, message_id: int, user_id: int, user_name: str, 
                         chat_id: int, content: str, timestamp: datetime.datetime):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO messages 
            (id, user_id, user_name, chat_id, content, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            message_id,
            user_id,
            user_name,
            chat_id,
            content,
            timestamp.isoformat()
        ))
        
        conn.commit()
        conn.close()

async def main():
    bot = XillenSecurityBot()
    
    try:
        await bot.run()
    except Exception as e:
        print(f"❌ Ошибка запуска бота: {e}")

if __name__ == "__main__":
    asyncio.run(main())

