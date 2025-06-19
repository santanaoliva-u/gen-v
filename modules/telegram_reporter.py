# modules/telegram_reporter.py
"""
Módulo para enviar logs del sistema a un chat de Telegram en tiempo real.
Incluye manejo de reintentos, rate limiting y división de mensajes largos.
"""

import asyncio
import logging
from telegram import Bot
from telegram.error import TelegramError
from dotenv import load_dotenv
import os
from typing import Optional
from asyncio import Queue
from time import time

# Cargar variables de entorno desde .env
load_dotenv()

# Configuración del bot desde variables de entorno
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
TELEGRAM_LOG_LEVEL = os.getenv("TELEGRAM_LOG_LEVEL", "INFO").upper()
TELEGRAM_MAX_MESSAGE_LENGTH = int(os.getenv("TELEGRAM_MAX_MESSAGE_LENGTH", 4096))
TELEGRAM_MAX_RETRIES = int(os.getenv("TELEGRAM_MAX_RETRIES", 3))
TELEGRAM_RATE_LIMIT = int(os.getenv("TELEGRAM_RATE_LIMIT", 20))  # Mensajes por minuto

# Configurar logger interno
log = logging.getLogger(__name__)

class TelegramHandler(logging.Handler):
    """
    Manejador de logging personalizado para enviar logs a Telegram.
    Usa una cola para limitar la tasa de envío y maneja bucles de eventos.
    """
    def __init__(self, bot_token: str, chat_id: str, max_retries: int = 3):
        super().__init__()
        self.bot = Bot(token=bot_token)
        self.chat_id = chat_id
        self.max_retries = max_retries
        self.setLevel(getattr(logging, TELEGRAM_LOG_LEVEL))
        self.formatter = logging.Formatter(
            '[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        self.message_queue = Queue()
        self.last_sent_time = time()
        self.sent_count = 0
        self._start_queue_processor()

    def _start_queue_processor(self):
        """
        Inicia un procesador asíncrono para manejar la cola de mensajes.
        Respeta el límite de tasa de envío.
        """
        async def process_queue():
            while True:
                text = await self.message_queue.get()
                current_time = time()
                if current_time - self.last_sent_time >= 60:
                    self.sent_count = 0
                    self.last_sent_time = current_time
                if self.sent_count >= TELEGRAM_RATE_LIMIT:
                    wait_time = 60 - (current_time - self.last_sent_time)
                    if wait_time > 0:
                        await asyncio.sleep(wait_time)
                    self.sent_count = 0
                    self.last_sent_time = time()
                await self._send_message_async(text)
                self.sent_count += 1
                self.message_queue.task_done()

        try:
            loop = asyncio.get_running_loop()
            loop.create_task(process_queue())
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.create_task(process_queue())
            loop.run_in_executor(None, loop.run_forever)

    async def _send_message_async(self, text: str, retry_count: int = 0) -> bool:
        """
        Envía un mensaje a Telegram de forma asíncrona con reintentos.
        """
        try:
            await self.bot.send_message(chat_id=self.chat_id, text=text)
            return True
        except TelegramError as e:
            if retry_count < self.max_retries:
                log.warning(f"Error enviando a Telegram, reintentando ({retry_count + 1}/{self.max_retries}): {e}")
                await asyncio.sleep(2 ** retry_count)  # Backoff exponencial
                return await self._send_message_async(text, retry_count + 1)
            log.error(f"Falló enviar mensaje a Telegram tras {self.max_retries} intentos: {e}")
            return False

    def emit(self, record: logging.LogRecord) -> None:
        """
        Añade el mensaje de log a la cola para su envío a Telegram.
        Divide mensajes largos si es necesario.
        """
        log_entry = self.format(record)
        parts = [log_entry[i:i + TELEGRAM_MAX_MESSAGE_LENGTH] 
                 for i in range(0, len(log_entry), TELEGRAM_MAX_MESSAGE_LENGTH)]
        
        for part in parts:
            try:
                self.message_queue.put_nowait(part)
            except asyncio.QueueFull:
                log.warning("Cola de mensajes de Telegram llena, descartando mensaje.")

def setup_telegram_logging() -> Optional[TelegramHandler]:
    """
    Configura el sistema de logging para enviar logs a Telegram.
    """
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        log.error("Faltan TELEGRAM_BOT_TOKEN o TELEGRAM_CHAT_ID en .env. Logging de Telegram deshabilitado.")
        return None

    telegram_handler = TelegramHandler(TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, TELEGRAM_MAX_RETRIES)
    logging.getLogger().addHandler(telegram_handler)
    log.info("Configuración de logging para Telegram completada.")
    return telegram_handler
