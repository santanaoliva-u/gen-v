# modules/database.py
"""
Este archivo define la clase Database, que maneja una base de datos SQLite para el proyecto CazaDivina.
Usa aiosqlite para operaciones asíncronas y sqlite3 para inicialización síncrona.
La base de datos almacena programas, hallazgos (vulnerabilidades) y reportes.
"""

import sqlite3
import asyncio
import aiosqlite
import logging
import json
from typing import Any, Dict, List, Optional, Tuple
from contextlib import asynccontextmanager
from pathlib import Path
from datetime import datetime
from modules.config import DB_PATH  # Asumimos que está definido en config.py

# Configuración de logging estructurado
class JsonFormatter(logging.Formatter):
    """Formatea los logs como JSON para que sean fáciles de leer y analizar."""
    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "level": record.levelname,
            "module": record.name,
            "message": record.getMessage(),
            "file": record.pathname,
            "line": record.lineno
        }
        return json.dumps(log_entry, ensure_ascii=False)

# Configura el logger
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
file_handler = logging.FileHandler('output/database.log')
file_handler.setFormatter(JsonFormatter())
log.addHandler(file_handler)
console_handler = logging.StreamHandler()
console_handler.setFormatter(JsonFormatter())
log.addHandler(console_handler)

# Lista de tipos de vulnerabilidades permitidos
VALID_VULN_TYPES = {
    'XSS Reflejado', 'DOM XSS', 'XSS (POST)', 'SQLi', 'LFI',
    'Command Injection', 'CRLF Injection', 'File Upload', 'Backdoor',
    'CVE', 'Recon', 'Intel'
}

class Database:
    """
    Clase Database para manejar conexiones a una base de datos SQLite.
    Usa un patrón Singleton para garantizar una única instancia.
    Soporta operaciones síncronas (para inicialización) y asíncronas (para consultas).
    """
    _instance = None
    _lock = asyncio.Lock()

    async def __new__(cls, *args, **kwargs):
        async with cls._lock:
            if cls._instance is None:
                log.info("Creando nueva instancia de Database...")
                cls._instance = super().__new__(cls)
                cls._instance.sync_conn = None
                cls._instance.async_conn = None
                cls._instance.db_path = DB_PATH if 'DB_PATH' in globals() else 'output/database.db'
                await asyncio.to_thread(cls._instance._initialize_sync_db)
        return cls._instance

    def _initialize_sync_db(self):
        try:
            db_file = Path(self.db_path)
            db_file.parent.mkdir(parents=True, exist_ok=True)
            log.debug(f"Directorio de la base de datos: {db_file.parent}")

            self.sync_conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self.sync_conn.row_factory = sqlite3.Row

            with self.sync_conn:
                self.sync_conn.execute("PRAGMA foreign_keys = ON;")
                self.sync_conn.execute("PRAGMA journal_mode=WAL;")
                self._create_tables()
                self._apply_migrations()

            log.info("Base de datos síncrona inicializada exitosamente.")
        except sqlite3.Error as e:
            log.critical(f"Error al inicializar la base de datos síncrona: {e}", exc_info=True)
            raise
        except NameError as e:
            log.critical(f"DB_PATH no definido en modules.config: {e}", exc_info=True)
            raise

    def _create_tables(self):
        try:
            self.sync_conn.executescript("""
                CREATE TABLE IF NOT EXISTS programs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    url TEXT,
                    scope TEXT,
                    out_of_scope TEXT,
                    last_updated TEXT
                );
                
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    program_name TEXT NOT NULL,
                    target TEXT NOT NULL,
                    url TEXT NOT NULL,
                    description TEXT NOT NULL,
                    vuln_type TEXT NOT NULL CHECK(vuln_type IN (
                        'XSS Reflejado', 'DOM XSS', 'XSS (POST)', 'SQLi', 'LFI',
                        'Command Injection', 'CRLF Injection', 'File Upload', 'Backdoor',
                        'CVE', 'Recon', 'Intel'
                    )),
                    cve TEXT,
                    risk_score REAL NOT NULL CHECK(risk_score >= 0 AND risk_score <= 10),
                    status TEXT NOT NULL DEFAULT 'NEW' CHECK(status IN ('NEW', 'REPORTED', 'FIXED', 'INVALID')),
                    timestamp TEXT NOT NULL,
                    UNIQUE(target, url, vuln_type, description)
                );

                CREATE TABLE IF NOT EXISTS reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    program_name TEXT NOT NULL,
                    report_type TEXT NOT NULL CHECK(report_type IN ('JSON', 'Markdown')),
                    file_path TEXT NOT NULL,
                    generated_at TEXT NOT NULL
                );
                
                -- Índices para acelerar consultas comunes
                CREATE INDEX IF NOT EXISTS idx_findings_program_target ON findings(program_name, target);
                CREATE INDEX IF NOT EXISTS idx_findings_vuln_type ON findings(vuln_type);
                CREATE INDEX IF NOT EXISTS idx_findings_timestamp ON findings(timestamp);
                CREATE INDEX IF NOT EXISTS idx_reports_program ON reports(program_name);
            """)
            log.debug("Tablas e índices creados/verificados.")
        except sqlite3.Error as e:
            log.error(f"Error al crear tablas: {e}", exc_info=True)
            raise

    def _apply_migrations(self):
        """
        Aplica migraciones para actualizar el esquema de la base de datos.
        Verifica y actualiza la restricción CHECK en vuln_type.
        """
        try:
            cursor = self.sync_conn.execute("PRAGMA table_info(findings);")
            columns = [row['name'] for row in cursor.fetchall()]
            if 'vuln_type' in columns:
                log.debug("Columna vuln_type encontrada, verificando soporte para 'Recon' y 'Intel'...")
                # Crear una tabla temporal con la restricción actualizada
                self.sync_conn.execute("""
                    CREATE TABLE IF NOT EXISTS findings_temp (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        program_name TEXT NOT NULL,
                        target TEXT NOT NULL,
                        url TEXT NOT NULL,
                        description TEXT NOT NULL,
                        vuln_type TEXT NOT NULL CHECK(vuln_type IN (
                            'XSS Reflejado', 'DOM XSS', 'XSS (POST)', 'SQLi', 'LFI',
                            'Command Injection', 'CRLF Injection', 'File Upload', 'Backdoor',
                            'CVE', 'Recon', 'Intel'
                        )),
                        cve TEXT,
                        risk_score REAL NOT NULL CHECK(risk_score >= 0 AND risk_score <= 10),
                        status TEXT NOT NULL DEFAULT 'NEW' CHECK(status IN ('NEW', 'REPORTED', 'FIXED', 'INVALID')),
                        timestamp TEXT NOT NULL,
                        UNIQUE(target, url, vuln_type, description)
                    );
                """)
                # Migrar datos
                self.sync_conn.execute("""
                    INSERT OR IGNORE INTO findings_temp
                    SELECT * FROM findings;
                """)
                # Eliminar tabla antigua y renombrar la nueva
                self.sync_conn.execute("DROP TABLE IF EXISTS findings;")
                self.sync_conn.execute("ALTER TABLE findings_temp RENAME TO findings;")
                # Recrear índices
                self.sync_conn.executescript("""
                    CREATE INDEX IF NOT EXISTS idx_findings_program_target ON findings(program_name, target);
                    CREATE INDEX IF NOT EXISTS idx_findings_vuln_type ON findings(vuln_type);
                    CREATE INDEX IF NOT EXISTS idx_findings_timestamp ON findings(timestamp);
                """)
                log.info("Migración completada: vuln_type ahora soporta 'Recon' e 'Intel'.")
        except sqlite3.Error as e:
            log.error(f"Error al aplicar migraciones: {e}", exc_info=True)
            raise

    async def get_async_connection(self) -> aiosqlite.Connection:
        try:
            if self.async_conn is None or await self._is_connection_closed():
                async with self._lock:
                    if self.async_conn is None or await self._is_connection_closed():
                        log.info("Creando/reconectando conexión asíncrona...")
                        self.async_conn = await aiosqlite.connect(self.db_path)
                        self.async_conn.row_factory = aiosqlite.Row
                        await self.async_conn.execute("PRAGMA foreign_keys = ON;")
                        await self.async_conn.execute("PRAGMA journal_mode=WAL;")
                        log.info("Conexión asíncrona establecida.")
            return self.async_conn
        except aiosqlite.Error as e:
            log.error(f"Error al obtener conexión asíncrona: {e}", exc_info=True)
            raise

    async def _is_connection_closed(self) -> bool:
        try:
            if self.async_conn is None:
                return True
            await self.async_conn.execute("SELECT 1")
            return False
        except (aiosqlite.Error, AttributeError):
            return True

    @asynccontextmanager
    async def transaction(self):
        conn = await self.get_async_connection()
        try:
            yield conn
            await conn.commit()
            log.debug("Transacción confirmada.")
        except aiosqlite.Error as e:
            await conn.rollback()
            log.error(f"Error en transacción, cambios revertidos: {e}", exc_info=True)
            raise
        except Exception as e:
            await conn.rollback()
            log.error(f"Error inesperado en transacción: {e}", exc_info=True)
            raise

    async def fetch_all_async(self, query: str, params: Tuple = ()) -> List[Dict]:
        try:
            conn = await self.get_async_connection()
            async with conn.execute(query, params) as cursor:
                rows = await cursor.fetchall()
                return [dict(row) for row in rows]
        except aiosqlite.Error as e:
            log.error(f"Error en fetch_all_async: {e}", exc_info=True)
            return []

    async def fetch_one_async(self, query: str, params: Tuple = ()) -> Optional[Dict]:
        try:
            conn = await self.get_async_connection()
            async with conn.execute(query, params) as cursor:
                row = await cursor.fetchone()
                return dict(row) if row else None
        except aiosqlite.Error as e:
            log.error(f"Error en fetch_one_async: {e}", exc_info=True)
            return None

    async def insert_finding_async(self, program_name: str, target: str, url: str, description: str, vuln_type: str, risk_score: float, cve: Optional[str] = None) -> Optional[int]:
        # Validación de parámetros
        if not all([program_name, target, description, vuln_type]):
            log.error(f"Parámetros requeridos faltantes en insert_finding_async: program_name={program_name}, target={target}, description={description}, vuln_type={vuln_type}")
            return None
        if not (0 <= risk_score <= 10):
            log.error(f"risk_score inválido: {risk_score}. Debe estar entre 0 y 10.")
            return None
        if vuln_type not in VALID_VULN_TYPES:
            log.warning(f"vuln_type inválido: {vuln_type}. Ajustando a 'Recon'.")
            vuln_type = 'Recon'

        timestamp = datetime.utcnow().isoformat()
        query = """
            INSERT INTO findings (program_name, target, url, description, vuln_type, cve, risk_score, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(target, url, vuln_type, description) DO NOTHING;
        """
        params = (program_name, target, url or "", description, vuln_type, cve, risk_score, timestamp)

        try:
            async with self.transaction() as conn:
                cursor = await conn.execute(query, params)
                if cursor.rowcount > 0:
                    log.debug(f"Hallazgo insertado para {target}: {description}")
                    return cursor.lastrowid
                log.debug(f"Hallazgo ya existía para {target}: {description}")
                return None
        except aiosqlite.Error as e:
            log.error(f"Error al insertar hallazgo para {target}: {e}", exc_info=True)
            return None

    async def insert_report_async(self, program_name: str, report_type: str, file_path: str) -> Optional[int]:
        if not all([program_name, report_type, file_path]):
            log.error("Parámetros requeridos faltantes en insert_report_async")
            return None
        valid_report_types = {'JSON', 'Markdown'}
        if report_type not in valid_report_types:
            log.error(f"report_type inválido: {report_type}. Valores válidos: {valid_report_types}")
            return None

        generated_at = datetime.utcnow().isoformat()
        query = """
            INSERT INTO reports (program_name, report_type, file_path, generated_at)
            VALUES (?, ?, ?, ?)
        """
        params = (program_name, report_type, file_path, generated_at)

        try:
            async with self.transaction() as conn:
                cursor = await conn.execute(query, params)
                log.debug(f"Reporte insertado para {program_name}: {file_path}")
                return cursor.lastrowid
        except aiosqlite.Error as e:
            log.error(f"Error al insertar reporte para {program_name}: {e}", exc_info=True)
            return None

    async def close_all(self):
        log.info("Cerrando conexiones de la base de datos...")
        try:
            if self.async_conn and not await self._is_connection_closed():
                await self.async_conn.close()
                self.async_conn = None
                log.info("Conexión asíncrona cerrada.")
            if self.sync_conn:
                await asyncio.to_thread(self.sync_conn.close)
                self.sync_conn = None
                log.info("Conexión síncrona cerrada.")
        except Exception as e:
            log.error(f"Error al cerrar conexiones: {e}", exc_info=True)
