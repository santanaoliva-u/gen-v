# modules/database.py
"""
Este archivo define la clase Database, que maneja una base de datos SQLite para el proyecto CazaDivina.
Usa aiosqlite para operaciones asíncronas y sqlite3 para inicialización síncrona.
La base de datos almacena programas, hallazgos (vulnerabilidades) y reportes.
"""

import sqlite3  # Para conexiones síncronas a SQLite
import asyncio  # Para manejar operaciones asíncronas
import aiosqlite  # Para conexiones asíncronas a SQLite
import logging  # Para registrar mensajes (logs)
import json  # Para formatear logs como JSON
from typing import Any, Dict, List, Optional, Tuple  # Para definir tipos de datos
from contextlib import asynccontextmanager  # Para manejar transacciones asíncronas
from pathlib import Path  # Para trabajar con rutas de archivos
from datetime import datetime  # Para generar marcas de tiempo
from modules.config import DB_PATH  # Ruta de la base de datos (definida en config.py)

# Configuración de logging estructurado (igual que en main.py y test.py)
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
        return json.dumps(log_entry)

# Configura el logger
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
# Guarda logs en un archivo
file_handler = logging.FileHandler('output/database.log')
file_handler.setFormatter(JsonFormatter())
log.addHandler(file_handler)
# Muestra logs en la consola
console_handler = logging.StreamHandler()
console_handler.setFormatter(JsonFormatter())
log.addHandler(console_handler)

class Database:
    """
    Clase Database para manejar conexiones a una base de datos SQLite.
    Usa un patrón Singleton para garantizar una única instancia.
    Soporta operaciones síncronas (para inicialización) y asíncronas (para consultas).
    """
    _instance = None  # Instancia única de la clase
    _lock = asyncio.Lock()  # Candado para evitar condiciones de carrera en la creación de la instancia

    async def __new__(cls, *args, **kwargs):
        """
        Implementa el patrón Singleton asíncrono.
        Garantiza que solo haya una instancia de Database.
        """
        async with cls._lock:
            if cls._instance is None:
                log.info("Creando nueva instancia de Database...")
                cls._instance = super().__new__(cls)
                cls._instance.sync_conn = None  # Conexión síncrona
                cls._instance.async_conn = None  # Conexión asíncrona
                # Ejecuta la inicialización síncrona en un hilo separado
                await asyncio.to_thread(cls._instance._initialize_sync_db)
        return cls._instance

    def _initialize_sync_db(self):
        """
        Inicializa la base de datos síncronamente.
        Crea el archivo de la base de datos y las tablas si no existen.
        """
        try:
            # Asegura que el directorio de la base de datos exista
            db_file = Path(DB_PATH)
            db_file.parent.mkdir(parents=True, exist_ok=True)
            log.debug(f"Directorio de la base de datos: {db_file.parent}")

            # Crea una conexión síncrona
            self.sync_conn = sqlite3.connect(DB_PATH, check_same_thread=False)
            self.sync_conn.row_factory = sqlite3.Row  # Devuelve filas como diccionarios

            with self.sync_conn:
                # Habilita claves foráneas
                self.sync_conn.execute("PRAGMA foreign_keys = ON;")
                # Usa Write-Ahead Logging para mejorar la concurrencia
                self.sync_conn.execute("PRAGMA journal_mode=WAL;")
                # Crea tablas e índices
                self._create_tables()
                # Aplica migraciones si es necesario
                self._apply_migrations()

            log.info("Base de datos síncrona inicializada exitosamente.")
        except sqlite3.Error as e:
            log.critical(f"Error al inicializar la base de datos síncrona: {e}", exc_info=True)
            raise

    def _create_tables(self):
        """
        Crea las tablas e índices necesarios en la base de datos.
        Incluye tablas para programas, hallazgos y reportes.
        """
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
                        'CVE', 'Recon'  -- Añadido para soportar hallazgos de ReconModule
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
        Por ejemplo, añade columnas nuevas o modifica restricciones.
        """
        try:
            # Verifica si la tabla findings tiene la columna vuln_type con 'Recon'
            cursor = self.sync_conn.execute("PRAGMA table_info(findings);")
            columns = [row['name'] for row in cursor.fetchall()]
            if 'vuln_type' in columns:
                # No podemos modificar CHECK constraints directamente, pero podemos verificar si 'Recon' está soportado
                log.debug("Columna vuln_type encontrada, migraciones no necesarias.")
            else:
                log.warning("Esquema de findings obsoleto, requiere actualización manual.")
        except sqlite3.Error as e:
            log.error(f"Error al aplicar migraciones: {e}", exc_info=True)

    async def get_async_connection(self) -> aiosqlite.Connection:
        """
        Devuelve una conexión asíncrona, creándola o reconectándola si es necesario.
        """
        try:
            if self.async_conn is None or await self._is_connection_closed():
                async with self._lock:
                    if self.async_conn is None or await self._is_connection_closed():
                        log.info("Creando/reconectando conexión asíncrona...")
                        self.async_conn = await aiosqlite.connect(DB_PATH)
                        self.async_conn.row_factory = aiosqlite.Row
                        await self.async_conn.execute("PRAGMA foreign_keys = ON;")
                        await self.async_conn.execute("PRAGMA journal_mode=WAL;")
                        log.info("Conexión asíncrona establecida.")
            return self.async_conn
        except aiosqlite.Error as e:
            log.error(f"Error al obtener conexión asíncrona: {e}", exc_info=True)
            raise

    async def _is_connection_closed(self) -> bool:
        """
        Verifica si la conexión asíncrona está cerrada.
        """
        try:
            if self.async_conn is None:
                return True
            await self.async_conn.execute("SELECT 1")
            return False
        except (aiosqlite.Error, AttributeError):
            return True

    @asynccontextmanager
    async def transaction(self):
        """
        Proporciona un contexto de transacción asíncrona.
        Asegura que las operaciones se confirmen o reviertan correctamente.
        """
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
        """
        Recupera todas las filas de una consulta.
        Args:
            query: Consulta SQL (por ejemplo, "SELECT * FROM findings").
            params: Parámetros para la consulta (por ejemplo, (program_name,)).
        Returns:
            Lista de diccionarios con los resultados.
        """
        try:
            conn = await self.get_async_connection()
            async with conn.execute(query, params) as cursor:
                rows = await cursor.fetchall()
                return [dict(row) for row in rows]
        except aiosqlite.Error as e:
            log.error(f"Error en fetch_all_async: {e}", exc_info=True)
            return []

    async def fetch_one_async(self, query: str, params: Tuple = ()) -> Optional[Dict]:
        """
        Recupera una única fila de una consulta.
        Args:
            query: Consulta SQL.
            params: Parámetros para la consulta.
        Returns:
            Diccionario con la fila o None si no hay resultados.
        """
        try:
            conn = await self.get_async_connection()
            async with conn.execute(query, params) as cursor:
                row = await cursor.fetchone()
                return dict(row) if row else None
        except aiosqlite.Error as e:
            log.error(f"Error en fetch_one_async: {e}", exc_info=True)
            return None

    async def insert_finding_async(self, program_name: str, target: str, url: str, description: str, vuln_type: str, risk_score: float, cve: Optional[str] = None) -> Optional[int]:
        """
        Inserta un nuevo hallazgo en la tabla findings.
        Args:
            program_name: Nombre del programa (por ejemplo, "test").
            target: Objetivo del hallazgo (por ejemplo, "subdomain.value.com").
            url: URL asociada al hallazgo.
            description: Descripción del hallazgo.
            vuln_type: Tipo de vulnerabilidad (por ejemplo, "Recon").
            risk_score: Puntuación de riesgo (0 a 10).
            cve: Identificador CVE (opcional).
        Returns:
            ID del hallazgo insertado o None si ya existía.
        """
        # Validación de parámetros
        if not all([program_name, target, url, description, vuln_type]):
            log.error("Parámetros requeridos faltantes en insert_finding_async")
            return None
        if not (0 <= risk_score <= 10):
            log.error(f"risk_score inválido: {risk_score}. Debe estar entre 0 y 10.")
            return None
        valid_vuln_types = {
            'XSS Reflejado', 'DOM XSS', 'XSS (POST)', 'SQLi', 'LFI',
            'Command Injection', 'CRLF Injection', 'File Upload', 'Backdoor',
            'CVE', 'Recon'
        }
        if vuln_type not in valid_vuln_types:
            log.error(f"vuln_type inválido: {vuln_type}. Valores válidos: {valid_vuln_types}")
            return None

        timestamp = datetime.utcnow().isoformat()
        query = """
            INSERT INTO findings (program_name, target, url, description, vuln_type, cve, risk_score, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(target, url, vuln_type, description) DO NOTHING;
        """
        params = (program_name, target, url, description, vuln_type, cve, risk_score, timestamp)

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
        """
        Inserta un registro de un reporte generado.
        Args:
            program_name: Nombre del programa.
            report_type: Tipo de reporte ("JSON" o "Markdown").
            file_path: Ruta del archivo del reporte.
        Returns:
            ID del reporte insertado o None si falla.
        """
        # Validación de parámetros
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
        """
        Cierra todas las conexiones a la base de datos de forma segura.
        """
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
