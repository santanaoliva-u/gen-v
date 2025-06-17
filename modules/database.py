# database.py
import sqlite3
import threading
import aiosqlite
import logging
from typing import Any, Dict, List, Optional, Tuple  # Incluye Dict para evitar NameError
from contextlib import asynccontextmanager
from config import DB_PATH, LOG_LEVEL

# Configurar logging
logging.basicConfig(level=LOG_LEVEL)
log = logging.getLogger(__name__)

class Database:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(Database, cls).__new__(cls)
                cls._instance._initialize_sync_db()
        return cls._instance

    def _initialize_sync_db(self):
        """Inicializa la base de datos síncrona."""
        try:
            self.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
            self.conn.row_factory = sqlite3.Row
            self._create_tables()
            log.info("Base de datos síncrona inicializada")
        except sqlite3.Error as e:
            log.error(f"Error inicializando base de datos síncrona: {e}")
            raise

    def _create_tables(self):
        """Crea tablas e índices."""
        try:
            with self.conn:
                self.conn.executescript("""
                    CREATE TABLE IF NOT EXISTS programs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT UNIQUE NOT NULL,
                        url TEXT,
                        tvs REAL CHECK(tvs >= 0),
                        scope TEXT,
                        out_of_scope TEXT,
                        last_updated TEXT
                    );
                    CREATE TABLE IF NOT EXISTS findings (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        program_name TEXT NOT NULL,
                        target TEXT NOT NULL,
                        description TEXT NOT NULL,
                        vuln_type TEXT NOT NULL CHECK(vuln_type IN ('XSS', 'SQLi', 'LFI', 'Command Injection', 'CRLF Injection', 'File Upload', 'Backdoor', 'CVE')),
                        cve TEXT,
                        risk_score REAL CHECK(risk_score >= 0 AND risk_score <= 10),
                        status TEXT DEFAULT 'NEW' CHECK(status IN ('NEW', 'REPORTED', 'FIXED', 'INVALID')),
                        timestamp TEXT NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS template_reputation (
                        template_id TEXT PRIMARY KEY,
                        reputation_score REAL DEFAULT 0.5 CHECK(reputation_score BETWEEN 0 AND 1),
                        success_count INTEGER DEFAULT 0 CHECK(success_count >= 0),
                        fail_count INTEGER DEFAULT 0 CHECK(fail_count >= 0)
                    );
                    CREATE TABLE IF NOT EXISTS cves (
                        id TEXT PRIMARY KEY,
                        description TEXT,
                        severity TEXT CHECK(severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
                        cvss_score REAL CHECK(cvss_score BETWEEN 0 AND 10),
                        affected_products TEXT,
                        published_date TEXT,
                        last_updated TEXT
                    );
                    CREATE TABLE IF NOT EXISTS finding_cves (
                        finding_id INTEGER,
                        cve_id TEXT,
                        PRIMARY KEY (finding_id, cve_id),
                        FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE,
                        FOREIGN KEY (cve_id) REFERENCES cves(id) ON DELETE CASCADE
                    );
                    CREATE TABLE IF NOT EXISTS pipeline_runs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        program_name TEXT NOT NULL,
                        start_time TEXT NOT NULL,
                        end_time TEXT,
                        status TEXT NOT NULL CHECK(status IN ('RUNNING', 'COMPLETED', 'FAILED')),
                        execution_time REAL CHECK(execution_time >= 0)
                    );
                    CREATE TABLE IF NOT EXISTS reports (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        program_name TEXT NOT NULL,
                        report_type TEXT NOT NULL CHECK(report_type IN ('JSON', 'MARKDOWN', 'CSV')),
                        file_path TEXT NOT NULL,
                        generated_at TEXT NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_findings_program_name ON findings(program_name);
                    CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target);
                    CREATE INDEX IF NOT EXISTS idx_findings_vuln_type ON findings(vuln_type);
                    CREATE INDEX IF NOT EXISTS idx_findings_timestamp ON findings(timestamp);
                    CREATE INDEX IF NOT EXISTS idx_finding_cves_cve_id ON finding_cves(cve_id);
                    CREATE INDEX IF NOT EXISTS idx_pipeline_runs_program_name ON pipeline_runs(program_name);
                    CREATE INDEX IF NOT EXISTS idx_reports_program_name ON reports(program_name);
                """)
        except sqlite3.Error as e:
            log.error(f"Error creando tablas: {e}")
            raise

    @asynccontextmanager
    async def get_async_connection(self):
        """Proporciona una conexión asíncrona."""
        conn = await aiosqlite.connect(DB_PATH)
        conn.row_factory = aiosqlite.Row
        try:
            yield conn
        except aiosqlite.Error as e:
            log.error(f"Error en conexión asíncrona: {e}")
            raise
        finally:
            await conn.commit()
            await conn.close()

    def execute_query(self, query: str, params: Tuple = ()) -> sqlite3.Cursor:
        """Ejecuta una consulta síncrona."""
        try:
            with self.conn:
                cursor = self.conn.cursor()
                cursor.execute(query, params)
                return cursor
        except sqlite3.Error as e:
            log.error(f"Error ejecutando consulta síncrona: {e}")
            raise

    async def execute_query_async(self, query: str, params: Tuple = ()) -> None:
        """Ejecuta una consulta asíncrona."""
        async with self.get_async_connection() as conn:
            await conn.execute(query, params)

    async def execute_bulk_insert_async(self, query: str, params_list: List[Tuple]) -> None:
        """Ejecuta inserciones masivas asíncronas."""
        async with self.get_async_connection() as conn:
            await conn.executemany(query, params_list)

    def fetch_all(self, query: str, params: Tuple = ()) -> List[sqlite3.Row]:
        """Recupera todas las filas síncronamente."""
        try:
            with self.conn:
                cursor = self.conn.cursor()
                cursor.execute(query, params)
                return cursor.fetchall()
        except sqlite3.Error as e:
            log.error(f"Error recuperando datos síncronos: {e}")
            raise

    async def fetch_all_async(self, query: str, params: Tuple = ()) -> List[Dict]:
        """Recupera todas las filas asíncronamente."""
        try:
            async with self.get_async_connection() as conn:
                cursor = await conn.execute(query, params)
                rows = await cursor.fetchall()
                return [dict(row) for row in rows]
        except aiosqlite.Error as e:
            log.error(f"Error recuperando datos asíncronos: {e}")
            return []  # Retorna una lista vacía en caso de error

    def fetch_one(self, query: str, params: Tuple = ()) -> Optional[sqlite3.Row]:
        """Recupera una fila síncronamente."""
        try:
            with self.conn:
                cursor = self.conn.cursor()
                cursor.execute(query, params)
                return cursor.fetchone()
        except sqlite3.Error as e:
            log.error(f"Error recuperando una fila síncrona: {e}")
            raise

    async def fetch_one_async(self, query: str, params: Tuple = ()) -> Optional[Dict]:
        """Recupera una fila asíncronamente."""
        async with self.get_async_connection() as conn:
            cursor = await conn.execute(query, params)
            row = await cursor.fetchone()
            return dict(row) if row else None

    async def insert_finding_async(self, program_name: str, target: str, description: str, vuln_type: str, risk_score: float, cve: Optional[str] = None) -> int:
        """Inserta un hallazgo asíncronamente."""
        from datetime import datetime
        timestamp = datetime.utcnow().isoformat()
        query = """
            INSERT INTO findings (program_name, target, description, vuln_type, cve, risk_score, status, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, 'NEW', ?)
        """
        async with self.get_async_connection() as conn:
            cursor = await conn.execute(query, (program_name, target, description, vuln_type, cve, risk_score, timestamp))
            finding_id = cursor.lastrowid
            if cve:
                await conn.execute(
                    "INSERT OR IGNORE INTO finding_cves (finding_id, cve_id) VALUES (?, ?)",
                    (finding_id, cve)
                )
            return finding_id

    async def insert_report_async(self, program_name: str, report_type: str, file_path: str) -> int:
        """Inserta un reporte asíncronamente."""
        from datetime import datetime
        generated_at = datetime.utcnow().isoformat()
        query = """
            INSERT INTO reports (program_name, report_type, file_path, generated_at)
            VALUES (?, ?, ?, ?)
        """
        async with self.get_async_connection() as conn:
            cursor = await conn.execute(query, (program_name, report_type, file_path, generated_at))
            return cursor.lastrowid

    async def clean_old_findings_async(self, days: int = 30):
        """Limpia hallazgos antiguos."""
        from datetime import datetime, timedelta
        cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat()
        async with self.get_async_connection() as conn:
            await conn.execute("DELETE FROM findings WHERE timestamp < ?", (cutoff,))

    def close(self):
        """Cierra la conexión síncrona."""
        try:
            self.conn.close()
            log.info("Conexión síncrona cerrada")
        except sqlite3.Error as e:
            log.error(f"Error cerrando conexión síncrona: {e}")
