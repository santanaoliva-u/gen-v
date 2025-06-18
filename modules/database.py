# modules/database.py
import sqlite3
import asyncio
import aiosqlite
import logging
from typing import Any, Dict, List, Optional, Tuple
from contextlib import asynccontextmanager
from pathlib import Path
from modules.config import DB_PATH

# Configurar logging
logging.basicConfig( format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
log = logging.getLogger(__name__)

class Database:
    _instance = None
    _lock = asyncio.Lock()  # Usar asyncio.Lock para el contexto asíncrono

    # CORRECCIÓN: Usamos un patrón Singleton asíncrono para garantizar una única instancia.
    async def __new__(cls, *args, **kwargs):
        async with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                # Inicializamos las propiedades de la conexión a None
                cls._instance.sync_conn = None
                cls._instance.async_conn = None
                
                # Inicialización síncrona se realiza al crear la instancia
                await asyncio.to_thread(cls._instance._initialize_sync_db)
        return cls._instance
    
    # Este método de inicialización síncrona se ejecuta en un hilo separado.
    def _initialize_sync_db(self):
        """Inicializa la base de datos y crea tablas si no existen."""
        try:
            # Asegurarse de que el directorio de la base de datos existe
            db_file = Path(DB_PATH)
            db_file.parent.mkdir(parents=True, exist_ok=True)
            
            self.sync_conn = sqlite3.connect(DB_PATH, check_same_thread=False)
            self.sync_conn.row_factory = sqlite3.Row
            
            with self.sync_conn:
                self.sync_conn.execute("PRAGMA foreign_keys = ON;")
                # MEJORA: WAL (Write-Ahead Logging) mejora drásticamente la concurrencia.
                self.sync_conn.execute("PRAGMA journal_mode=WAL;")
                self._create_tables()

            log.info("Base de datos síncrona inicializada exitosamente.")
        except sqlite3.Error as e:
            log.critical(f"Error CRÍTICO al inicializar la base de datos síncrona: {e}", exc_info=True)
            raise

    def _create_tables(self):
        """Crea todas las tablas e índices necesarios en la base de datos."""
        try:
            # La ejecución ya está dentro de una transacción por _initialize_sync_db
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
                    url TEXT NOT NULL, -- CORRECCIÓN: Columna crucial añadida.
                    description TEXT NOT NULL,
                    vuln_type TEXT NOT NULL CHECK(vuln_type IN ('XSS Reflejado', 'DOM XSS', 'XSS (POST)', 'SQLi', 'LFI', 'Command Injection', 'CRLF Injection', 'File Upload', 'Backdoor', 'CVE')),
                    cve TEXT,
                    risk_score REAL NOT NULL CHECK(risk_score >= 0 AND risk_score <= 10),
                    status TEXT NOT NULL DEFAULT 'NEW' CHECK(status IN ('NEW', 'REPORTED', 'FIXED', 'INVALID')),
                    timestamp TEXT NOT NULL,
                    UNIQUE(target, url, vuln_type, description) -- Evitar hallazgos duplicados idénticos
                );

                CREATE TABLE IF NOT EXISTS reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    program_name TEXT NOT NULL,
                    report_type TEXT NOT NULL CHECK(report_type IN ('JSON', 'Markdown')), -- Simplificado
                    file_path TEXT NOT NULL,
                    generated_at TEXT NOT NULL
                );
                
                -- ÍNDICES para acelerar consultas comunes
                CREATE INDEX IF NOT EXISTS idx_findings_program_target ON findings(program_name, target);
                CREATE INDEX IF NOT EXISTS idx_findings_vuln_type ON findings(vuln_type);
                CREATE INDEX IF NOT EXISTS idx_reports_program ON reports(program_name);
            """)
            log.debug("Tablas e índices verificados/creados.")
        except sqlite3.Error as e:
            log.error(f"Error al crear las tablas: {e}", exc_info=True)
            raise
    
    # MEJORA: Patrón para mantener una única conexión asíncrona y reutilizarla.
    async def get_async_connection(self) -> aiosqlite.Connection:
        """Devuelve una conexión asíncrona compartida, creándola si es necesario."""
        if self.async_conn is None or not self.async_conn.is_alive():
            async with self._lock:
                # Doble verificación para evitar recreaciones en condiciones de carrera
                if self.async_conn is None or not self.async_conn.is_alive():
                    log.info("Creando nueva conexión asíncrona a la base de datos...")
                    self.async_conn = await aiosqlite.connect(DB_PATH)
                    self.async_conn.row_factory = aiosqlite.Row
                    await self.async_conn.execute("PRAGMA foreign_keys = ON;")
                    await self.async_conn.execute("PRAGMA journal_mode=WAL;")
                    log.info("Conexión asíncrona establecida y configurada.")
        return self.async_conn

    @asynccontextmanager
    async def transaction(self):
        """Proporciona un contexto de transacción asíncrona."""
        conn = await self.get_async_connection()
        try:
            yield conn
            await conn.commit()
        except aiosqlite.Error as e:
            await conn.rollback()
            log.error(f"Error en transacción, se revirtieron los cambios: {e}", exc_info=True)
            raise

    # --- MÉTODOS DE API ASÍNCRONOS ---

    async def fetch_all_async(self, query: str, params: Tuple = ()) -> List[Dict]:
        """Recupera todas las filas de forma asíncrona."""
        try:
            conn = await self.get_async_connection()
            async with conn.execute(query, params) as cursor:
                rows = await cursor.fetchall()
                return [dict(row) for row in rows]
        except aiosqlite.Error as e:
            log.error(f"Error en fetch_all_async: {e}", exc_info=True)
            return []

    async def fetch_one_async(self, query: str, params: Tuple = ()) -> Optional[Dict]:
        """Recupera una única fila de forma asíncrona."""
        try:
            conn = await self.get_async_connection()
            async with conn.execute(query, params) as cursor:
                row = await cursor.fetchone()
                return dict(row) if row else None
        except aiosqlite.Error as e:
            log.error(f"Error en fetch_one_async: {e}", exc_info=True)
            return None

    async def insert_finding_async(self, program_name: str, target: str, url: str, description: str, vuln_type: str, risk_score: float, cve: Optional[str] = None) -> Optional[int]:
        """Inserta un nuevo hallazgo de forma segura y eficiente."""
        from datetime import datetime
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
                if cursor.rowcount > 0: # Si se insertó una nueva fila
                    return cursor.lastrowid
                return None # No se insertó nada (ya existía)
        except aiosqlite.Error as e:
            log.error(f"Fallo al insertar hallazgo para {target}: {e}", exc_info=True)
            return None
    
    async def insert_report_async(self, program_name: str, report_type: str, file_path: str) -> Optional[int]:
        """Inserta un registro de un reporte generado."""
        from datetime import datetime
        generated_at = datetime.utcnow().isoformat()
        
        query = "INSERT INTO reports (program_name, report_type, file_path, generated_at) VALUES (?, ?, ?, ?)"
        params = (program_name, report_type, file_path, generated_at)
        
        try:
            async with self.transaction() as conn:
                cursor = await conn.execute(query, params)
                return cursor.lastrowid
        except aiosqlite.Error as e:
            log.error(f"Fallo al insertar reporte para {program_name}: {e}", exc_info=True)
            return None
    
    # --- MÉTODO DE CIERRE ---
    
    async def close_all(self):
        """Cierra todas las conexiones a la base de datos de forma segura."""
        log.info("Cerrando todas las conexiones de la base de datos...")
        if self.async_conn:
            await self.async_conn.close()
            self.async_conn = None
            log.info("Conexión asíncrona cerrada.")
        if self.sync_conn:
            await asyncio.to_thread(self.sync_conn.close)
            self.sync_conn = None
            log.info("Conexión síncrona cerrada.")

# Para usar esta clase en un contexto asíncrono, instánciala con await:
# db = await Database()
# await db.close_all()
