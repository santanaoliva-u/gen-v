import os
import subprocess
import sqlite3
import autopep8
import ast
import re
import time
from typing import Dict, List, Optional

class CodeMasterBot:
    """Un bot súper inteligente para reparar módulos, programar y gestionar proyectos."""

    def __init__(self, db_path: str = "project.db"):
        """Inicializa el bot con una base de datos y configuraciones."""
        self.db_path = db_path
        self.db_conn = None
        self.cursor = None
        self.current_project = None
        self.command_history = []
        self.connect_db()
        self.setup_db()
        print("CodeMasterBot listo para ayudarte.")

    ### Gestión de Base de Datos
    def connect_db(self):
        """Conecta a la base de datos SQLite."""
        try:
            self.db_conn = sqlite3.connect(self.db_path)
            self.cursor = self.db_conn.cursor()
        except sqlite3.Error as e:
            print(f"Error al conectar a la base de datos: {e}")

    def setup_db(self):
        """Crea las tablas necesarias en la base de datos."""
        tables = [
            """
            CREATE TABLE IF NOT EXISTS project_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT NOT NULL UNIQUE,
                status TEXT DEFAULT 'pending',
                last_modified TEXT
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS analysis_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id INTEGER,
                tool TEXT,
                result TEXT,
                timestamp TEXT,
                FOREIGN KEY (file_id) REFERENCES project_files(id)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS fix_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id INTEGER,
                action TEXT,
                timestamp TEXT,
                FOREIGN KEY (file_id) REFERENCES project_files(id)
            )
            """
        ]
        try:
            for table in tables:
                self.cursor.execute(table)
            self.db_conn.commit()
        except sqlite3.Error as e:
            print(f"Error al configurar la base de datos: {e}")

    def execute_query(self, query: str, params: tuple = ()) -> List:
        """Ejecuta una consulta SQL y devuelve resultados si es SELECT."""
        try:
            self.cursor.execute(query, params)
            if query.strip().upper().startswith("SELECT"):
                return self.cursor.fetchall()
            self.db_conn.commit()
            return []
        except sqlite3.Error as e:
            print(f"Error en la consulta: {e}")
            return []

    def close_db(self):
        """Cierra la conexión a la base de datos."""
        if self.db_conn:
            self.db_conn.close()
            print("Base de datos cerrada.")

    ### Gestión de Proyectos
    def set_project(self, directory: str):
        """Establece el directorio del proyecto actual."""
        if not os.path.exists(directory):
            print(f"El directorio '{directory}' no existe.")
            return
        self.current_project = os.path.abspath(directory)
        self.scan_project()

    def scan_project(self):
        """Escanea el proyecto y registra archivos en la base de datos."""
        if not self.current_project:
            print("Primero establece un proyecto con 'set_project <directorio>'.")
            return
        files = [os.path.join(root, f) for root, _, fs in os.walk(self.current_project) 
                 for f in fs if f.endswith((".py", ".txt"))]
        for file_path in files:
            self.register_file(file_path)
        print(f"Escaneados {len(files)} archivos en el proyecto.")

    def register_file(self, file_path: str):
        """Registra o actualiza un archivo en la base de datos."""
        relative_path = os.path.relpath(file_path, self.current_project)
        query = "INSERT OR REPLACE INTO project_files (path, last_modified) VALUES (?, ?)"
        self.execute_query(query, (relative_path, time.ctime(os.path.getmtime(file_path))))

    ### Análisis y Reparación
    def analyze_file(self, file_path: str):
        """Analiza un archivo y guarda los resultados."""
        if not self.check_project_and_file(file_path):
            return
        full_path = os.path.join(self.current_project, file_path)
        results = self.analyze_code(full_path)
        file_id = self.get_file_id(file_path)
        if file_id:
            for tool, result in results.items():
                self.execute_query(
                    "INSERT INTO analysis_results (file_id, tool, result, timestamp) VALUES (?, ?, ?, ?)",
                    (file_id, tool, result, time.ctime())
                )
        print(f"\nAnálisis de '{file_path}':")
        for tool, result in results.items():
            print(f"- {tool}: {result.strip() or 'Sin problemas detectados'}")

    def analyze_code(self, file_path: str) -> Dict[str, str]:
        """Analiza el código con múltiples herramientas."""
        results = {}
        # Verificación básica
        if not os.path.exists(file_path):
            return {"error": "Archivo no encontrado"}
        
        # Análisis con pylint
        try:
            pylint_result = subprocess.run(['pylint', file_path], capture_output=True, text=True, timeout=10)
            results['pylint'] = pylint_result.stdout or "Sin errores"
        except subprocess.TimeoutExpired:
            results['pylint'] = "Análisis tardó demasiado"
        except Exception as e:
            results['pylint'] = f"Error: {e}"

        # Análisis con flake8
        try:
            flake8_result = subprocess.run(['flake8', file_path], capture_output=True, text=True, timeout=10)
            results['flake8'] = flake8_result.stdout or "Sin errores"
        except subprocess.TimeoutExpired:
            results['flake8'] = "Análisis tardó demasiado"
        except Exception as e:
            results['flake8'] = f"Error: {e}"

        # Análisis de sintaxis con AST
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                ast.parse(f.read())
            results['syntax'] = "Sintaxis correcta"
        except SyntaxError as e:
            results['syntax'] = f"Error de sintaxis: {e}"
        except Exception as e:
            results['syntax'] = f"Error al leer archivo: {e}"

        return results

    def fix_file(self, file_path: str):
        """Repara un archivo automáticamente."""
        if not self.check_project_and_file(file_path):
            return
        full_path = os.path.join(self.current_project, file_path)
        try:
            with open(full_path, 'r', encoding='utf-8') as f:
                code = f.read()
            # Aplicar autopep8
            fixed_code = autopep8.fix_code(code, options={'aggressive': 2})
            # Añadir importaciones faltantes
            analysis = self.analyze_code(full_path)
            if "NameError" in analysis.get('pylint', ''):
                fixed_code = self.add_missing_imports(fixed_code)
            with open(full_path, 'w', encoding='utf-8') as f:
                f.write(fixed_code)
            self.register_file(full_path)
            file_id = self.get_file_id(file_path)
            if file_id:
                self.execute_query(
                    "INSERT INTO fix_history (file_id, action, timestamp) VALUES (?, ?, ?)",
                    (file_id, "fixed", time.ctime())
                )
            print(f"Archivo '{file_path}' reparado con éxito.")
        except Exception as e:
            print(f"Error al reparar '{file_path}': {e}")

    def add_missing_imports(self, code: str) -> str:
        """Añade importaciones faltantes detectadas."""
        imports = []
        if "os." in code and "import os" not in code:
            imports.append("import os")
        if "sqlite3" in code and "import sqlite3" not in code:
            imports.append("import sqlite3")
        if "time" in code and "import time" not in code:
            imports.append("import time")
        if imports:
            return "\n".join(imports) + "\n\n" + code
        return code

    ### Generación de Código
    def generate_code(self, prompt: str, output_file: str):
        """Genera código basado en un prompt y lo guarda."""
        if not self.current_project:
            print("Primero establece un proyecto con 'set_project <directorio>'.")
            return
        code = self.generate_code_from_prompt(prompt)
        if not code:
            print("No pude entender el prompt. Usa algo como 'crea una función que sume dos números'.")
            return
        full_path = os.path.join(self.current_project, output_file)
        with open(full_path, 'w', encoding='utf-8') as f:
            f.write(code)
        self.fix_file(output_file)  # Repara el código generado para formato
        file_id = self.get_file_id(output_file)
        if file_id:
            self.execute_query(
                "INSERT INTO fix_history (file_id, action, timestamp) VALUES (?, ?, ?)",
                (file_id, "generated", time.ctime())
            )
        print(f"Código generado y guardado en '{output_file}'.")

    def generate_code_from_prompt(self, prompt: str) -> str:
        """Genera código basado en el prompt del usuario."""
        prompt = prompt.lower().strip()
        if "función que sume" in prompt or "suma dos números" in prompt:
            return """def sumar(a, b):
    return a + b"""
        elif "función" in prompt:
            match = re.search(r"función\s+(\w+)", prompt)
            if match:
                return f"""def {match.group(1)}(arg):
    # Implementación personalizada aquí
    return arg"""
        elif "conectar a base de datos" in prompt:
            return """import sqlite3

def connect_db(db_name):
    try:
        conn = sqlite3.connect(db_name)
        print("Conexión exitosa a", db_name)
        return conn
    except sqlite3.Error as e:
        print(f"Error: {e}")
        return None"""
        elif "leer archivo" in prompt:
            return """def leer_archivo(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        return "Archivo no encontrado"
    except Exception as e:
        return f"Error: {e}\""""
        return ""

    ### Utilidades
    def get_file_id(self, file_path: str) -> Optional[int]:
        """Obtiene el ID de un archivo en la base de datos."""
        result = self.execute_query("SELECT id FROM project_files WHERE path = ?", (file_path,))
        return result[0][0] if result else None

    def check_project_and_file(self, file_path: str) -> bool:
        """Verifica que el proyecto y el archivo existan."""
        if not self.current_project:
            print("Primero establece un proyecto con 'set_project <directorio>'.")
            return False
        full_path = os.path.join(self.current_project, file_path)
        if not os.path.exists(full_path):
            print(f"El archivo '{file_path}' no existe en el proyecto.")
            return False
        return True

    ### Interfaz de Usuario
    def run(self):
        """Ejecuta el bot en un bucle interactivo."""
        print("\n¡Bienvenido a CodeMasterBot! Escribe 'help' para ver comandos o 'exit' para salir.\n")
        while True:
            try:
                command = input("Comando > ").strip().lower()
                self.command_history.append(command)
                if command == "exit":
                    self.close_db()
                    print("¡Hasta luego!")
                    break
                elif command == "help":
                    print("""
Comandos disponibles:
- set_project <directorio> : Establece el directorio del proyecto.
- scan                     : Escanea el proyecto y registra archivos.
- analyze <archivo>        : Analiza un archivo con herramientas avanzadas.
- fix <archivo>            : Repara un archivo automáticamente.
- generate "<prompt>" <archivo> : Genera código basado en el prompt (ejemplo: "crea una función que sume dos números").
- query "<sql>"            : Ejecuta una consulta SQL en la base de datos.
- help                     : Muestra esta ayuda.
- exit                     : Sale del bot.
                    """)
                elif command.startswith("set_project"):
                    self.set_project(command.split(maxsplit=1)[1])
                elif command == "scan":
                    self.scan_project()
                elif command.startswith("analyze"):
                    self.analyze_file(command.split(maxsplit=1)[1])
                elif command.startswith("fix"):
                    self.fix_file(command.split(maxsplit=1)[1])
                elif command.startswith("generate"):
                    parts = command.split('"')
                    if len(parts) >= 3:
                        prompt, output_file = parts[1], parts[2].strip().split()[0]
                        self.generate_code(prompt, output_file)
                    else:
                        print("Uso: generate \"<prompt>\" <archivo>")
                elif command.startswith("query"):
                    parts = command.split('"')
                    if len(parts) >= 3:
                        sql = parts[1]
                        results = self.execute_query(sql)
                        print("Resultados:", results)
                    else:
                        print("Uso: query \"<sql>\"")
                else:
                    print("Comando no reconocido. Escribe 'help' para ver opciones.")
            except IndexError:
                print("Faltan argumentos. Usa 'help' para más información.")
            except Exception as e:
                print(f"Error inesperado: {e}")

if __name__ == "__main__":
    bot = CodeMasterBot()
    bot.run()
