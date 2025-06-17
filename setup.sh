#!/bin/bash

# Colores para la terminal
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# Verificar directorio raíz
if [ ! -f "main.py" ]; then
  echo -e "${RED}[!] Ejecuta este script desde el directorio raíz de CazaDivina${NC}"
  exit 1
fi

# Crear estructura
echo -e "${GREEN}[+] Creando estructura...${NC}"
mkdir -p modules/xss_server/public output/recon_cache wordlists
touch output/capture.log output/xss_cache.json output/system.log
touch xss_payloads.txt proxies.txt user_agents.txt wordlists/parameters.txt

# Descargar recursos
echo -e "${GREEN}[+] Descargando recursos...${NC}"
wget -q https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt -O wordlists/common.txt
wget -q https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/xss-payloads.txt -O xss_payloads.txt
echo -e "id\nq\nsearch\ncallback" >wordlists/parameters.txt

# Configurar ejemplos
echo -e "${GREEN}[+] Configurando ejemplos...${NC}"
if [ ! -s "proxies.txt" ]; then
  echo "http://138.199.233.152:80" >proxies.txt
fi
if [ ! -s "user_agents.txt" ]; then
  echo "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" >user_agents.txt
fi

# Instalar dependencias
echo -e "${GREEN}[+] Instalando dependencias...${NC}"
sudo apt update
sudo apt install -y nodejs npm golang-go python3-pip
pip install requests psutil

# Instalar herramientas
echo -e "${GREEN}[+] Instalando herramientas...${NC}"
go install -v github.com/ffuf/ffuf@latest
go install -v github.com/OJ/gobuster/v3@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/OWASP/Amass/v3/...@master
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
pip install dirsearch arjun

# Verificar herramientas
echo -e "${GREEN}[+] Verificando herramientas...${NC}"
python3 -c "from utils.tool_wrapper import is_tool_available; tools = ['amass', 'subfinder', 'assetfinder', 'findomain', 'dnsx', 'httpx', 'waybackurls', 'gau', 'katana', 'ffuf', 'gobuster', 'dirsearch', 'arjun']; print('\n'.join(f'{t}: {'OK' if is_tool_available(t) else 'MISSING'}' for t in tools))"

# Verificar Node.js y ngrok
if ! command -v node &>/dev/null; then
  echo -e "${RED}[!] Instala Node.js desde nodejs.org${NC}"
  exit 1
fi
if ! command -v ngrok &>/dev/null; then
  echo -e "${RED}[!] Instala ngrok desde ngrok.com${NC}"
  exit 1
fi

# Configurar servidor XSS
echo -e "${GREEN}[+] Configurando servidor XSS...${NC}"
cd modules/xss_server
npm install
cd ../..

# Actualizar URL de ngrok dinámicamente
echo -e "${GREEN}[+] Configurando ngrok...${NC}"
ngrok http 3000 >/dev/null &
sleep 5
NGROK_URL=$(curl -s http://localhost:4040/api/tunnels | grep -o 'https://[^"]*' | head -n 1)
if [ -z "$NGROK_URL" ]; then
  echo -e "${RED}[!] No se pudo obtener la URL de ngrok${NC}"
  exit 1
fi
sed -i "s|https://42a4-189-174-213-167.ngrok-free.app|$NGROK_URL|" modules/xss_server/public/payload.js
sed -i "s|https://42a4-189-174-213-167.ngrok-free.app|$NGROK_URL|" modules/deep_fuzz_xss.py

# Iniciar servidor XSS
echo -e "${GREEN}[+] Iniciando servidor XSS...${NC}"
node modules/xss_server/server.js &
sleep 2

# Configurar Discord webhook (opcional)
echo -e "${GREEN}[+] Configurando Discord webhook (ingresa URL o presiona Enter para omitir)...${NC}"
read -p "URL del webhook: " DISCORD_WEBHOOK
if [ -n "$DISCORD_WEBHOOK" ]; then
  echo "export DISCORD_WEBHOOK='$DISCORD_WEBHOOK'" >>~/.bashrc
  source ~/.bashrc
fi

# Actualizar config.yaml
echo -e "${GREEN}[+] Actualizando config.yaml...${NC}"
cat <<EOF >config.yaml
modules:
  - IntelModule
  - ReconModule
  - DeepFuzzXSSModule
  - ExecutionModule
  - PredictModule
  - StealthModule
  - ReportingModule
  - LearningModule
cve:
  api_url: https://services.nvd.nist.gov/rest/json/cves/2.0
scope:
  include:
    - payments.myntra.com
    - api.myntra.com
    - www.myntra.com
  exclude:
    - uiscoop.payzippy.com
EOF

# Actualizar main.py
echo -e "${GREEN}[+] Actualizando main.py...${NC}"
sed -i '/module_file_map = {/a \            '\''DeepFuzzXSSModule'\'': '\''deep_fuzz_xss'\'',' main.py

# Abrir ventana de monitoreo
echo -e "${GREEN}[+] Abriendo ventana de monitoreo...${NC}"
if command -v gnome-terminal &>/dev/null; then
  gnome-terminal -- bash -c "tail -f output/system.log output/capture.log; exec bash" &
else
  xterm -e "tail -f output/system.log output/capture.log" &
fi

# Iniciar pipeline
echo -e "${GREEN}[+] Iniciando pipeline...${NC}"
python3 main.py --target-program "Valve"
