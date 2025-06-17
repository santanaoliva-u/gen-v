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

# Instalar herramientas
echo -e "${GREEN}[+] Instalando herramientas...${NC}"
go install -v github.com/ffuf/ffuf@latest >/dev/null 2>&1
go install -v github.com/OJ/gobuster/v3@latest >/dev/null 2>&1
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest >/dev/null 2>&1
go install -v github.com/OWASP/Amass/v3/...@master >/dev/null 2>&1
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest >/dev/null 2>&1
go install -v github.com/tomnomnom/assetfinder@latest >/dev/null 2>&1
go install -v github.com/tomnomnom/waybackurls@latest >/dev/null 2>&1
go install -v github.com/lc/gau/v2/cmd/gau@latest >/dev/null 2>&1
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest >/dev/null 2>&1
go install -v github.com/projectdiscovery/katana/cmd/katana@latest >/dev/null 2>&1
pip install dirsearch arjun >/dev/null 2>&1

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
npm install >/dev/null 2>&1
cd ../..

# Iniciar servidor XSS
echo -e "${GREEN}[+] Iniciando servidor XSS...${NC}"
node modules/xss_server/server.js &
sleep 2

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
EOF

# Actualizar main.py
echo -e "${GREEN}[+] Actualizando main.py...${NC}"
sed -i '/module_file_map = {/a \            '\''DeepFuzzXSSModule'\'': '\''deep_fuzz_xss'\'',' main.py

# Abrir ventana de monitoreo
echo -e "${GREEN}[+] Abriendo ventana de monitoreo...${NC}"
gnome-terminal -- bash -c "tail -f output/system.log output/capture.log; exec bash" &

# Iniciar pipeline
echo -e "${GREEN}[+] Iniciando pipeline...${NC}"
python main.py --target-program "Valve"
