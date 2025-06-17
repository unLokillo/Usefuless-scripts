#!/bin/bash

# ===================================================================================
# WAF Bypass Finder v2.2
# ===================================================================================

# --- FICHEROS DE CONFIGURACIÓN ---
DOMAINS_FILE="dominios_audit.txt"
RANGES_FILE="rangos_posibles.txt"
OUTPUT_FILE="resultados_v2.2.csv"
PROGRESS_FILE="progreso.log"
ALL_IPS_TEMP_FILE="all_ips.tmp"

# --- LISTA DE IPs A PROBAR CON PRIORIDAD ---
HIGH_PRIORITY_IPS=() # Separadas por espacios y entre comillas

# --- PARÁMETROS DE PRUEBA ---
USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
CURL_TIMEOUT=4
WAF_TEST_PAYLOAD="?lang=<svg/onload=alert()>"
REQUEST_COUNTER=0

# --- COLORES PARA LA SALIDA ---
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
BLUE="\033[0;34m"
NC="\033[0m"

# ===================================================================================
# FUNCIONES AUXILIARES
# ===================================================================================

function cleanup() {
    echo -e "\n\n${YELLOW}[!] Saliendo de forma segura...${NC}"
    rm -f "$ALL_IPS_TEMP_FILE" "domains_to_check.tmp" 2>/dev/null
    echo -e "${GREEN}[OK] Limpieza finalizada. Ejecuta de nuevo para continuar el progreso.${NC}"
    exit 0
}
trap cleanup SIGINT

function format_time() {
    local T=$1; ((T < 0)) && T=0
    local D=$((T/60/60/24)); local H=$((T/60/60%24)); local M=$((T/60%60)); local S=$((T%60))
    (( D > 0 )) && printf '%d días, %02d:%02d:%02d' $D $H $M $S || printf '%02d:%02d:%02d' $H $M $S
}

# ===================================================================================
# INICIO DEL SCRIPT
# ===================================================================================

START_TIME_TOTAL=$(date +%s) # Guardar tiempo de inicio global

echo -e "${BLUE}[INFO] WAF Bypass Finder v2.2 Iniciado${NC}"
echo -e "${BLUE}[INFO] Comprobando dependencias...${NC}"
command -v curl >/dev/null 2>&1 || { echo -e >&2 "${RED}[ERROR] 'curl' no está instalado. Abortando.${NC}"; exit 1; }
command -v nmap >/dev/null 2>&1 || { echo -e >&2 "${RED}[ERROR] 'nmap' no está instalado. Abortando.${NC}"; exit 1; }
echo -e "${GREEN}[OK] Dependencias encontradas.${NC}"

touch "$PROGRESS_FILE"
if [ ! -f "$OUTPUT_FILE" ]; then
    echo "Dominio,IP_Encontrada,WAF_Presente_En_IP,Baseline_HTTP_Code" > "$OUTPUT_FILE"
fi

echo -e "${BLUE}[INFO] Cargando dominios y comprobando progreso...${NC}"
initial_domains_count=$(wc -l < "$DOMAINS_FILE" 2>/dev/null || echo 0)
comm -23 <(sort "$DOMAINS_FILE" 2>/dev/null) <(sort "$PROGRESS_FILE" 2>/dev/null) > domains_to_check.tmp
DOMAINS_TO_CHECK=($(<"domains_to_check.tmp"))
rm -f domains_to_check.tmp
processed_count=$((initial_domains_count - ${#DOMAINS_TO_CHECK[@]}))
if [ $processed_count -gt 0 ]; then
    echo -e "${GREEN}[INFO] Reanudando sesión. Se han omitido ${processed_count} dominios ya procesados.${NC}"
fi

echo -e "${BLUE}[INFO] Generando lista de IPs a partir de los rangos...${NC}"
nmap -sL -n -iL "$RANGES_FILE" 2>/dev/null | grep "Nmap scan report for" | awk '{print $5}' > "$ALL_IPS_TEMP_FILE"
TOTAL_IPS_GENERATED=$(wc -l < "$ALL_IPS_TEMP_FILE")
NUM_PRIORITY_IPS=${#HIGH_PRIORITY_IPS[@]}
echo -e "${GREEN}[OK] Fuentes de IPs: ${TOTAL_IPS_GENERATED} desde rangos y ${NUM_PRIORITY_IPS} IPs prioritarias.${NC}"

SUCCESSFUL_IPS=()
TOTAL_DOMAINS_TO_RUN=${#DOMAINS_TO_CHECK[@]}
DOMAINS_PROCESSED_THIS_RUN=0
START_TIME_LOOP=$(date +%s)

for domain in "${DOMAINS_TO_CHECK[@]}"; do
    ((DOMAINS_PROCESSED_THIS_RUN++))
    
    CURRENT_TIME=$(date +%s)
    ELAPSED_SECONDS=$((CURRENT_TIME - START_TIME_LOOP))
    if [ $DOMAINS_PROCESSED_THIS_RUN -gt 1 ]; then
        TIME_PER_DOMAIN=$((ELAPSED_SECONDS / (DOMAINS_PROCESSED_THIS_RUN - 1)))
        REMAINING_DOMAINS=$((TOTAL_DOMAINS_TO_RUN - DOMAINS_PROCESSED_THIS_RUN + 1))
        ETA_SECONDS=$((TIME_PER_DOMAIN * REMAINING_DOMAINS))
        ETA_FORMATTED=$(format_time $ETA_SECONDS)
        ETA_MSG="| ETA: ${ETA_FORMATTED}"
    else
        ETA_MSG=""
    fi
    
    echo -e "\n${YELLOW}======================================================================${NC}"
    echo -e "${YELLOW}[${DOMAINS_PROCESSED_THIS_RUN}/${TOTAL_DOMAINS_TO_RUN}] Procesando: ${domain} | Peticiones: ${REQUEST_COUNTER} ${ETA_MSG}${NC}"
    echo -e "${YELLOW}======================================================================${NC}"

    echo -e "${BLUE}[INFO] Obteniendo baseline para ${domain}...${NC}"
    ((REQUEST_COUNTER++)); baseline_response=$(curl -s -k --connect-timeout $CURL_TIMEOUT -A "$USER_AGENT" "https://${domain}")
    ((REQUEST_COUNTER++)); baseline_code=$(curl -o /dev/null -s -w "%{http_code}" -k "https://${domain}")
    
    if [[ "$baseline_code" == "000" ]]; then
        echo -e "${RED}[ERROR] No se pudo obtener respuesta base para ${domain}. Imposible comparar.${NC}"
        echo "${domain},NO_RESPONSE,N/A,N/A" >> "$OUTPUT_FILE"; echo "${domain}" >> "$PROGRESS_FILE"; continue
    fi
    
    if [[ "$baseline_code" == 2* ]]; then
        baseline_title=$(echo "$baseline_response" | grep -o -i '<title>.*</title>' | sed -e 's/<[^>]*>//g' | tr -d '\n' | awk '{$1=$1};1')
        baseline_title=${baseline_title:-"NO_TITLE_FOUND"}
        echo -e "${BLUE}[INFO] Baseline -> Código: ${baseline_code} | Título: '${baseline_title}'${NC}"
    else
        baseline_title=""
        echo -e "${BLUE}[INFO] Baseline -> Código: ${baseline_code}${NC}"
    fi

    found_ip_details=""
    IP_TEST_LIST=$( (printf "%s\n" "${HIGH_PRIORITY_IPS[@]}" "${SUCCESSFUL_IPS[@]}"; cat "$ALL_IPS_TEMP_FILE") | awk '!seen[$0]++' )
    
    for ip in $IP_TEST_LIST; do
        echo -ne "${BLUE}  -> Probando IP: ${ip}...${NC}\r"

        ((REQUEST_COUNTER++)); test_code=$(curl --resolve "${domain}:443:${ip}" -o /dev/null -s -w "%{http_code}" -k --connect-timeout $CURL_TIMEOUT -A "$USER_AGENT" "https://${domain}")
        
        match=false
        if [[ "$baseline_code" == "$test_code" ]] && [[ "$test_code" != "000" ]]; then
            if [[ "$baseline_code" == 2* ]]; then
                ((REQUEST_COUNTER++)); test_response=$(curl --resolve "${domain}:443:${ip}" -s -k --connect-timeout $CURL_TIMEOUT -A "$USER_AGENT" "https://${domain}")
                test_title=$(echo "$test_response" | grep -o -i '<title>.*</title>' | sed -e 's/<[^>]*>//g' | tr -d '\n' | awk '{$1=$1};1')
                test_title=${test_title:-"NO_TITLE_FOUND"}
                if [[ "$test_title" != "NO_TITLE_FOUND" && "$test_title" == "$baseline_title" ]]; then match=true; fi
            else
                match=true
            fi
        fi

        if $match; then
            echo -ne "\r\033[K"
            echo -e "${GREEN}[ÉXITO] Posible IP de origen encontrada para ${domain}: ${ip}${NC}"
            
            echo -e "${BLUE}  -> Realizando test de WAF en la IP de origen ${ip}...${NC}"
            ((REQUEST_COUNTER++)); clean_size=$(curl --resolve "${domain}:443:${ip}" -o /dev/null -s -w "%{size_download}" -k --connect-timeout $CURL_TIMEOUT -A "$USER_AGENT" "https://${domain}")
            
            payload_url="https://${domain}/${WAF_TEST_PAYLOAD}"
            ((REQUEST_COUNTER++)); waf_check_code=$(curl --resolve "${domain}:443:${ip}" -o /dev/null -s -w "%{http_code}" -k --connect-timeout $CURL_TIMEOUT -A "$USER_AGENT" "$payload_url")
            ((REQUEST_COUNTER++)); waf_check_size=$(curl --resolve "${domain}:443:${ip}" -o /dev/null -s -w "%{size_download}" -k --connect-timeout $CURL_TIMEOUT -A "$USER_AGENT" "$payload_url")

            waf_present="NO"
            if [[ "$test_code" != "$waf_check_code" ]] || [[ "$clean_size" != "$waf_check_size" ]]; then
                echo -e "${YELLOW}  -> [!] WAF DETECTADO. La respuesta cambió con el payload malicioso.${NC}"
                waf_present="SI"
            else
                echo -e "${GREEN}  -> [OK] No se detectó WAF. La respuesta fue idéntica.${NC}"
            fi

            found_ip_details="${domain},${ip},${waf_present},${baseline_code}"
            if [[ ! " ${SUCCESSFUL_IPS[@]} " =~ " ${ip} " ]]; then SUCCESSFUL_IPS+=("$ip"); fi
            break
        fi
    done

    echo -ne "\r\033[K"
    if [ -n "$found_ip_details" ]; then
        echo "$found_ip_details" >> "$OUTPUT_FILE"
    else
        echo -e "${RED}[FALLO] No se encontró IP de origen para ${domain}.${NC}"
        echo "${domain},NOT_FOUND,N/A,${baseline_code}" >> "$OUTPUT_FILE"
    fi
    echo "${domain}" >> "$PROGRESS_FILE"
done

END_TIME_TOTAL=$(date +%s)
TOTAL_EXECUTION_TIME=$((END_TIME_TOTAL - START_TIME_TOTAL))

echo -e "\n${YELLOW}======================================================================${NC}"
echo -e "${GREEN}Script finalizado en $(format_time $TOTAL_EXECUTION_TIME).${NC}"
echo -e "${GREEN}Se han realizado un total de ${REQUEST_COUNTER} peticiones.${NC}"
echo -e "${GREEN}Los resultados se han guardado en '${OUTPUT_FILE}'.${NC}"
echo -e "${YELLOW}======================================================================${NC}"

# Llamada a cleanup no es estrictamente necesaria aquí, pero es buena práctica
cleanup
