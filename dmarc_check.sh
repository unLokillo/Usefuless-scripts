#!/bin/bash

DOMAINS_FILE="dominios_dmarc.txt"
ERROR_LOG_FILE="dmarc_parsing_errors.txt" # Para errores de parseo inesperados

# Opcional: Limpiar el archivo de errores al inicio
# > "$ERROR_LOG_FILE"

if [ ! -f "$DOMAINS_FILE" ]; then
    echo "Error: El archivo '$DOMAINS_FILE' no existe."
    exit 1
fi

# Arrays para el resumen
declare -a domains_dmarc_valid
declare -a domains_dmarc_txt_present_invalid_format # Tiene TXT pero v= o p= mal
declare -a domains_dmarc_is_cname # _dmarc es un CNAME
declare -a domains_dmarc_exists_no_txt # _dmarc existe pero no tiene TXT
declare -a domains_dmarc_subdomain_nxdomain # _dmarc.dominio NO existe
declare -a domains_dmarc_dns_other_error # Otros errores DNS

echo "--- Resultados Detallados de la Verificación DMARC ---"

while IFS= read -r domain_line || [[ -n "$domain_line" ]]; do
    domain=$(echo "$domain_line" | xargs)
    if [ -z "$domain" ]; then
        continue
    fi

    dmarc_subdomain="_dmarc.$domain"

    echo # Línea en blanco
    echo "Dominio: $domain (consultando $dmarc_subdomain)"

    # Paso 1: Verificar si _dmarc es un CNAME
    cname_output=$(dig CNAME "$dmarc_subdomain" +noall +answer +short +tries=1 +time=3)

    if [ -n "$cname_output" ]; then
        echo "  Alerta: $dmarc_subdomain es un CNAME apuntando a '$cname_output'."
        echo "  Esto es una configuración DMARC inválida."
        domains_dmarc_is_cname+=("$domain")
        echo "-------------------------------------"
        continue
    fi

    # Paso 2: Si no es CNAME, proceder a buscar TXT
    dig_output_txt=$(dig TXT "$dmarc_subdomain" +noall +answer +tries=1 +time=5)
    dig_exit_status_txt=$?
    
    if [ $dig_exit_status_txt -ne 0 ]; then
        if [ $dig_exit_status_txt -eq 9 ]; then # NXDOMAIN para _dmarc
            echo "  Error: El subdominio $dmarc_subdomain no existe (NXDOMAIN)."
            domains_dmarc_subdomain_nxdomain+=("$domain")
        else # Otros errores de dig al buscar TXT
            error_message="Error DNS para $dmarc_subdomain al buscar TXT (código $dig_exit_status_txt)"
            echo "  $error_message"
            domains_dmarc_dns_other_error+=("$domain")
        fi
        echo "-------------------------------------"
        continue
    fi

    # Si dig_exit_status_txt es 0 (éxito) pero dig_output_txt está vacío, _dmarc existe pero no tiene TXT.
    if [ -z "$dig_output_txt" ]; then
        echo "  Alerta: El subdominio $dmarc_subdomain existe pero no tiene registros TXT."
        domains_dmarc_exists_no_txt+=("$domain")
        echo "-------------------------------------"
        continue
    fi

    # Si llegamos aquí, dig TXT tuvo éxito Y devolvió algo.
    first_line_of_dig_output_txt=$(echo "$dig_output_txt" | head -n 1)
    txt_data_part=$(echo "$first_line_of_dig_output_txt" | awk -F'IN\tTXT\t' '{print $2}')

    if [ -z "$txt_data_part" ]; then
        # Este caso debería ser menos común ahora que manejamos CNAMEs y NXDOMAINs antes.
        # Podría ser un formato de TXT muy extraño que awk no parsea.
        echo "  Error Inesperado: Se obtuvo respuesta TXT de dig, pero no se pudo extraer la sección de datos."
        echo "         Salida cruda de dig (primera línea TXT): $first_line_of_dig_output_txt"
        domains_dmarc_txt_present_invalid_format+=("$domain") # Lo ponemos aquí como formato inválido
        
        echo "--- Error de Parseo Inesperado para: $dmarc_subdomain ---" >> "$ERROR_LOG_FILE"
        echo "Fecha: $(date)" >> "$ERROR_LOG_FILE"
        echo "Salida completa de dig TXT (puede ser multilínea):" >> "$ERROR_LOG_FILE"
        echo "$dig_output_txt" >> "$ERROR_LOG_FILE"
        echo "--- Fin Error ---" >> "$ERROR_LOG_FILE"
        echo "" >> "$ERROR_LOG_FILE"
        
        echo "-------------------------------------"
        continue
    fi

    dmarc_record_content=$(echo "$txt_data_part" | tr -d '"' | awk '{$1=$1};1')
    
    echo "  Registro TXT encontrado en $dmarc_subdomain:"
    echo "    Contenido: $dmarc_record_content"

    if echo "$dmarc_record_content" | grep -qE '^v=DMARC1\s*;' && \
       echo "$dmarc_record_content" | grep -iqE 'p\s*=\s*(none|quarantine|reject)'; then
        echo "  Estado DMARC: Válido"
        domains_dmarc_valid+=("$domain")
    else
        echo "  Estado DMARC: TXT presente pero formato Inválido/Incompleto (no cumple v=DMARC1; y/o política p= válida)"
        domains_dmarc_txt_present_invalid_format+=("$domain")
    fi
    echo "-------------------------------------"

done < "$DOMAINS_FILE"

# --- RESUMEN ---
echo # Línea en blanco al final
echo "--- RESUMEN DE VERIFICACIÓN DMARC ---"
echo

echo "Dominios CON DMARC VÁLIDO (TXT en _dmarc, v=DMARC1; y p=...): (${#domains_dmarc_valid[@]})"
for d in "${domains_dmarc_valid[@]}"; do echo "  - $d"; done
echo

echo "Dominios CON TXT en _dmarc PERO DMARC CON FORMATO INVÁLIDO/INCOMPLETO: (${#domains_dmarc_txt_present_invalid_format[@]})"
# (Esto incluye errores de parseo de TXT y fallos en v=DMARC1 o p=)
for d in "${domains_dmarc_txt_present_invalid_format[@]}"; do echo "  - $d"; done
if grep -q "Error de Parseo Inesperado" "$ERROR_LOG_FILE" 2>/dev/null; then # Si hubo errores de parseo guardados
    echo "  (Algunos pueden tener detalles de error de parseo inesperado en '$ERROR_LOG_FILE')"
fi
echo

echo "Dominios donde _dmarc ES UN CNAME (Inválido para DMARC): (${#domains_dmarc_is_cname[@]})"
for d in "${domains_dmarc_is_cname[@]}"; do echo "  - $d"; done
echo

echo "Dominios donde _dmarc EXISTE PERO NO TIENE REGISTROS TXT: (${#domains_dmarc_exists_no_txt[@]})"
for d in "${domains_dmarc_exists_no_txt[@]}"; do echo "  - $d"; done
echo

echo "Dominios donde el subdominio _dmarc NO EXISTE (NXDOMAIN): (${#domains_dmarc_subdomain_nxdomain[@]})"
for d in "${domains_dmarc_subdomain_nxdomain[@]}"; do echo "  - $d"; done
echo

echo "Dominios CON OTROS ERRORES DNS al consultar _dmarc: (${#domains_dmarc_dns_other_error[@]})"
for d in "${domains_dmarc_dns_other_error[@]}"; do echo "  - $d"; done
echo

# Comprobar si se escribió algo en el log de errores de parseo inesperados
# grep -q devolverá 0 (true) si encuentra la cadena, 1 (false) si no.
# 2>/dev/null es para silenciar el error de grep si el archivo no existe la primera vez.
if grep -q "Error de Parseo Inesperado para:" "$ERROR_LOG_FILE" 2>/dev/null ; then
    echo "Se han registrado errores de parseo de DMARC inesperados en el archivo: $ERROR_LOG_FILE"
fi
echo "--- Verificación completada ---"
