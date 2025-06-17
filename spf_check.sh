#!/bin/bash

TARGET_SPF_INCLUDE="include:spf.tmes.trendmicro.com"
DOMAINS_FILE="dominios.txt" # Nombre del archivo con tus dominios

if [ ! -f "$DOMAINS_FILE" ]; then
    echo "Error: El archivo '$DOMAINS_FILE' no existe."
    exit 1
fi

# Arrays para el resumen
declare -a domains_with_target_include
declare -a domains_spf_without_target_include
declare -a domains_no_spf_record # Tienen TXT pero ninguno es SPF
declare -a domains_no_txt_records
declare -a domains_dns_error

echo "--- Resultados Detallados de la Verificación SPF ---"

while IFS= read -r domain_line || [[ -n "$domain_line" ]]; do
    domain=$(echo "$domain_line" | xargs) # Limpiar espacios
    if [ -z "$domain" ]; then
        continue
    fi

    echo # Línea en blanco para separar dominios
    echo "Dominio: $domain"

    # +tcp para queries más largas, aunque TXT no suele ser tan largo, no daña.
    # +tries=1 +time=3 para evitar esperas largas en dominios que no responden
    # Usamos dig sin +short inicialmente para ver mejor los errores y la estructura.
    # Luego procesaremos las líneas relevantes.
    dig_output=$(dig TXT "$domain" +noall +answer +tries=1 +time=3)
    dig_exit_status=$? # Capturar el código de salida de dig

    # Inicializar flags para este dominio
    domain_has_spf_record=false
    target_found_in_domain=false
    all_txt_records_for_domain=""
    spf_records_found_for_domain=""


    if [ $dig_exit_status -ne 0 ]; then
        # Manejar errores de dig (NXDOMAIN, SERVFAIL, etc.)
        error_message="Error DNS"
        if [ $dig_exit_status -eq 9 ]; then # NXDOMAIN
            error_message="Dominio no existe (NXDOMAIN)"
        elif [ $dig_exit_status -eq 1 ]; then # Usage error / timeout con algunas versiones
             error_message="Timeout o error de consulta (revisar conectividad/DNS resolver)"
        else
            error_message="Error DNS (código $dig_exit_status)"
        fi
        echo "  $error_message"
        domains_dns_error+=("$domain ($error_message)")
        echo "-------------------------------------"
        continue
    fi

    if [ -z "$dig_output" ]; then
        echo "  No se encontraron registros TXT."
        domains_no_txt_records+=("$domain")
        echo "  '$TARGET_SPF_INCLUDE' presente: No (No hay TXT)"
        echo "-------------------------------------"
        continue
    fi

    # Procesar cada línea del output de dig +answer
    # Cada línea de TXT devuelta por dig +answer representa un registro TXT.
    # Si un registro TXT está dividido en múltiples "strings" en el DNS,
    # dig +answer los muestra como "string1" "string2" en la misma línea.
    
    # Primero, construimos all_txt_records_for_domain para mostrar si no hay SPF
    while IFS= read -r line; do
        # Extraer solo la parte de los datos del TXT (después de IN TXT)
        txt_data_part=$(echo "$line" | awk -F'IN\tTXT\t' '{print $2}')
        if [ -n "$txt_data_part" ]; then
             all_txt_records_for_domain+="${txt_data_part}\n"
        fi
    done <<< "$dig_output"


    # Ahora, iteramos de nuevo para analizar específicamente SPF
    while IFS= read -r line; do
        # Extraer solo la parte de los datos del TXT
        txt_data_part=$(echo "$line" | awk -F'IN\tTXT\t' '{print $2}')
        if [ -z "$txt_data_part" ]; then
            continue
        fi

        # Unir las cadenas si están separadas por comillas y espacios (ej: "v=spf1" " include:...")
        # Eliminar comillas y luego comprimir espacios múltiples
        full_txt_string=$(echo "$txt_data_part" | tr -d '"' | awk '{$1=$1};1')

        if [[ "$full_txt_string" == v=spf1* ]]; then
            domain_has_spf_record=true
            spf_records_found_for_domain+="    ${full_txt_string}\n" # Añadir con indentación

            if [[ "$full_txt_string" == *"$TARGET_SPF_INCLUDE"* ]]; then
                target_found_in_domain=true
                # No hacemos break aquí, por si hay múltiples SPF y queremos verlos todos
            fi
        fi
    done <<< "$dig_output"


    if [ "$domain_has_spf_record" = true ]; then
        echo "  Registro(s) SPF encontrado(s) (v=spf1...):"
        # printf para evitar que \n en la variable se interprete literalmente
        printf '%b' "$spf_records_found_for_domain"

        if [ "$target_found_in_domain" = true ]; then
            echo "  '$TARGET_SPF_INCLUDE' presente: Sí"
            domains_with_target_include+=("$domain")
        else
            echo "  '$TARGET_SPF_INCLUDE' presente: No (pero hay SPF)"
            domains_spf_without_target_include+=("$domain")
        fi
    else
        echo "  Registros TXT encontrados, pero ninguno parece ser un registro SPF (no comienza con 'v=spf1'):"
        # Mostramos todos los TXT para depuración, indentados
        printf '%b' "$all_txt_records_for_domain" | sed 's/^/    /'
        domains_no_spf_record+=("$domain")
        echo "  '$TARGET_SPF_INCLUDE' presente: No (No hay SPF)"
    fi
    echo "-------------------------------------"

done < "$DOMAINS_FILE"

echo # Línea en blanco al final
echo "--- RESUMEN DE VERIFICACIÓN ---"
echo

echo "Dominios CON '$TARGET_SPF_INCLUDE': (${#domains_with_target_include[@]})"
for d in "${domains_with_target_include[@]}"; do echo "  - $d"; done
echo

echo "Dominios CON SPF pero SIN '$TARGET_SPF_INCLUDE': (${#domains_spf_without_target_include[@]})"
for d in "${domains_spf_without_target_include[@]}"; do echo "  - $d"; done
echo

echo "Dominios CON TXT pero SIN registro SPF (v=spf1...): (${#domains_no_spf_record[@]})"
for d in "${domains_no_spf_record[@]}"; do echo "  - $d"; done
echo

echo "Dominios SIN NINGÚN registro TXT: (${#domains_no_txt_records[@]})"
for d in "${domains_no_txt_records[@]}"; do echo "  - $d"; done
echo

echo "Dominios CON ERRORES DNS (ej. no existe, timeout): (${#domains_dns_error[@]})"
for d in "${domains_dns_error[@]}"; do echo "  - $d"; done
echo

echo "--- Verificación completada ---"
