#!/bin/bash

# ==============================================================================
# Script: check_waf.sh
# Descripción: Comprueba el WAF de una lista de dominios utilizando wafw00f.
# Autor: Tu Nombre/Compañía
# Fecha: [Fecha Actual]
#
# Uso: ./check_waf.sh
#
# El script lee dominios desde 'Domain_list.txt' y muestra el nombre del WAF
# o 'NO_WAF' si no se detecta ninguno.
# ==============================================================================

# Fichero de entrada con la lista de dominios
INPUT_FILE="Domain_list.txt"

# Fichero de salida para guardar los resultados
OUTPUT_FILE="waf_results.txt"

# --- Validaciones iniciales ---

# 1. Comprobar si wafw00f está instalado
if ! command -v wafw00f &> /dev/null; then
    echo "Error: El comando 'wafw00f' no se encuentra."
    echo "Por favor, instálalo con: pip install wafw00f"
    exit 1
fi

# 2. Comprobar si el fichero de dominios existe
if [ ! -f "$INPUT_FILE" ]; then
    echo "Error: El fichero de entrada '$INPUT_FILE' no existe."
    echo "Por favor, crea el fichero con un dominio por línea."
    exit 1
fi

# Limpiar el fichero de resultados si ya existe
> "$OUTPUT_FILE"

echo "Iniciando la comprobación de WAF para los dominios en '$INPUT_FILE'..."
echo "Los resultados se guardarán en '$OUTPUT_FILE'."
echo "----------------------------------------------------"

# --- Bucle principal ---

# Leer cada línea (dominio) del fichero de entrada
while IFS= read -r domain || [[ -n "$domain" ]]; do
    # Ignorar líneas vacías o comentadas
    if [[ -z "$domain" ]] || [[ "$domain" =~ ^# ]]; then
        continue
    fi

    echo "Analizando: $domain"

    # Ejecutar wafw00f y procesar la salida con sed para extraer la información clave.
    # -a: No se detiene en la primera coincidencia, busca todas las posibles.
    # sed -n: No imprime nada por defecto.
    # 1ª regla: Si encuentra "is behind", extrae el nombre del WAF (la palabra que sigue) y lo imprime.
    # 2ª regla: Si encuentra "No WAF detected", imprime "NO_WAF".
    # El resultado se guarda en la variable 'waf_result'.
    waf_result=$(wafw00f -a "$domain" | sed -n -e 's/.*is behind \([^ (]*\).*/\1/p' -e 's/.*No WAF detected.*/NO_WAF/p' -e 's/.*seems to be behind a WAF.*/UNKNOWN_WAF/p')

    # Si después del procesamiento, la variable está vacía, es que hubo un error o un resultado inesperado.
    if [[ -z "$waf_result" ]]; then
        result_line="ERROR_ANALIZANDO"
    else
        # wafw00f a veces devuelve múltiples líneas si encuentra más de una coincidencia.
        # Nos quedamos solo con la primera línea del resultado para asegurar una salida limpia.
        result_line=$(echo "$waf_result" | head -n 1)
    fi

    # Escribir el resultado en el fichero de salida
    echo "$domain: $result_line" >> "$OUTPUT_FILE"
    echo "  -> Resultado: $result_line"

done < "$INPUT_FILE"

echo "----------------------------------------------------"
echo "¡Análisis completado!"
echo "Resultados guardados en '$OUTPUT_FILE'."
