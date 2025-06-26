#!/bin/bash

# Opciones por defecto para el primer escaneo
DEFAULT_NMAP_OPTIONS="-sT -n -Pn -v -p- -T3"
CUSTOM_OPTIONS=()  # Aquí recogeremos las opciones personalizadas
CUSTOM_T_VALUE=""  # Para capturar posibles cambios del parámetro -T

# Variable global para controlar si el escaneo debe continuar o no.
ESCANEO_ACTIVO=true
SALTAR=false # Variable global para saltar el objetivo actual

# Función para combinar opciones personalizadas y predeterminadas
combinar_opciones() {
    local opciones="$DEFAULT_NMAP_OPTIONS"
    for opt in "${CUSTOM_OPTIONS[@]}"; do
        # Si la opción personalizada es -T, reemplaza la de por defecto
        if [[ $opt =~ ^-T[0-5]$ ]]; then
            CUSTOM_T_VALUE="$opt"  # Guardar el valor de -T para el segundo escaneo
            opciones=$(echo "$opciones" | sed 's/-T[0-5]//g') # Quita el -T default
        # Si la opción personalizada es -p, reemplaza la de por defecto (-p-)
        elif [[ $opt =~ ^-p ]]; then
            opciones=$(echo "$opciones" | sed 's/-p[^ ]*//g') # Quita el -p default
        # Si la opción personalizada es -sX, reemplaza la de por defecto (-sT)
        elif [[ $opt =~ ^-s[sAFTUVXY] ]]; then # Ajustado para tipos de scan comunes
            opciones=$(echo "$opciones" | sed 's/-s[sAFTUVXY]//g') # Quita el -s default
        fi
        # Añade la opción personalizada (o la que no fue reemplazada)
        opciones="$opciones $opt"
    done
    # Eliminar espacios extra
    echo "$opciones" | xargs
}

# Manejar SIGINT (Ctrl+C)
gestionar_ctrlc() {
    echo -e "\n\n[!] Capturado Ctrl+C. Seleccione una opción:"
    select opcion in "Terminar todos los escaneos" "Saltar objetivo actual" "Continuar escaneo actual"; do
        case $REPLY in
            1)
                echo "[*] Finalizando todos los escaneos..."
                ESCANEO_ACTIVO=false
                # Podríamos intentar matar procesos nmap hijos aquí si fuera necesario
                break
                ;;
            2)
                echo "[*] Señal para saltar el objetivo actual recibida..."
                SALTAR=true # La lógica principal del bucle manejará esto
                break
                ;;
            3)
                echo "[*] Cancelando menú, continuando escaneo actual..."
                break
                ;;
            *)
                echo "[!] Opción inválida, intente de nuevo."
                ;;
        esac
    done
}

# Mostrar barra de progreso
mostrar_barra_progreso() {
    local progreso=${1:-0} # Default a 0 si no se provee
    local eta=${2:-"Calculando..."}
    local largo=40  # Largo de la barra
    # Asegurarse que progreso es un número antes de usar bc
    if ! [[ "$progreso" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
        progreso=0
    fi
    local progreso_entero=$(printf "%.0f" "$progreso")
    # Asegurarse que progreso_entero no exceda 100
    [[ "$progreso_entero" -gt 100 ]] && progreso_entero=100

    local rellenado=$(printf "%.0f" "$(echo "$largo * $progreso_entero / 100" | bc -l)")
    local vacio=$((largo - rellenado))
    # Asegurarse que rellenado y vacio no sean negativos
    [[ "$rellenado" -lt 0 ]] && rellenado=0
    [[ "$vacio" -lt 0 ]] && vacio=0

    local barra=$(printf "%-${rellenado}s" "#" | tr ' ' '#')
    local espacio=$(printf "%-${vacio}s" " ")
    # Limpiar línea con \r y K para evitar artefactos
    echo -ne "\r\033[K[${barra}${espacio}] ${progreso_entero}% (ETA: $eta) "
}


# Mostrar la ayuda
mostrar_ayuda() {
    echo "Uso: nmaplus [OPCIONES_NMAP] [OBJETIVOS...]"
    echo ""
    echo "Descripción:"
    echo "    Herramienta automatizada para realizar escaneos Nmap a varios objetivos"
    echo "    (IPs, nombres de host, URLs) centrada en los puertos abiertos,"
    echo "    con opciones de cancelación e indicación de progreso."
    echo ""
    echo "Parámetros:"
    echo "    --help              Muestra esta ayuda y sale."
    echo ""
    echo "    Opciones personalizables de Nmap:"
    echo "        Al añadir opciones personalizadas, estas afectarán los parámetros predeterminados"
    echo "        (-sT, -p-, -T3) si son del mismo tipo (ej. -sS, -p80, -T4)."
    echo "        Otras opciones (ej. --script, -A) se añadirán."
    echo "        Ejemplo: '-T1 -sS -p80,443 --script=vuln'."
    echo ""
    echo "    OBJETIVOS...        Lista de IPs, nombres de host o URLs a escanear, separados por espacios."
    echo ""
    echo "Predeterminadas (si no se especifican personalizadas):"
    echo "    - Primer escaneo: $DEFAULT_NMAP_OPTIONS"
    echo "    - Segundo escaneo: -sVC -n -Pn -v (sobre los puertos detectados)."
    echo ""
    echo "Dependencias: nmap, bc"
    echo ""
    exit 0
}

# Captura Ctrl+C
trap gestionar_ctrlc SIGINT

# Verificar si se pide ayuda
if [[ "$1" == "--help" ]]; then
    mostrar_ayuda
fi

# Procesar opciones personalizadas de Nmap
while [[ $1 == -* ]]; do
    CUSTOM_OPTIONS+=("$1")
    # Manejar opciones que requieren un argumento (simple ejemplo)
    case "$1" in
        -p|--exclude-ports|--exclude|--script|--script-args|-o*|--stylesheet|--datadir)
            shift
            # Asegurarse de que hay un argumento siguiente
            if [[ -n "$1" ]] && [[ "$1" != -* ]]; then
                CUSTOM_OPTIONS+=("$1")
            else
                echo "[!] Opción $1 requiere un argumento."
                # Devolver el argumento desplazado si no era para la opción
                [[ -n "$1" ]] && [[ "$1" == -* ]] && set -- "$1" "${@:2}"
                # Opcional: salir si falta argumento
                # exit 1
            fi
            ;;
        # Añadir más casos si es necesario para otras opciones con argumentos
    esac
    shift # Mover al siguiente argumento
    # Salir del bucle si no quedan argumentos
    if [ $# -eq 0 ]; then
        break
    fi
done


# Verificar si quedan objetivos
if [ $# -eq 0 ]; then
    echo "[!] No se proporcionaron objetivos (IPs/URLs). Usa --help para más información."
    exit 1
fi
TARGETS=("$@") # Usar TARGETS en lugar de IPS

# Crear carpeta de resultados
mkdir -p nmap_results

# Seleccionar las opciones combinadas para el primer escaneo
PRIMER_ESCANEO_OPCIONES=$(combinar_opciones)

# Propagar el valor de -T al segundo escaneo si se ha modificado
# Asegurar que -n y -Pn estén presentes si no se anularon globalmente (considerar caso de uso)
SEGUNDO_ESCANEO_OPCIONES="-sVC -n -Pn -v ${CUSTOM_T_VALUE}"
# Limpiar espacios extra en las opciones del segundo escaneo
SEGUNDO_ESCANEO_OPCIONES=$(echo "$SEGUNDO_ESCANEO_OPCIONES" | xargs)

# Procesar cada Objetivo
total_targets=${#TARGETS[@]}
target_actual=0

for TARGET in "${TARGETS[@]}"; do
    ((target_actual++))
    SALTAR=false # Resetear flag de salto para cada objetivo

    if ! $ESCANEO_ACTIVO; then
        echo "[*] Escaneo global finalizado por el usuario."
        break # Salir del bucle principal
    fi

    # Sanitizar el nombre del objetivo para usarlo en nombres de archivo
    sanitized_target=$(echo "$TARGET" | sed 's|/|_|g' | sed 's|:|_|g') # Reemplaza / y : con _
    output_file_base="nmap_results/${sanitized_target}"
    nmap_output_file="${output_file_base}_full_scan.nmap"
    detailed_output_prefix="${output_file_base}_detailed_scan"


    echo ""
    echo "[*] Iniciando Objetivo: $TARGET ($target_actual/$total_targets)"
    inicio_ts=$(date +%s) # Timestamp para cálculo de duración
    inicio_fmt=$(date "+%Y-%m-%d %H:%M:%S")
    echo "[*] Hora de inicio: $inicio_fmt"

    # --- PRIMER ESCANEO ---
    echo "[+] Iniciando primer escaneo (descubrimiento de puertos): $PRIMER_ESCANEO_OPCIONES $TARGET"
    # Limpiar la barra de progreso anterior
    mostrar_barra_progreso 0 "Iniciando..."

    # Ejecutar Nmap y procesar su salida para la barra de progreso
    # Usamos 'script' o 'unbuffer' si la barra no se actualiza debido al buffering de Nmap
    # Alternativa: Ejecutar en segundo plano y usar --stats-every
    nmap_pid=0
    coproc NMAP_PROC { nmap $PRIMER_ESCANEO_OPCIONES "$TARGET" -oN "$nmap_output_file"; }
    nmap_pid=$!

    # Monitorear la salida de NMAP_PROC para progreso
    progreso_entero=0
    eta="Calculando..."
    while IFS= read -r linea <&${NMAP_PROC[0]}; do
        # Comprobar si hay que saltar (puede ser activado por Ctrl+C)
        if $SALTAR; then
            echo -e "\n[!] Saltando escaneo de $TARGET por solicitud del usuario."
            # Intentar terminar el proceso Nmap actual
            if kill -0 $nmap_pid 2>/dev/null; then
                 kill $nmap_pid 2>/dev/null
                 wait $nmap_pid 2>/dev/null # Esperar a que termine
            fi
            break # Salir del bucle de lectura de salida
        fi

        # Extraer porcentaje de progreso
        if [[ "$linea" =~ ([0-9]+\.[0-9]+)%\ done ]]; then
            progreso=${BASH_REMATCH[1]}
            progreso_entero=$(printf "%.0f" "$progreso")
        fi
        # Extraer ETA (expresión regular corregida)
        if [[ "$linea" =~ \((.*)\s+remaining\) ]]; then
            eta=${BASH_REMATCH[1]}
        elif [[ "$linea" =~ "Estimating completion time:" ]]; then
             # Otra posible forma en que Nmap muestra ETA
             eta=$(echo "$linea" | sed -n 's/.*ETA \(.*\))/\1/p')
        fi
        mostrar_barra_progreso $progreso_entero "$eta"

        # Opcional: Imprimir otras líneas de Nmap si se desea
        # echo "$linea" # Cuidado: puede interferir con la barra de progreso

    done
    wait $nmap_pid # Asegurarse de que Nmap termine
    nmap_exit_status=$?
    echo "" # Nueva línea después de la barra de progreso

    # --- Comprobaciones Post-Primer Escaneo ---

    # Si se activó el salto DURANTE el escaneo
    if $SALTAR; then
        echo "[*] Salto confirmado para $TARGET."
        # Asegurarse que no queden restos de la barra
        echo -ne "\r\033[K"
        continue # Pasar al siguiente objetivo en el bucle 'for'
    fi

    # Si el escaneo fue cancelado globalmente
    if ! $ESCANEO_ACTIVO; then
        echo "[*] Escaneo global detenido."
        # Asegurarse que no queden restos de la barra
        echo -ne "\r\033[K"
        break # Salir del bucle 'for'
    fi

    # Comprobar si Nmap falló
    if [ $nmap_exit_status -ne 0 ]; then
         echo "[!] El primer escaneo de Nmap para $TARGET falló con código de salida $nmap_exit_status."
         # Opcional: Mostrar últimas líneas del archivo .nmap si existe
         if [ -f "$nmap_output_file" ]; then
             echo "[!] Últimas líneas de $nmap_output_file:"
             tail -n 5 "$nmap_output_file"
         fi
         continue # Pasar al siguiente objetivo
    fi

    # Verificar si el archivo de salida se creó
    if [ ! -f "$nmap_output_file" ]; then
        echo "[!] No se encontró el archivo de resultados del primer escaneo: $nmap_output_file"
        continue # Pasar al siguiente objetivo
    fi

    # --- EXTRACCIÓN DE PUERTOS ---
    echo "[+] Extrayendo puertos abiertos de $nmap_output_file..."
    OPEN_PORTS=$(grep -oP '^\d+/tcp\s+open' "$nmap_output_file" | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//')

    if [ -z "$OPEN_PORTS" ]; then
        echo "[!] No se encontraron puertos TCP abiertos en $TARGET."
        fin_ts=$(date +%s)
        duracion=$((fin_ts - inicio_ts))
        echo "[*] Escaneo de $TARGET finalizado (sin puertos abiertos) en $(($duracion / 60)) min y $(($duracion % 60)) seg."
        continue # Pasar al siguiente objetivo
    fi

    echo "[+] Puertos TCP abiertos detectados: $OPEN_PORTS"

    # --- SEGUNDO ESCANEO ---
    echo "[+] Iniciando segundo escaneo detallado (Servicios/Versiones): $SEGUNDO_ESCANEO_OPCIONES -p$OPEN_PORTS $TARGET"
    # Ejecutar el segundo escaneo. -oA guarda en .nmap, .gnmap, y .xml
    nmap $SEGUNDO_ESCANEO_OPCIONES -p"$OPEN_PORTS" "$TARGET" -oA "$detailed_output_prefix"
    nmap_detailed_exit_status=$?

    if [ $nmap_detailed_exit_status -ne 0 ]; then
        echo "[!] El segundo escaneo (detallado) de Nmap para $TARGET falló con código de salida $nmap_detailed_exit_status."
    else
        echo "[+] Segundo escaneo completado. Resultados guardados como ${detailed_output_prefix}.*"
    fi

    fin_ts=$(date +%s)
    duracion=$((fin_ts - inicio_ts))
    echo "[*] Escaneo completo de $TARGET finalizado en $(($duracion / 60)) minutos y $(($duracion % 60)) segundos."

done

echo ""
if $ESCANEO_ACTIVO; then
    echo "[+] Todos los objetivos procesados. Resultados en 'nmap_results/'"
else
    echo "[*] Proceso de escaneo interrumpido por el usuario. Resultados parciales en 'nmap_results/'"
fi

# Limpiar el trap al salir
trap - SIGINT
exit 0
