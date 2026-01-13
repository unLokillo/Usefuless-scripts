#!/usr/bin/env python3

# shcheck - Security headers check!
# Copyright (C) 2019-2021  santoru
# Modifications for Spanish translation and policy updates (2024)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


import urllib.request
import urllib.error
import urllib.parse
import http.client
import socket
import sys
import ssl
import os
import json
from optparse import OptionParser

# --- Language Strings ---

LANG_STRINGS_EN = {
    "banner_title": "> shcheck.py - santoru ..............................",
    "banner_subtitle": " Simple tool to check security headers on a webserver ",
    "unknown_url_type": "Unknown url type",
    "http_error": "[!] URL Returned an HTTP error: {}",
    "ssl_error": "SSL: Certificate validation error.\nIf you want to ignore it run the program with the \"-d\" option.",
    "unreachable_host": "Target host {} seems to be unreachable ({})",
    "unknown_protocol": "Unknown protocol: {}. Are you using a proxy? Try disabling it",
    "cant_read_response": "Couldn't read a response from server.",
    "analyzing_headers": "[*] Analyzing headers of {}",
    "effective_url": "[*] Effective URL: {}",
    "header_present": "[*] Header {} is present! (Value: {})",
    "header_present_no_value": "[*] Header {} is present!",
    "csp_value": "Value:",
    "insecure_referrer": "[!] Insecure header {} is set! (Value: {})",
    "insecure_hsts": "[!] Insecure header {} is set! (Value: {})",
    "missing_header": "[!] Missing security header: {}",
    "obsolete_header_present": "[!] Obsolete header {} is present! (Value: {})",
    "info_disclosure_present": "[!] Possible information disclosure: header {} is present! (Value: {})",
    "no_info_disclosure": "[*] No information disclosure headers detected",
    "cache_header_present": "[!] Cache control header {} is present! (Value: {})",
    "no_cache_headers": "[*] No caching headers detected",
    "report_analyzed_for": "[!] Headers analyzed for {}",
    "report_safe": "[+] There are {} security headers",
    "report_unsafe": "[-] There are not {} security headers",
    "invalid_header_format": "[!] Header strings must be of the format 'Header: value'",
    "usage": "Usage: %prog [options] <target>",
    "option_port": "Set a custom port to connect to",
    "option_cookie": "Set cookies for the request",
    "option_add_header": "Add headers for the request e.g. 'Header: value'",
    "option_disable_ssl": "Disable SSL/TLS certificate validation",
    "option_use_get": "Use GET method instead HEAD method",
    "option_use_method": "Use a specified method",
    "option_json": "Print the output in JSON format",
    "option_information": "Display information headers",
    "option_caching": "Display caching headers",
    "option_deprecated": "Display deprecated headers (like Expect-CT)",
    "option_proxy": "Set a proxy (Ex: http://127.0.0.1:8080)",
    "option_hfile": "Load a list of hosts from a flat file",
    "option_colours": "Set up a colour profile [dark/light/none]",
    "option_colors_alias": "Alias for colours for US English",
    "option_language": "Set output language [en/es]",
}

LANG_STRINGS_ES = {
    "banner_title": "> shcheck.py - santoru ..............................",
    "banner_subtitle": " Herramienta simple para comprobar cabeceras de seguridad ",
    "unknown_url_type": "Tipo de URL desconocido",
    "http_error": "[!] La URL devolvió un error HTTP: {}",
    "ssl_error": "SSL: Error de validación de certificado.\nSi quieres ignorarlo, ejecuta el programa con la opción \"-d\".",
    "unreachable_host": "El host de destino {} parece inaccesible ({})",
    "unknown_protocol": "Protocolo desconocido: {}. ¿Estás usando un proxy? Intenta desactivarlo",
    "cant_read_response": "No se pudo leer una respuesta del servidor.",
    "analyzing_headers": "[*] Analizando cabeceras de {}",
    "effective_url": "[*] URL efectiva: {}",
    "header_present": "[*] ¡Cabecera {} presente! (Valor: {})",
    "header_present_no_value": "[*] ¡Cabecera {} presente!",
    "csp_value": "Valor:",
    "insecure_referrer": "[!] ¡Cabecera insegura {} establecida! (Valor: {})",
    "insecure_hsts": "[!] ¡Cabecera insegura {} establecida! (Valor: {})",
    "missing_header": "[!] Falta cabecera de seguridad: {}",
    "obsolete_header_present": "[!] ¡Cabecera obsoleta {} presente! (Valor: {})",
    "info_disclosure_present": "[!] Posible divulgación de información: ¡cabecera {} presente! (Valor: {})",
    "no_info_disclosure": "[*] No se detectaron cabeceras de divulgación de información",
    "cache_header_present": "[!] ¡Cabecera de control de caché {} presente! (Valor: {})",
    "no_cache_headers": "[*] No se detectaron cabeceras de caché",
    "report_analyzed_for": "[!] Cabeceras analizadas para {}",
    "report_safe": "[+] Hay {} cabeceras de seguridad",
    "report_unsafe": "[-] No hay {} cabeceras de seguridad",
    "invalid_header_format": "[!] Las cadenas de cabecera deben tener el formato 'Cabecera: valor'",
    "usage": "Uso: %prog [opciones] <objetivo>",
    "option_port": "Establecer un puerto personalizado para conectar",
    "option_cookie": "Establecer cookies para la petición",
    "option_add_header": "Añadir cabeceras para la petición, ej: 'Cabecera: valor'",
    "option_disable_ssl": "Desactivar la validación de certificados SSL/TLS",
    "option_use_get": "Usar método GET en lugar de HEAD",
    "option_use_method": "Usar un método específico",
    "option_json": "Imprimir la salida en formato JSON",
    "option_information": "Mostrar cabeceras informativas",
    "option_caching": "Mostrar cabeceras de caché",
    "option_deprecated": "Mostrar cabeceras obsoletas (como Expect-CT)",
    "option_proxy": "Establecer un proxy (Ej: http://127.0.0.1:8080)",
    "option_hfile": "Cargar una lista de hosts desde un archivo plano",
    "option_colours": "Configurar un perfil de color [dark/light/none]",
    "option_colors_alias": "Alias para colours (colores)",
    "option_language": "Establecer idioma de salida [en/es]",
}

# Global language dictionary holder
STRINGS = LANG_STRINGS_EN

# Helper function for translation
def _t(key, *args):
    """Gets the translated string for the key."""
    return STRINGS.get(key, key).format(*args)


# --- Colors ---

class darkcolours:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class lightcolours:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[95m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


# --- Global Variables ---
options = None
headers = {}
json_headers = {} # For JSON output

# --- Functions ---

# log - prints unless JSON output is set
def log(string):
    if options and options.json_output:
        return
    print(string)


# Client headers to send to the server during the request.
client_headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:53.0)\
 Gecko/20100101 Firefox/53.0',
    'Accept': 'text/html,application/xhtml+xml,\
 application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US;q=0.8,en;q=0.3',
    'Upgrade-Insecure-Requests': '1'
 }


# Security headers that should be enabled
# Severity levels: 'error', 'warning', 'deprecated'
sec_headers = {
    'X-XSS-Protection': 'warning',  # Obsolete, show warning if missing OR present
    'X-Frame-Options': 'warning',   # Obsolete, show warning if missing OR present
    'X-Content-Type-Options': 'warning',
    'Strict-Transport-Security': 'error',
    'Content-Security-Policy': 'warning',
    'X-Permitted-Cross-Domain-Policies': 'deprecated',
    'Referrer-Policy': 'warning',
    'Expect-CT': 'deprecated',
    'Permissions-Policy': 'warning',
}

information_headers = {
    'X-Powered-By',
    'Server',
    'X-AspNet-Version',
    'X-AspNetMvc-Version'
}

cache_headers = {
    'Cache-Control',
    'Pragma',
    'Last-Modified',
    'Expires',
    'ETag'
}


def colorize(string, alert):
    bcolors = darkcolours
    if options.colours == "light":
        bcolors = lightcolours
    elif options.colours == "none":
        return string
    color = {
        'error':    bcolors.FAIL + string + bcolors.ENDC,
        'warning':  bcolors.WARNING + string + bcolors.ENDC,
        'ok':       bcolors.OKGREEN + string + bcolors.ENDC,
        'info':     bcolors.OKBLUE + string + bcolors.ENDC,
        'deprecated': string
    }
    return color[alert] if alert in color else string


def parse_headers(hdrs):
    global headers
    headers = dict((x.lower(), y) for x, y in hdrs)


def append_port(target, port):
    if not target.endswith('/'):
        target += '/'
    parts = urllib.parse.urlparse(target)
    netloc_parts = parts.netloc.split(':')
    new_netloc = netloc_parts[0] + ':' + port
    new_target = urllib.parse.urlunparse((parts.scheme, new_netloc, parts.path, parts.params, parts.query, parts.fragment))
    if target.endswith('/') and not new_target.endswith('/'):
         new_target += '/'
    elif not parts.path and not new_target.endswith('/'):
         new_target += '/'
    return new_target


def build_opener(proxy, ssldisabled):
    handlers = []
    if proxy:
        proxyhnd = urllib.request.ProxyHandler({
            'http':  proxy,
            'https': proxy
        })
        handlers.append(proxyhnd)

    ctx = None
    if ssldisabled:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    sslhnd = urllib.request.HTTPSHandler(context=ctx) if ssldisabled else urllib.request.HTTPSHandler()
    handlers.append(sslhnd)

    handlers.append(urllib.request.HTTPHandler)

    opener = urllib.request.build_opener(*handlers)
    urllib.request.install_opener(opener)


def normalize(target):
    if not urllib.parse.urlparse(target).scheme:
        parts = target.split(':')
        host = parts[0]
        try:
            socket.inet_pton(socket.AF_INET6, host)
            target = 'http://' + target
        except (ValueError, socket.error):
            try:
                socket.inet_aton(host)
                target = 'http://' + target
            except (ValueError, socket.error):
                 if '.' in host:
                     target = 'http://' + target
    return target


def print_error(target, e):
    sys.stdout = sys.__stdout__
    if isinstance(e, ValueError):
        print(_t("unknown_url_type"))

    elif isinstance(e, urllib.error.HTTPError):
        print(_t("http_error", colorize(str(e.code), 'error')))

    elif isinstance(e, urllib.error.URLError):
        if hasattr(e.reason, 'errno') and e.reason.errno == 111:
             print(_t("unreachable_host", target, f"Connection refused ({e.reason})"))
        elif "CERTIFICATE_VERIFY_FAILED" in str(e.reason):
            print(_t("ssl_error"))
        else:
            print(_t("unreachable_host", target, e.reason))
    elif isinstance(e, http.client.UnknownProtocol):
         print(_t("unknown_protocol", e))
    elif isinstance(e, socket.gaierror):
        print(_t("unreachable_host", target, f"Name or service not known ({e})"))
    elif isinstance(e, socket.timeout):
        print(f"[!] Timeout connecting to {target}")
    else:
        print("{}".format(str(e)))


def check_target(target):
    ssldisabled = options.ssldisabled
    useget = options.useget
    usemethod = options.usemethod
    proxy = options.proxy
    response = None

    target = normalize(target)

    request = urllib.request.Request(target, headers=client_headers)
    method = "GET" if useget else usemethod
    if not useget and usemethod != 'HEAD':
        method = usemethod.upper()
    request.get_method = lambda: method

    build_opener(proxy, ssldisabled)
    try:
        response = urllib.request.urlopen(request, timeout=15)
    except http.client.UnknownProtocol as e:
        print_error(target, e)
        return None
    except Exception as e:
        print_error(target, e)
        if hasattr(e, 'code') and isinstance(e, urllib.error.HTTPError):
            response = e
        else:
            return None

    if response is not None:
        if not hasattr(response, 'getheaders'):
             log(_t("cant_read_response"))
             return None
        return response

    log(_t("cant_read_response"))
    return None


def is_https(target_url):
    return urllib.parse.urlparse(target_url).scheme == 'https'


def report(target_url, safe, unsafe):
    log("-------------------------------------------------------")
    log(_t("report_analyzed_for", colorize(target_url, 'info')))
    log(_t("report_safe", colorize(str(safe), 'ok')))
    log(_t("report_unsafe", colorize(str(unsafe), 'error')))
    log("")

def parse_csp(csp_value):
    unsafe_keywords = ['unsafe-inline', 'unsafe-eval', 'unsafe-hashes', 'wasm-unsafe-eval']
    warn_keywords = ["'self'", "'none'", "data:", "blob:", "filesystem:", "mediastream:", "*", "http:"]
    log(_t("csp_value"))
    directives = csp_value.split(";")
    for directive in directives:
        parts = directive.strip().split(None, 1)
        if not parts:
            continue
        directive_name = parts[0]
        values_str = parts[1] if len(parts) > 1 else ""

        colored_values = []
        for value in values_str.split():
            value_lower = value.lower()
            if value_lower in unsafe_keywords:
                colored_values.append(colorize(value, 'error'))
            elif value_lower in warn_keywords or ('*' in value and value_lower != "'*'") :
                 colored_values.append(colorize(value, 'warning'))
            else:
                colored_values.append(value)

        log("\t" + colorize(directive_name, 'info') + (": " + " ".join(colored_values) if colored_values else ""))


def main():
    global options, STRINGS, json_headers

    options, targets = parse_options()

    if options.language.lower() == 'es':
        STRINGS = LANG_STRINGS_ES
    else:
        STRINGS = LANG_STRINGS_EN

    port = options.port
    cookie = options.cookie
    custom_headers = options.custom_headers
    information = options.information
    cache_control = options.cache_control
    show_deprecated = options.show_deprecated
    hfile = options.hfile
    json_output = options.json_output

    if json_output:
        sys.stdout = open(os.devnull, 'w')

    if cookie is not None:
        client_headers.update({'Cookie': cookie})

    if custom_headers is not None:
        for header in custom_headers:
            header_split = header.split(':', 1)
            if len(header_split) == 2:
                 client_headers.update({header_split[0].strip(): header_split[1].strip()})
            else:
                 sys.stdout = sys.__stdout__
                 print(_t("invalid_header_format"))
                 sys.stdout = open(os.devnull, 'w') if json_output else sys.__stdout__

    if hfile is not None:
        try:
            with open(hfile) as f:
                targets = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
             sys.stdout = sys.__stdout__
             print(f"[!] Error: Hosts file not found: {hfile}")
             sys.exit(1)
        except Exception as e:
             sys.stdout = sys.__stdout__
             print(f"[!] Error reading hosts file {hfile}: {e}")
             sys.exit(1)

    if not targets:
        sys.stdout = sys.__stdout__
        print("[!] No targets specified either via command line or host file.")
        sys.exit(1)


    # --- Main Loop ---
    json_out = {}

    for target in targets:
        global headers
        headers = {}
        json_target_results = {}

        original_target = target
        if port is not None:
            target = append_port(target, port)

        safe = 0
        unsafe = 0

        log(_t("analyzing_headers", colorize(original_target, 'info')))

        response = check_target(target)
        if not response:
            if not json_output: print("")
            continue

        rUrl = response.geturl()
        log(_t("effective_url", colorize(rUrl, 'info')))

        parse_headers(response.getheaders())

        json_target_results = {"present": {}, "missing": []}
        json_out[rUrl] = json_target_results

        # --- Security Header Checks ---

        csp_header_value = headers.get("content-security-policy")
        csp_has_frame_ancestors = csp_header_value and "frame-ancestors" in csp_header_value.lower()

        current_sec_headers = sec_headers.copy()
        if csp_has_frame_ancestors and "X-Frame-Options" in current_sec_headers:
             current_sec_headers.pop("X-Frame-Options")
             headers.pop("x-frame-options", None)


        current_target_is_https = is_https(rUrl)

        for safeh in current_sec_headers:
            lsafeh = safeh.lower()
            header_severity = current_sec_headers.get(safeh)

            if lsafeh in headers:
                safe += 1
                header_value = headers.get(lsafeh)
                json_target_results["present"][safeh] = header_value

                # --- Special Handling for Present Headers ---

                if lsafeh in ['x-xss-protection', 'x-frame-options']:
                    log_msg = _t("obsolete_header_present", colorize(safeh, 'warning'), header_value)
                    log(log_msg)

                elif lsafeh == 'content-security-policy':
                    log(_t("header_present_no_value", colorize(safeh, 'ok')))
                    parse_csp(header_value)
                elif lsafeh == 'referrer-policy' and header_value.lower() == 'unsafe-url':
                    log(_t("insecure_referrer", colorize(safeh, 'warning'), colorize(header_value, 'error')))
                elif lsafeh == 'strict-transport-security' and "max-age=0" in header_value.replace(" ", ""):
                    log(_t("insecure_hsts", colorize(safeh, 'warning'), colorize(header_value, 'error')))
                else:
                    log(_t("header_present", colorize(safeh, 'ok'), header_value))

            else:
                # --- Handling Missing Headers ---
                if lsafeh in ['x-xss-protection', 'x-frame-options']:
                    continue
                
                unsafe += 1
                should_report_missing = True

                if lsafeh == 'strict-transport-security' and not current_target_is_https:
                    unsafe -= 1
                    should_report_missing = False

                if header_severity == "deprecated" and not show_deprecated:
                    unsafe -= 1
                    should_report_missing = False

                if should_report_missing:
                    json_target_results["missing"].append(safeh)
                    log(_t("missing_header", colorize(safeh, header_severity)))

        # --- Optional Checks ---

        if information:
            json_target_results["information_disclosure"] = {}
            i_chk = False
            log("")
            for infoh in information_headers:
                linfoh = infoh.lower()
                if linfoh in headers:
                    header_value = headers.get(linfoh)
                    json_target_results["information_disclosure"][infoh] = header_value
                    i_chk = True
                    log(_t("info_disclosure_present",
                           colorize(infoh, 'warning'),
                           header_value))
            if not i_chk:
                log(_t("no_info_disclosure"))

        if cache_control:
            json_target_results["caching"] = {}
            c_chk = False
            log("")
            for cacheh in cache_headers:
                lcacheh = cacheh.lower()
                if lcacheh in headers:
                     header_value = headers.get(lcacheh)
                     json_target_results["caching"][cacheh] = header_value
                     c_chk = True
                     log(_t("cache_header_present",
                            colorize(cacheh, 'info'),
                            header_value))
            if not c_chk:
                log(_t("no_cache_headers"))

        # --- Report Summary for Target ---
        report(rUrl, safe, unsafe)

    # --- Final Output ---
    if json_output:
        sys.stdout = sys.__stdout__
        print(json.dumps(json_out, indent=4))


# <<< FUNCIÓN CORREGIDA >>>
def parse_options():
    global STRINGS
    
    # --- Paso 1: Detectar el idioma manualmente antes de parsear ---
    # Esto evita que parse_args() falle con opciones que todavía no conoce.
    lang = 'en' # Idioma por defecto
    args = sys.argv[1:]
    for i, arg in enumerate(args):
        if arg == '-l' or arg == '--language':
            if i + 1 < len(args):
                lang = args[i+1]
                break
    
    if lang.lower() == 'es':
        STRINGS = LANG_STRINGS_ES
    else:
        STRINGS = LANG_STRINGS_EN

    # --- Paso 2: Ahora creamos el parser definitivo con TODAS las opciones ---
    parser = OptionParser(_t("usage"), prog=sys.argv[0])
    
    parser.add_option("-l", "--language", dest="language", default="en",
                      choices=["en", "es"],
                      help="Set output language [en/es] [default: %default]")
    parser.add_option("-p", "--port", dest="port",
                      help=_t("option_port"),
                      metavar="PORT")
    parser.add_option("-c", "--cookie", dest="cookie",
                      help=_t("option_cookie"),
                      metavar="COOKIE_STRING")
    parser.add_option("-a", "--add-header", dest="custom_headers",
                      help=_t("option_add_header"),
                      metavar="HEADER_STRING",
                      action="append")
    parser.add_option('-d', "--disable-ssl-check", dest="ssldisabled",
                      default=False,
                      help=_t("option_disable_ssl"),
                      action="store_true")
    parser.add_option('-g', "--use-get-method", dest="useget",
                      default=False, help=_t("option_use_get"),
                      action="store_true")
    parser.add_option('-m', "--use-method", dest="usemethod", default='HEAD',
                      choices=["HEAD", "GET", "POST", "PUT", "DELETE", "TRACE", "OPTIONS", "PATCH"],
                      help=_t("option_use_method"),)
    parser.add_option("-j", "--json-output", dest="json_output",
                      default=False, help=_t("option_json"),
                      action="store_true")
    parser.add_option("-i", "--information", dest="information", default=False,
                      help=_t("option_information"),
                      action="store_true")
    parser.add_option("-x", "--caching", dest="cache_control", default=False,
                      help=_t("option_caching"),
                      action="store_true")
    parser.add_option("-k", "--deprecated", dest="show_deprecated", default=False,
                      help=_t("option_deprecated"),
                      action="store_true")
    parser.add_option("--proxy", dest="proxy",
                      help=_t("option_proxy"),
                      metavar="PROXY_URL")
    parser.add_option("-f", "--hfile", dest="hfile",
                      help=_t("option_hfile"),
                      metavar="PATH_TO_FILE")
    parser.add_option("--colours", dest="colours",
                      help=_t("option_colours"),
                      default="dark", choices=['dark', 'light', 'none'])
    parser.add_option("--colors", dest="colours",
                      help=_t("option_colors_alias"))

    # --- Paso 3: Parseamos los argumentos una sola vez ---
    (options, targets) = parser.parse_args()

    if not targets and not options.hfile:
        sys.stdout = sys.__stdout__
        parser.print_help()
        sys.exit(1)

    return options, targets

if __name__ == "__main__":
    main()
