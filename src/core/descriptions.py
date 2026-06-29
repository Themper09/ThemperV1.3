_EXACT = {
    "Falta X-Frame-Options":
        "Permite que la página sea cargada en iframes, exponiendo a ataques de clickjacking",
    "Falta X-Content-Type-Options":
        "El navegador podría interpretar archivos con tipos MIME incorrectos (content sniffing)",
    "Falta Strict-Transport-Security":
        "No obliga a usar HTTPS, permitiendo ataques man-in-the-middle (SSL stripping)",
    "Falta Content-Security-Policy":
        "Permite ejecutar scripts no autorizados, facilitando ataques XSS",
    "Falta Referrer-Policy":
        "La URL completa puede filtrarse a sitios externos en las cabeceras Referer",
    "Falta Permissions-Policy":
        "APIs del navegador (cámara, micrófono, geolocalización) pueden usarse sin restricción",
    "Cookie sin HttpOnly":
        "Las cookies pueden ser accedidas por JavaScript, permitiendo robo de sesión via XSS",
    "Cookie sin Secure":
        "Las cookies se envían en conexiones HTTP no cifradas, permitiendo su interceptación",
    "Cookie sin SameSite":
        "Las cookies se envían en solicitudes cross-site, permitiendo ataques CSRF",
    "Fuga de info X-Powered-By":
        "Revela la tecnología y versión del servidor, facilitando ataques dirigidos",
    "XSS Reflejado":
        "Permite inyectar scripts maliciosos que se ejecutan en el navegador de la víctima",
    "CORS preflight permite métodos no estándar":
        "Permite métodos HTTP peligrosos (PUT, DELETE) desde orígenes externos",
    "Sin Rate Limiting":
        "El servidor no limita peticiones, permitiendo ataques de fuerza bruta y DoS",
    "Rate Limit débil":
        "La limitación de peticiones es insuficiente para prevenir abusos",
    "SSL handshake lento":
        "La negociación SSL/TLS es lenta, posiblemente por configuración subóptima",
}

_PREFIX = [
    ("CORS killer",
     "Configuración CORS insegura que permite a sitios maliciosos leer datos del servidor"),
    ("SourceMap expuesto",
     "Expone el código fuente original del frontend, revelando lógica de negocio y posiblemente secretos"),
    ("Grid expuesto",
     "Panel de administración o servicio interno expuesto sin autenticación"),
    ("Verificar versión",
     "La versión del framework puede tener vulnerabilidades conocidas (CVEs)"),
]

_SUFFIX = [
    (" público",
     "Archivo sensible accesible públicamente, puede exponer credenciales y datos internos"),
    (" en JS",
     "Clave secreta o credencial expuesta en JavaScript del lado del cliente, accesible a cualquier visitante"),
]

_LIBRARY_PREFIXES = [
    "jQuery", "React", "Vue", "Angular", "Bootstrap",
    "Lodash", "Moment.js", "DOMPurify", "socket.io", "Chart.js",
]

_LIB_DESC = "Librería con vulnerabilidades conocidas (CVE). Se recomienda actualizar a la última versión"


def get_vuln_description(vuln_text):
    if vuln_text in _EXACT:
        return _EXACT[vuln_text]

    for prefix, desc in _PREFIX:
        if vuln_text.startswith(prefix):
            return desc

    for suffix, desc in _SUFFIX:
        if vuln_text.endswith(suffix):
            return desc

    for lib in _LIBRARY_PREFIXES:
        if vuln_text.startswith(lib):
            return _LIB_DESC

    return ""
