# Themper v1.3 - Web Security Header Scanner

Scanner de cabeceras HTTP y configuración SSL/TLS desarrollado en Python para auditorías de seguridad en entornos controlados.

## Aviso Legal Importante

Esta herramienta debe usarse EXCLUSIVAMENTE en sistemas de tu propiedad o con autorización escrita del propietario.

El uso no autorizado en sistemas ajenos constituye delito según la Ley 1273 de 2009 Art. 269A en Colombia, con penas de prisión de 48 a 96 meses y multas de 100 a 1000 SMMLV.

El autor no se hace responsable del mal uso de esta herramienta.

## Objetivo

Detectar configuraciones inseguras en cabeceras HTTP y certificados SSL que puedan exponer aplicaciones web a ataques como:

- Clickjacking
- Cross-Site Scripting (XSS) 
- Man-in-the-Middle (MITM)
- Downgrade attacks

Basado en las recomendaciones de OWASP Secure Headers Project.

## Características

| Módulo | Descripción |
| --- | --- |
| Header Check | Verifica 8 headers críticos: CSP, HSTS, X-Frame-Options, etc |
| SSL Audit | Valida certificado, fecha de vencimiento y versión TLS |
| WAF Detection | Identifica Cloudflare, Akamai, Imperva, etc |
| Score 0-100 | Calcula nivel de seguridad según OWASP |
| Reportes | Exporta resultados en TXT, HTML y JSON |

## Instalación

Requisitos previos: Python 3.8 o superior

```bash
git clone https://github.com/Themper09/ThemperV1.3.git
cd themper
pip install -r requirements.txt
```
