import re


def detectar_framework(html, headers):
    frameworks = {}
    if '__NEXT_DATA__' in html:
        frameworks['Next.js'] = "Detectado"
        build = re.search(r'"buildId":"([^"]+)"', html)
        if build:
            frameworks['Next.js Build'] = build.group(1)[:8]
    if 'id="__nuxt"' in html or '/_nuxt/' in html:
        frameworks['Nuxt.js'] = "Detectado"
    if 'astro-' in html:
        frameworks['Astro'] = "Detectado"
    if 'id="svelte' in html:
        frameworks['SvelteKit'] = "Detectado"
    server = str(headers.get('Server', '')).lower()
    if 'vercel' in server:
        frameworks['Hosting'] = "Vercel"
    elif 'cloudflare' in server:
        frameworks['Hosting'] = "Cloudflare"
    elif 'netlify' in server:
        frameworks['Hosting'] = "Netlify"
    return frameworks
