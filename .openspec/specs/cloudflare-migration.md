# Protocol Guard: migración de Railway a Cloudflare Containers

## Despliegue (Workers Builds, configurado el 2026-10-22)

- Proyecto Workers Builds sobre este repo, rama de producción `main`.
- Root directory: `apps/cf-worker` (ahí vive el wrangler.jsonc del envoltorio).
- Build command: vacío. La app se compila dentro de la imagen Docker durante
  el deploy; la carpeta del envoltorio no tiene script de build.
- Deploy command: `npx wrangler deploy`.
- La imagen se construye desde `docker/Dockerfile` con la raíz del monorepo
  como contexto (campo image_build_context del wrangler.jsonc).
- Sin secretos en el repo: la app es stateless y no requiere variables.


Estado: auditoría completada el 2026-10-22. Ruta decidida por Edu el 2026-10-22:
Containers con el Dockerfile actual, sin reescribir código (lo que ya es Node o
Next no se reescribe, solo se reempaqueta). Edu borró el proyecto de Railway, así
que la migración es también la recuperación del servicio.
Nota: el repo usa hoy .specify (Spec Kit); esta spec sigue la plantilla OpenSpec de Edu.

## Hallazgos de la auditoría (verificados en el código)

- La app es STATELESS en la práctica: ni PrismaClient ni DATABASE_URL se usan en
  ningún punto de apps/web/src ni de packages/*/src. El schema de Prisma, las
  variables NEXTAUTH_* de .env.example y la dependencia better-auth son restos
  heredados (el propio Dockerfile lo dice: "legacy leftover, app is stateless").
  No hay rutas de auth cableadas.
- El motor de escaneo trabaja contra servidores REMOTOS por HTTP (fetch/SSE):
  packages/mcp-sdk (1,216 líneas TS), a2a-sdk (629), ucp-sdk (872), shared (70).
  No hay child_process, ni fs, ni spawn reales en el código de escaneo; la única
  coincidencia es una expresión regular del propio checker de seguridad.
- apps/web es Next.js 14.2.35 (salida standalone, arranque con node server.js),
  9 rutas API de escaneo/test (mcp, a2a, ucp) y unas 9,100 líneas en src.
- Producción actual: Railway (Dockerfile del monorepo) detrás del proxy de
  Cloudflare en protocol-guard.arananet.net.

## Destino

- Cloudflare Containers con el docker/Dockerfile actual, sin tocar el código
  de la app: un Worker fino con una clase Durable Object Container que
  reenvía todo el tráfico al contenedor (puerto 3000), con custom domain
  protocol-guard.arananet.net (la zona ya está en la misma cuenta).
- Sin base de datos. Los secretos, si hicieran falta, van como secrets de
  Cloudflare, nunca en el repo.

## Trabajo necesario

1. Construir la imagen con el Dockerfile actual y subirla al registry de
   Cloudflare (registry.cloudflare.com) fijando el digest en la config.
2. Crear el Worker contenedor (wrangler.jsonc con [[containers]], binding de
   Durable Object y exports) y desplegarlo en un subdominio de prueba.
3. Verificar en el subdominio de prueba: home 200, rutas API de escaneo
   respondiendo y un escaneo real contra un servidor MCP público.
4. Limpieza muerta opcional, sin prisa: prisma generate en el Dockerfile y
   dependencias @prisma/client y better-auth.
5. Corte DNS: apuntar protocol-guard.arananet.net al Worker y verificar (200,
   sin cabeceras de Railway, API respondiendo). Sin rollback a Railway: Edu
   borró el proyecto; el rollback es la imagen anterior en el registry.

## Riesgos

- Containers sigue en beta: arranques en frío al escalar desde cero y al
  desplegar (la primera petición tras un rollout puede tardar segundos).
- La imagen del monorepo es grande (build de Next completo); vigilar el
  tamaño frente al disco del tipo de instancia elegido.
- Duración de escaneos largos contra objetivos lentos dentro del contenedor:
  validar con un caso real antes del corte.

## Esfuerzo estimado

Medio día a 1 día: la imagen ya existe como Dockerfile probado en Railway; el
trabajo nuevo es el Worker envoltorio, la subida de la imagen y el corte.
