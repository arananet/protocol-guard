# Protocol Guard: actualización de protocolos UCP 2026-08-25 y A2A 1.0

Estado: especificación escrita el 2026-10-22, antes de implementar. Origen: la
revisión de versiones del mismo día (protocol-version-review.md), que detectó
dos brechas: ucp-sdk implementa la spec UCP 2026-01-23 cuando la vigente es
2026-08-25, y el cliente de a2a-sdk no implementa ningún binding oficial de
A2A 1.0. MCP no tiene brecha y queda fuera de este cambio.
Nota: la copia local de protocol-version-review.md está truncada al final de
la sección de A2A; el detalle normativo de este cambio se verificó contra las
fuentes primarias listadas abajo, no contra ese archivo.

## Fuentes primarias verificadas (2026-10-22)

UCP (Universal Commerce Protocol):

- Repo oficial github.com/Universal-Commerce-Protocol/ucp, commit 2bbae24.
  Schemas normativos en source/schemas/: profile.json, ucp.json,
  service.json, capability.json y payment_handler.json. La documentación
  publicada en ucp.dev/2026-08-25 coincide byte a byte en tamaño con la de
  ucp.dev/latest a fecha de la revisión.
- Firma de mensajes: docs/specification/signatures.md (RFC 9421 y RFC 9530).
- Identity Linking: docs/specification/common/identity-linking/index.md
  (OAuth 2.0 Authorization Code con PKCE, descubrimiento RFC 8414 en
  /.well-known/oauth-authorization-server).

A2A (Agent2Agent):

- Repo oficial github.com/google-a2a/A2A, commit 98279d6. Modelo canónico en
  specification/a2a.proto y texto normativo en docs/specification.md:
  sección 3.6 (versionado), 5.3 (tabla de métodos por binding), 5.4 (códigos
  de error) y 9 (binding JSON-RPC).

## Cambio 1: packages/ucp-sdk a la spec 2026-08-25

### Modelo de perfil nuevo (normativo)

- El documento de perfil es `{ ucp: {...}, keys?: [...] }`. Las claves de
  firma van en el array top-level `keys[]` (JWK Set, RFC 7517); `signing_keys`
  desaparece del modelo. Cada clave exige `kid` y `kty`; los tipos conocidos
  son EC (P-256, P-384) y OKP (Ed25519), con vocabulario abierto: un lector
  debe tolerar tipos que no reconozca.
- `ucp.services`, `ucp.capabilities` y `ucp.payment_handlers` son registros
  por nombre en dominio inverso cuyo valor es un ARRAY de entidades, no una
  sola entidad. Un mismo servicio se declara una vez por binding.
- Cada binding de servicio lleva `version`, `spec`, `schema`, `id` y
  `config` opcionales, y dos campos propios: `transport` como STRING con
  valores "rest", "mcp", "a2a" o "embedded", y `endpoint` como URI. En
  perfiles de negocio, rest, mcp y a2a exigen `endpoint`; embedded usa
  `config` en su lugar. Desaparece el objeto `transport` con subobjetos por
  protocolo del modelo 2026-01-23.
- La URL de `schema` de cada entidad es la autoridad normativa de su
  estructura; `spec` es solo el documento legible. Ninguna regla puede
  exigir que el host de `spec` coincida con la autoridad del namespace.
- `ucp.supported_versions` es un mapa de versión (YYYY-MM-DD) a URI de
  perfil: cada URI apunta a un perfil completo y autocontenido (leaf
  profile) de esa versión. Si se omite, solo se soporta `ucp.version`.
  El perfil de negocio exige `services` y `payment_handlers` presentes
  (pueden ser objetos vacíos).
- Capacidades: entidad base más `extends` como string o array de nombres.
  En perfiles de negocio cada capacidad exige `schema`. Nombres nuevos o
  reubicados que el SDK debe conocer: `dev.ucp.shopping.cart`,
  `dev.ucp.shopping.catalog.search`, `dev.ucp.shopping.catalog.lookup`,
  `dev.ucp.common.identity_linking` y las extensiones de pago bajo
  `dev.ucp.common.payment.*` (por ejemplo
  `dev.ucp.common.payment.ap2_mandate`).
- Payment handlers: entidad base con `id` obligatorio y
  `available_instruments` opcional.

### Lectura tolerante de perfiles 2026-01-23

- El cliente normaliza cualquier perfil al modelo 2026-08-25 al cargarlo:
  entidad suelta pasa a array de un elemento; el objeto `transport` antiguo
  se descompone en un binding por subobjeto presente, heredando `version`,
  `spec` y `schema` de la entidad; `signing_keys` se mapea a `keys`.
- La normalización es pura y exportable (`normalizeUCPProfile`), para que el
  checker y cualquier consumidor trabajen siempre sobre el modelo nuevo.
  Los perfiles antiguos accesibles vía `supported_versions` se leen con la
  misma tolerancia.

### Cliente

- `fetchBusinessProfile` normaliza y detecta si el perfil original era
  legacy (propiedad `profileWasLegacy`).
- Se conservan los accesores con la semántica nueva: `getServices` y
  `getCapabilities` devuelven los registros con arrays; nuevo
  `getServiceBindings(name)` y `getServiceEndpoint(name, transport)`;
  `getServiceRestEndpoint` queda como atajo sobre el binding "rest".
- Cabecera `UCP-Agent` con la URL del perfil de plataforma cuando se
  configura `agentProfileUrl` (rol ucp-agent frente a ucp-business).
- Identity Linking: tipo `UCIdentityLinkingConfig` leído de la capacidad
  `dev.ucp.common.identity_linking` y método
  `fetchOAuthMetadata()` que descubre el authorization server en
  `/.well-known/oauth-authorization-server` (RFC 8414).
- Firma de peticiones (RFC 9421): módulo `signing.ts` con
  `computeContentDigest` (RFC 9530) y `signUCPRequest`, que genera las
  cabeceras Signature-Input, Signature y Content-Digest con WebCrypto
  (ES256 y EdDSA). El cliente aplica la firma cuando se configura un
  `signer`. Verificable con un test de ida y vuelta (firmar y verificar con
  la clave pública publicada en `keys[]`).

### Checker de compliance

- Todas las reglas existentes se reescriben sobre el modelo normalizado.
- La regla `ucp-spec-binding` invierte su semántica: antes fallaba si el
  host de la URL `spec` no coincidía con la autoridad derivada del
  namespace, lo que marca como sospechosos perfiles 2026-08-25 válidos
  (por ejemplo los de Shopify). La regla pasa a validar que `schema` sea
  una URL absoluta presente (la autoridad normativa) y que `spec`, si
  existe, sea una URL absoluta; hosts distintos entre `spec` y `schema`
  ya no son un hallazgo.
- Reglas nuevas: `ucp-supported-versions` (mapa bien formado, URIs HTTPS,
  la versión actual no necesita estar en el mapa), `ucp-keys` (sustituye a
  `ucp-signing-keys`: valida `keys[]` con `kid` y `kty`; la presencia de
  `signing_keys` en el perfil original es un aviso legacy, no un acierto),
  `ucp-payment-handler-id`, y reglas informativas `ucp-cart-capability`,
  `ucp-catalog-capability`, `ucp-identity-linking` y
  `ucp-payment-namespace`.
- La regla de endpoints HTTPS recorre los bindings: `endpoint` de cada
  binding debe ser HTTPS.

## Cambio 2: packages/a2a-sdk al binding JSON-RPC de A2A 1.0

### Modelo de datos (a2a.proto, serialización JSON camelCase)

- Estados de tarea como enum de strings: TASK_STATE_UNSPECIFIED,
  TASK_STATE_SUBMITTED, TASK_STATE_WORKING, TASK_STATE_COMPLETED,
  TASK_STATE_FAILED, TASK_STATE_CANCELED, TASK_STATE_INPUT_REQUIRED,
  TASK_STATE_REJECTED, TASK_STATE_AUTH_REQUIRED. `Task.status` es un objeto
  `{ state, message?, timestamp? }`. La tarea lleva `id`, `contextId`,
  `artifacts[]` e `history[]`.
- `Message`: `messageId` obligatorio, `role` como ROLE_USER o ROLE_AGENT,
  `parts[]`, `contextId`, `taskId`, `referenceTaskIds`, `extensions`,
  `metadata`.
- `Part` es un oneof sin discriminador `type` ni `kind` en 1.0: un objeto
  con exactamente una de `text`, `raw` (base64), `url` o `data`, más
  `mediaType`, `filename` y `metadata` opcionales.
- `AgentCard`: `supportedInterfaces` es el campo canónico (cada interfaz
  con `url`, `protocolBinding`, `protocolVersion` y `tenant` opcional);
  `securitySchemes` y `securityRequirements`; `defaultInputModes`,
  `defaultOutputModes` y `skills` obligatorios en la spec.

### Cliente JSON-RPC 2.0

- Transporte único: POST al endpoint de la interfaz con `protocolBinding`
  "JSONRPC" de la Agent Card (o la URL configurada), cuerpo
  `{ jsonrpc: "2.0", id, method, params }` y cabecera `A2A-Version: 1.0`
  en cada petición. Los nombres de método JSON-RPC en 1.0 son los de la
  operación en PascalCase (sección 9.4 de la spec): SendMessage,
  SendStreamingMessage, GetTask, ListTasks, CancelTask, SubscribeToTask,
  CreateTaskPushNotificationConfig, GetTaskPushNotificationConfig,
  ListTaskPushNotificationConfigs, DeleteTaskPushNotificationConfig y
  GetExtendedAgentCard. Los paths `message:send` o `tasks/{id}` son del
  binding HTTP+JSON/REST, no del JSON-RPC; esta distinción corrige la
  descripción inicial del encargo, que los mezclaba.
- `sendMessage` devuelve la unión `{ task } | { message }` del proto.
  `sendStreamingMessage` consume el SSE y produce eventos StreamResponse
  (`task`, `message`, `statusUpdate`, `artifactUpdate`).
- Errores: clase `A2AError` con `code`, `message` y `data`; nombres por
  código según la sección 5.4: -32001 TaskNotFoundError, -32002
  TaskNotCancelableError, -32003 PushNotificationNotSupportedError,
  -32004 UnsupportedOperationError, -32005 ContentTypeNotSupportedError,
  -32006 InvalidAgentResponseError, -32007
  ExtendedAgentCardNotConfiguredError, -32008 ExtensionSupportRequiredError
  y -32009 VersionNotSupportedError, además de los estándar JSON-RPC.
- Compatibilidad: `sendTask` se conserva como adaptador @deprecated
  sobre el nuevo transporte, traduciendo las formas antiguas (parts con
  `type`, estados en minúscula) a las de 1.0 y de vuelta. `getTask` y
  `cancelTask` pasan a ser las operaciones 1.0 (params compatibles con
  los antiguos, pero devuelven la Task completa), y las formas antiguas
  quedan como `getTaskLegacy` y `cancelTaskLegacy`. Los tipos antiguos
  quedan exportados con @deprecated.
- El checker gana una regla `agent-card-interfaces`: interfaces presentes
  con `protocolBinding` y `protocolVersion`; `protocolVersion` a nivel de
  card sigue como aviso porque en 1.0 la versión vive en cada interfaz.

## Tests y verificación

- Tests nuevos con vitest en packages/ucp-sdk/tests y
  packages/a2a-sdk/tests: normalización de un perfil legacy 2026-01-23,
  checker sobre un perfil 2026-08-25 válido basado en el ejemplo normativo
  de la spec oficial (sin falsos críticos y sin que `ucp-spec-binding`
  marque hosts distintos), firma RFC 9421 de ida y vuelta, y cliente A2A
  con fetch simulado (sobre JSON-RPC, cabecera A2A-Version, mapping de
  errores y adaptadores legacy).
- Typecheck y tests por paquete con las herramientas locales del repo
  (tsc y vitest de node_modules). pnpm no está instalado en esta VM; si
  algún comando de turbo no puede ejecutarse, se deja constancia exacta.

## Fuera de alcance

- La app web (apps/web) tiene rutas API propias con llamadas inline de la
  era 0.3 (por ejemplo apps/web/src/app/api/a2a/send-task/route.ts usa
  `tasks/send`). No se toca en este cambio; queda como trabajo posterior.
- Sin cambios en apps/cf-worker, Dockerfile ni README.
- Nada de secretos en el repo; las claves de firma de los tests se generan
  en tiempo de ejecución.
