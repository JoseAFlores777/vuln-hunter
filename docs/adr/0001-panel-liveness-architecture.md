# Arquitectura de liveness del panel

El panel administrativo muestra el progreso de la auditoría "en vivo", pero los
agentes corren como subagentes `Task` opacos: el hilo principal no recibe nada de
un subagente hasta que retorna. Decidimos lograr la sensación de tiempo real con
dos archivos separados y polling, no con streaming fino.

## Estado: accepted

## Decisión

- **Split estado/eventos.** `.vuln-hunter/ledger.json` sigue siendo la única
  verdad de estado (findings, status, mitigación). Un archivo nuevo
  `.vuln-hunter/activity.jsonl` (append-only) lleva el timeline de eventos.
- **Granularidad etapa + finding.** El orquestador (y cada comando de etapa, vía
  el helper `scripts/activity.py`) emite eventos en los bordes:
  `stage:start`, `stage:end`, `finding:new`, `deploy:blocked`, `run:start/done`.
  No hay eventos intra-agente: el subagente Task es una caja negra hasta que
  termina, así que "vivo" significa por-etapa y por-finding, no token a token.
- **Estado de agentes y status de findings se DERIVAN**, no se duplican. El panel
  calcula idle/running/done de cada agente a partir del último `stage:*` de su
  etapa, y lee la mitigación directamente del ledger.
- **Servido con `http.server` + polling 2s.** El comando `/vuln-hunter:panel`
  sirve `.vuln-hunter/` y el `index.html` (React por CDN) hace `fetch()` de ambos
  archivos. python3 ya es dependencia del kit, así que no se instala nada.

## Alternativas descartadas

- **Eventos dentro del ledger.** Contamina el contrato que ya consumen 7 agentes
  y multiplica las reescrituras concurrentes que `ledger-contract` desaconseja.
- **Derivar todo de snapshots del ledger** (sin activity.jsonl). Pierde el evento
  "empezó la etapa X" cuando aún no hay findings, y no da timeline ni timestamps.
- **SSE / long-poll.** Exige un server Python propio con endpoint, más código y
  superficie; contradice el objetivo "sencillo, sin instalar nada". Polling 2s
  basta para la cadencia de una auditoría.
- **Instrumentar el interior de cada agente.** Imposible de forma fiable con la
  opacidad del Task tool, y obligaría a tocar los 7 prompts de agente.

## Consecuencias

- El panel nunca muestra "el agente está pensando en X ahora mismo"; lo más fino
  es "red-team corriendo" + los findings que ya aterrizaron. Es el techo real de
  la arquitectura Task actual; si algún día los subagentes emiten progreso, se
  puede subir la granularidad sin cambiar el split de archivos.
- Todos los comandos de etapa adquieren una dependencia ligera de
  `scripts/activity.py`. Si un comando olvida emitir, el timeline se degrada pero
  el estado derivado del ledger sigue correcto.
