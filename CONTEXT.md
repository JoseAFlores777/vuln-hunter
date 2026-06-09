# vuln-hunter

Kit defensivo de auditoría de seguridad asistida por agentes. Los agentes auditan
el código del propio usuario, se comunican por un estado compartido y proponen
fixes de causa raíz para que una persona los apruebe.

## Language

**Ledger**:
El estado compartido de una auditoría: `.vuln-hunter/ledger.json`. Única fuente de
verdad. Cada agente lee, enriquece su sub-objeto y reescribe. Es el contrato que
consume el panel.
_Avoid_: estado, base de datos, store.

**Proyecto** (en contexto del panel):
El único repositorio que se está auditando. El panel vive dentro de ese repo y lee
su propio ledger. No hay vista multi-proyecto: "por proyecto" se entiende como "por
scope/paquete" dentro del mismo repo.
_Avoid_: workspace, tenant.

**Finding** (hallazgo):
Una vulnerabilidad candidata con un `id` (p.ej. VULN-001). Acumula sub-objetos de
cada agente (`sast`, `exploitability`, `intel`, `triage`, `fix`, `verification`) y
un `status` global.
_Avoid_: issue, alerta, bug.

**Status** (de un finding):
Etapa global del hallazgo en el flujo: `hypothesis → confirmed → triaged → planned
→ fixing → fixed → closed → filtered`. `fixing` es el estado transitorio que el
appsec-fixer escribe al EMPEZAR a tocar ese hallazgo (se ve "trabajándose ahora"
en el panel); pasa a `fixed` al aplicar el cambio y a `closed` tras verificación.
_Avoid_: estado (ambiguo con Ledger), fase.

**Lifecycle** (agrupación del panel):
Cómo el panel agrupa los `status` en pestañas: **Encontrados** (hypothesis,
confirmed, triaged, planned), **Mitigando** (fixing, fixed), **Arreglados**
(closed), **Filtrados** (filtered). Un hallazgo "se mueve de pestaña" al avanzar.
_Avoid_: tab, columna._

**Panel**:
Frontend estático (React por CDN, sin instalar nada) que lee el ledger y se
actualiza para que el usuario vea hallazgos y su mitigación en vivo.
_Avoid_: dashboard (reservado a la salida de texto de `status.py`), UI.

**Activity log**:
`.vuln-hunter/activity.jsonl`, append-only. El comando orquestador escribe un
evento al empezar/terminar cada etapa y cuando aparece cada finding. Separado del
ledger para no contaminar el contrato. El panel lo lee como timeline de actividad.
_Avoid_: log, eventos, stream.
