---
name: agent-presentation
description: Define el formato visual uniforme con el que TODOS los agentes y comandos de vuln-hunter presentan resultados al usuario, hacen preguntas y recomiendan el siguiente comando. Usa este skill siempre que un agente termine su trabajo o un comando deba mostrar resultados, para que la experiencia sea consistente, escaneable y guiada paso a paso.
---

# Presentacion uniforme de vuln-hunter

Objetivo: que el usuario, tras CUALQUIER paso, entienda en 5 segundos (1) que se
hizo, (2) que se encontro, (3) que decision tiene delante y (4) cual es el
siguiente comando exacto. Sin prosa larga; bloques escaneables.

## 1. Cabecera de agente (siempre la primera linea del resultado)
Cada agente abre con una linea de identidad fija:

```
┌─ 🛰  RECON · Cartografo de superficie de ataque ─────────────
```

Iconos y etiquetas por agente (usalos EXACTOS):
| Agente | Icono | Etiqueta corta |
|---|---|---|
| recon-cartographer | 🛰 | RECON |
| sast-analyst | 🔬 | SAST |
| threat-intel-scout | 📡 | INTEL |
| redteam-whitehat | 🎯 | RED-TEAM |
| triage-judge | ⚖️ | TRIAGE |
| appsec-fixer | 🔧 | FIX |
| verify-engineer | ✅ | VERIFY |

## 2. Bloque "Resumen" (3 lineas maximo)
```
Resumen     3 hallazgos nuevos · 1 critico (P0) · 0 falsos positivos descartados
Scope       apps/example-app (Django)
Ledger      .vuln-hunter/ledger.json  (+3 findings)
```

## 3. Tabla de hallazgos (si aplica)
Una tabla compacta, ordenada por severidad. Severidad SIEMPRE con color-semaforo
textual:
- 🔴 P0 / Critico  · 🟠 P1 / Alto  · 🟡 P2 / Medio  · 🟢 P3 / Bajo  · ⚪ Filtrado

```
ID        Sev  Titulo                         Ubicacion              Estado
VULN-101  🔴   SQL injection (raw query)      views.py:11            confirmada
VULN-102  🟡   XSS dangerouslySetInnerHTML    page.jsx:4             hipotesis
VULN-201  🔴   Django 3.2.4 (CVE en KEV)      Django@3.2.4           confirmada
```

## 4. Barra de progreso del flujo (SIEMPRE al final, antes del next-step)
Muestra en que punto del pipeline esta el usuario:
```
Flujo  detect → [SAST ✓] [INTEL ✓] → red-team ● → triage ○ → plan ○ → fix ○ → verify ○
              (✓ hecho · ● en curso · ○ pendiente)
```

## 5. Bloque "Siguiente paso" (OBLIGATORIO, lo mas importante)
Cierra SIEMPRE con un bloque que recomiende el comando exacto. Si hay varias
opciones razonables, ofrece hasta 3, marcando la recomendada con ★.

```
▶ Siguiente paso
  ★ /vuln-hunter:redteam all      Confirmar explotabilidad de los 3 hallazgos
    /vuln-hunter:report           Ver el informe HTML de lo encontrado hasta ahora
    /vuln-hunter:watch --gate     Re-evaluar dependencias antes de desplegar

  ¿Continuo con el paso recomendado? (responde "si" o elige otro comando)
```

## 6. Preguntas al usuario (cuando se necesita decision)
Cuando un agente necesite una decision del usuario, usa el formato de pregunta
unica y enumerada (nunca mas de una pregunta a la vez, opciones cortas):

```
❓ Decision necesaria
   Hay 2 hallazgos P0 en dependencias con CVE en KEV. ¿Como procedo?
   1) Bloquear el deploy y crear branch de fix ahora      (recomendado)
   2) Solo reportar, decido yo despues
   3) Ver primero la cadena de explotacion conceptual
   Responde 1, 2 o 3.
```

Si el plugin corre en un entorno con la herramienta de opciones interactivas
(botones), prefiere esa; si no, usa esta lista numerada en texto.

## 7. Reglas de estilo
- Nada de parrafos largos. Bloques, tablas, listas cortas.
- El comando del siguiente paso SIEMPRE copiable tal cual (con el prefijo
  `/vuln-hunter:`).
- Si no hay hallazgos, dilo claro y celebra: "Sin hallazgos en este scope ✅" y
  ofrece ampliar el scope o pasar al siguiente paquete.
- Severidad siempre con el emoji-semaforo, nunca solo texto.
- No inventes hallazgos para "llenar" la tabla: el contenido sale del ledger.
