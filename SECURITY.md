# Seguridad de vuln-hunter

vuln-hunter es un kit DEFENSIVO para auditar tu propio código en un alcance
autorizado. Este documento cubre cómo usarlo de forma segura y cómo reportar
problemas en el propio kit.

## ⚠️ El repo auditado puede ejecutar código en tu máquina

Algunas etapas **ejecutan herramientas que cargan y corren código del repositorio
auditado**, que podría ser hostil:

- `verify-engineer` corre la **suite de tests** del repo (`pytest`, `npm test`,
  `dotnet test`) → el código de los tests se ejecuta con tus permisos.
- `run-scan.sh` / `sast-analyst` invocan linters/escáneres que pueden cargar
  **configuración o plugins del repo** (p.ej. `.eslintrc.js`, plugins de eslint,
  hooks de build) → código del repo se ejecuta.
- Instalar dependencias (`npm`, `pip`) puede correr **scripts de post-install**.

Por eso, si auditas un repositorio en el que **no confías plenamente**:

> **Córrelo dentro de un contenedor o VM aislada**, sin acceso a secretos ni a la
> red interna, con el árbol montado de solo lectura cuando sea posible.

Ejemplo (contenedor efímero, sin red, árbol de solo lectura):

```bash
docker run --rm -it \
  --network none \
  -v "$PWD":/work:ro \
  -w /work \
  python:3.12-slim bash
# dentro: instala los escáneres y corre vuln-hunter contra /work
```

Mitigaciones que el kit ya aplica (defensa en profundidad, no sustituyen el
aislamiento):

- `run-scan.sh` usa `npx --no-install` (no auto-instala desde el registry).
- Los agentes tratan el contenido del repo como **DATA, no instrucciones**
  (anti prompt-injection; ver `CLAUDE.md` §4-bis).
- Los hooks bloquean ejecución ofensiva y commits sin aprobación humana.
- `intel-cache.sh` solo consulta fuentes oficiales por https (allowlist).
- El panel se sirve solo en `127.0.0.1` con allowlist de `Host`.

## Marco de uso

- Solo sobre código propio, en auditoría **autorizada**, con fin de remediar.
- El red-team produce únicamente **PoCs conceptuales**; nunca exploits desplegables.
- El parcheo no commitea sin **aprobación humana** del índice staged exacto.

## Reportar una vulnerabilidad en el propio kit

Si encuentras un fallo de seguridad en vuln-hunter (no en un repo auditado),
repórtalo en privado al autor antes de divulgarlo públicamente:
`joseadolfoizaguirreflores@gmail.com`. Incluye versión, pasos de reproducción y el
impacto. Se aplica divulgación responsable.
