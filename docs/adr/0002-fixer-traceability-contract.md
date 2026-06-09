# Contrato de trazabilidad del fixer (dependencias)

Un usuario notó que una corrida del plugin **actualizó dependencias** que no
aparecían en el plan ni como vulnerabilidad. Eso rompe la promesa del kit: todo
cambio debe ser trazable a un hallazgo y aprobado por un humano. Decidimos
volver el contrato del `appsec-fixer` **estricto y trazable**.

## Estado: accepted

## Contexto

- La división SAST/SCA es dueña clara: `sast-analyst` = código propio,
  `threat-intel-scout` = dependencias (único dueño del SCA). Ver `ledger-contract`.
- El `appsec-fixer` corrige causa raíz e, históricamente, podía "actualizar a la
  versión parcheada mínima" un componente vulnerable. Sin una regla explícita,
  eso permitía subir una dependencia **sin** un finding SCA que la respaldara: un
  cambio fuera del ledger, fuera del plan, invisible para el usuario.
- El kit ya promete: "el patcher nunca commitea sin aprobación humana del diff
  exacto" y "todo pasa por el ledger". Un bump de dep silencioso contradice ambas.

## Decisión

1. **Todo cambio del fixer mapea a un VULN-id del plan.** El `appsec-fixer` solo
   modifica archivos/dependencias atados a un hallazgo concreto del ledger. No
   hay cambios "de paso".
2. **Un bump de dependencia EXIGE un finding SCA (VULN-2xx).** Si la causa raíz
   de un hallazgo es un componente vulnerable, debe existir el finding SCA que lo
   documente (paquete, versión, CVE, fixed_version) antes de tocar el manifest.
3. **Dep sin finding → threat-intel al vuelo.** Si a mitad del flujo el fixer
   necesita subir una dep que no tiene finding SCA, NO la sube en silencio:
   invoca a `threat-intel-scout` sobre esa dependencia para crear el finding
   real; solo si confirma vulnerabilidad, procede con el bump (ya trazado).
4. **Gate humano antes de aplicar fixes.** Tras triage+plan y ANTES de tocar
   código, el flujo pregunta: continuar con todos / elegir cuáles / detenerse.
   La aprobación por hash del diff (en `patch`) sigue existiendo como segunda red.
5. **Hook de defensa en profundidad.** Un hook avisa cuando un commit cambia un
   manifest/lockfile (`requirements*.txt`, `pyproject.toml`, `package.json`,
   `package-lock.json`, `*.csproj`, etc.) sin un finding SCA correspondiente en
   el ledger. Es una advertencia determinista, no solo confianza en el prompt.

## Alternativas descartadas

- **Permitir bumps y registrarlos a posteriori.** Deja una ventana donde el
  cambio existe antes que su justificación; el usuario aún puede ver deps movidas
  "sin razón" hasta que el registro alcance.
- **Prohibir al fixer tocar deps.** Separación limpia pero rompe el caso común
  (un hallazgo SCA cuya única cura es subir la versión) y obliga a un comando
  aparte para algo que el flujo ya sabe hacer.
- **Solo prompt, sin hook.** El kit ya decidió "hooks deterministas, no solo
  prompts"; un prompt puede ignorarse, un hook no.

## Consecuencias

- El usuario nunca ve una dependencia movida sin un finding + entrada de plan que
  la explique. La confianza en el plugin se mantiene.
- El `appsec-fixer` puede pausar para crear un finding SCA (vía threat-intel),
  alargando algún fix a cambio de trazabilidad total.
- Schema del ledger sube a 1.2 (nuevo status `fixing`, evento `finding:state`).
- Hay un hook nuevo que mantener; un falso positivo posible es un cambio legítimo
  de manifest no relacionado a seguridad (se resuelve documentándolo o con un
  finding informativo).
