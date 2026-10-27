# Evidencias

## Automáticas del pipeline (GitHub Actions)

Las genera el job `evidencias` en cada ejecución manual del workflow (**Actions → sbom-slsa → Run workflow**, con *Guardar evidencias* marcado). Son las salidas reales de esa ejecución; los archivos completos quedan en [`reports/ci/`](../reports/ci/).

| Archivo | Qué muestra |
|---|---|
| [`EVIDENCIAS-CI.md`](EVIDENCIAS-CI.md) | Informe completo: imagen, SBOM, vulnerabilidades, atestación, procedencia y nivel SLSA |
| `ci-01-imagen-nonroot.png` | Imagen publicada: usuario no root, distroless, tamaño |
| `ci-02-sbom-codigo-vs-imagen.png` | Componentes del SBOM del código frente al de la imagen |
| `ci-03-grype.png` | Escaneo de vulnerabilidades con Grype |
| `ci-04-cosign-attest.png` | Atestación del SBOM firmada con cosign y registrada en Rekor |
| `ci-05-cosign-verify.png` | Verificación de la atestación con la identidad exacta del workflow |
| `ci-06-slsa-verifier.png` | Verificación de la procedencia SLSA Build L3 |

## Ejecución local en Windows

Capturas de pantalla de tu propio equipo al ejecutar los scripts. Guárdalas aquí con estos nombres.

| Archivo | Qué debe verse |
|---|---|
| `local-01-entorno.png` | Script 00 con docker, git, syft, grype y cosign en verde |
| `local-02-sbom.png` | Resumen de componentes del SBOM del código y de la imagen |
| `local-03-imagen-nonroot.png` | Propiedades de la imagen: usuario `nonroot`, tamaño |
| `local-04-grype.png` | Resumen de Grype por severidad y componentes afectados |
| `local-05-cosign-attest.png` | `cosign attest` con tu cuenta de GitHub y la entrada en Rekor |
| `local-06-cosign-verify.png` | `cosign verify-attestation` con predicado, sujeto y componentes |
| `local-07-actions.png` | Pestaña Actions con los jobs en verde |
