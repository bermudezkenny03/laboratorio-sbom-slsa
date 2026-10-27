# Evidencias

Capturas de pantalla para la entrega. Guarda cada una con el nombre indicado.

| # | Archivo | Qué debe verse |
|---|---|---|
| 1 | `01-entorno.png` | Script 00 con docker, git, syft, grype y cosign en verde |
| 2 | `02-sbom-codigo-vs-imagen.png` | Resumen de componentes del SBOM del código y de la imagen |
| 3 | `03-imagen-nonroot.png` | Propiedades de la imagen: usuario `nonroot`, tamaño |
| 4 | `04-grype.png` | Resumen de Grype por severidad y componentes afectados |
| 5 | `05-cosign-attest.png` | `cosign attest` terminado, con la entrada en Rekor |
| 6 | `06-cosign-verify.png` | `cosign verify-attestation` con predicado, sujeto y componentes |
| 7 | `07-actions-jobs.png` | Ejecución del workflow con los 3 jobs en verde |
| 8 | `08-actions-summary.png` | Summary con tablas de SBOM, vulnerabilidades, SLSA y artefactos |
| 9 | `09-ci-verify-attestation.png` | Log del paso de verificación de la atestación en CI |
| 10 | `10-slsa-verifier.png` | Log de `slsa-verifier` con `PASSED: Verified SLSA provenance` |
| 11 | `11-remediacion.png` | (Opcional) Grype con Go 1.22 frente a Go 1.27 |
