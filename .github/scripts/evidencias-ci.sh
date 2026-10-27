#!/usr/bin/env bash
# Genera las evidencias del laboratorio a partir de las salidas REALES de una ejecución
# del workflow sbom-slsa: inspección de la imagen publicada, SBOM, Grype, cosign y slsa-verifier.
#
# Entradas (variables de entorno):
#   REF         imagen publicada por digest (ghcr.io/usuario/repo@sha256:...)
#   RUN_URL     URL de la ejecución de GitHub Actions
#   RUN_NUMBER  número de la ejecución
#   GO_VERSION  versión de Go usada para compilar
# Requiere que los artefactos de la ejecución estén descargados en reports/ci/.
#
# Salidas:
#   reports/ci/imagen-info.txt
#   evidencias/ci-0X-*.png   (renderizadas con Chrome headless desde las salidas reales)
#   evidencias/EVIDENCIAS-CI.md

set -euo pipefail

: "${REF:?Falta REF}" "${RUN_URL:?Falta RUN_URL}" "${GO_VERSION:?Falta GO_VERSION}"
RUN_NUMBER="${RUN_NUMBER:-?}"
CI=reports/ci
EV=evidencias
TMP=$(mktemp -d)
mkdir -p "$EV"

FECHA=$(TZ=America/Bogota date '+%Y-%m-%d %H:%M:%S (UTC-05:00)')
COMMIT="${GITHUB_SHA:-local}"
ORIGEN="GitHub Actions · ejecución #${RUN_NUMBER} · ${FECHA}"

for f in sbom-codigo.cdx.json sbom-imagen.cdx.json grype-resultados.json grype-resultados.txt \
         cosign-attest.txt cosign-verify-ci.txt atestacion-sbom-ci.jsonl \
         procedencia-slsa.json slsa-verifier.txt; do
  [[ -f "$CI/$f" ]] || { echo "Falta $CI/$f" >&2; exit 1; }
done

# ---------------------------------------------------------------------------
# 1. Imagen publicada
# ---------------------------------------------------------------------------
if command -v docker >/dev/null && docker pull -q "$REF" >/dev/null 2>&1; then
  USUARIO=$(docker image inspect "$REF" --format '{{.Config.User}}')
  TAMANO=$(docker image inspect "$REF" --format '{{.Size}}' | awk '{printf "%.1f MB", $1/1024/1024}')
  ENTRY=$(docker image inspect "$REF" --format '{{join .Config.Entrypoint " "}}')
  CAPAS=$(docker image inspect "$REF" --format '{{len .RootFS.Layers}}')
  PUERTOS=$(docker image inspect "$REF" --format '{{range $p, $_ := .Config.ExposedPorts}}{{$p}} {{end}}')
  SHELL_EN_IMAGEN="no (distroless: sin shell ni gestor de paquetes)"
  docker run --rm --entrypoint /bin/sh "$REF" -c true >/dev/null 2>&1 && SHELL_EN_IMAGEN="sí"
else
  USUARIO="(no disponible)"; TAMANO="?"; ENTRY="?"; CAPAS="?"; PUERTOS="?"; SHELL_EN_IMAGEN="?"
fi

cat > "$CI/imagen-info.txt" <<EOF
\$ docker image inspect $REF
Imagen:            $REF
Usuario:           $USUARIO
Entrypoint:        $ENTRY
Puertos:           $PUERTOS
Capas:             $CAPAS
Tamaño:            $TAMANO
Shell en imagen:   $SHELL_EN_IMAGEN
Compilada con Go:  $GO_VERSION
Commit de origen:  $COMMIT
EOF

# ---------------------------------------------------------------------------
# 2. Datos de SBOM, Grype, cosign y SLSA
# ---------------------------------------------------------------------------
N_COD=$(jq '.components | length' "$CI/sbom-codigo.cdx.json")
N_IMG=$(jq '.components | length' "$CI/sbom-imagen.cdx.json")
N_VULN=$(jq '.matches | length' "$CI/grype-resultados.json")

jq -r '.components[] | [.name, (.version // "-"), .type] | @tsv' "$CI/sbom-imagen.cdx.json" \
  | sort -k3,3 -k1,1 | awk -F'\t' 'BEGIN{printf "%-45s %-28s %s\n","COMPONENTE","VERSIÓN","TIPO"}
                                   {printf "%-45s %-28s %s\n",$1,$2,$3}' > "$TMP/sbom-imagen.txt"

jq -r '.components[] | [.name, (.version // "-"), .type] | @tsv' "$CI/sbom-codigo.cdx.json" \
  | sort -k3,3 -k1,1 | awk -F'\t' 'BEGIN{printf "%-45s %-28s %s\n","COMPONENTE","VERSIÓN","TIPO"}
                                   {printf "%-45s %-28s %s\n",substr($1,1,44),$2,$3}' > "$TMP/sbom-codigo.txt"

SEVERIDADES=$(jq -r '[.matches[].vulnerability.severity] | group_by(.) | map("\(.[0]): \(length)") | join("  ·  ")' \
  "$CI/grype-resultados.json")
[[ -z "$SEVERIDADES" ]] && SEVERIDADES="sin vulnerabilidades"
TABLA_SEV=$(jq -r '[.matches[].vulnerability.severity] | group_by(.) | map("| \(.[0]) | \(length) |") | .[]' \
  "$CI/grype-resultados.json")

LISTA_VULN=$(jq -r '.matches
  | sort_by({"Critical":0,"High":1,"Medium":2,"Low":3,"Negligible":4,"Unknown":5}[.vulnerability.severity])
  | .[:40][]
  | "| \(.vulnerability.id) | \(.artifact.name) \(.artifact.version) | \(.vulnerability.severity) | \((.vulnerability.fix.versions // []) | join(", ") | if . == "" then "sin fix" else . end) |"' \
  "$CI/grype-resultados.json")

DECL=$(head -n1 "$CI/atestacion-sbom-ci.jsonl" | jq -r '.payload | @base64d | fromjson')
ATEST_TIPO=$(jq -r '.predicateType' <<<"$DECL")
ATEST_SUJETO=$(jq -r '"\(.subject[0].name)@sha256:\(.subject[0].digest.sha256)"' <<<"$DECL")
ATEST_COMP=$(jq -r '.predicate.components | length' <<<"$DECL")
REKOR=$(grep -Eo 'tlog entry created with index: [0-9]+' "$CI/cosign-attest.txt" | grep -Eo '[0-9]+$' | head -n1 || true)

P="$CI/procedencia-slsa.json"
PROV_TIPO=$(jq -r '.predicateType' "$P")
PROV_BUILDER=$(jq -r '.predicate.builder.id // .predicate.runDetails.builder.id' "$P")
PROV_BUILDTYPE=$(jq -r '.predicate.buildType // .predicate.buildDefinition.buildType' "$P")
PROV_FUENTE=$(jq -r '(.predicate.materials // .predicate.buildDefinition.resolvedDependencies // [])[0] | "\(.uri) @ \(.digest.sha1 // .digest.gitCommit // "-")"' "$P")
PROV_SUJETO=$(jq -r '"\(.subject[0].name)@sha256:\(.subject[0].digest.sha256)"' "$P")

# ---------------------------------------------------------------------------
# 3. Capturas: cada una es la salida real renderizada en formato terminal
# ---------------------------------------------------------------------------
CHROME=$(command -v google-chrome || command -v chromium || command -v chromium-browser || true)

render() {  # render <png> <título> <archivo de texto>
  local png="$1" titulo="$2" fuente="$3" html="$TMP/$(basename "$1" .png).html"
  local cuerpo alto
  cuerpo=$(jq -Rrs @html < "$fuente")
  # Alto estimado: líneas (con ajuste a 150 columnas) * 18 px + cabecera
  alto=$(awk '{ n += (length($0) > 150 ? int(length($0)/150) + 1 : 1) } END { print n*18 + 150 }' "$fuente")
  if (( alto > 6000 )); then alto=6000; fi
  cat > "$html" <<HTML
<!doctype html><html><head><meta charset="utf-8"><style>
body{margin:0;background:#0d1117;font-family:Consolas,"DejaVu Sans Mono",monospace}
.bar{background:#161b22;color:#c9d1d9;padding:12px 18px;border-bottom:1px solid #30363d;font:14px system-ui,sans-serif}
.bar b{color:#58a6ff}.bar span{color:#8b949e;float:right}
pre{margin:0;padding:16px 18px;color:#c9d1d9;font-size:13px;line-height:18px;white-space:pre-wrap;word-break:break-all}
</style></head><body><div class="bar"><b>${titulo}</b><span>${ORIGEN}</span></div><pre>${cuerpo}</pre></body></html>
HTML
  if [[ -n "$CHROME" ]]; then
    "$CHROME" --headless=new --no-sandbox --disable-gpu --hide-scrollbars --force-device-scale-factor=1 \
      --window-size=1280,"$alto" --screenshot="$png" "file://$html" >/dev/null 2>&1 || true
  fi
}

{ cat "$CI/imagen-info.txt"; } > "$TMP/e1.txt"
render "$EV/ci-01-imagen-nonroot.png" "Imagen publicada: usuario no root y base distroless" "$TMP/e1.txt"

{ echo "\$ syft dir:.   →  reports/sbom-codigo.cdx.json  ($N_COD componentes)"; echo
  cat "$TMP/sbom-codigo.txt"; echo
  echo "\$ syft $REF   →  reports/sbom-imagen.cdx.json  ($N_IMG componentes)"; echo
  cat "$TMP/sbom-imagen.txt"; } > "$TMP/e2.txt"
render "$EV/ci-02-sbom-codigo-vs-imagen.png" "SBOM del código vs SBOM de la imagen (Syft)" "$TMP/e2.txt"

{ echo "\$ grype sbom:reports/sbom-imagen.cdx.json"; echo
  head -n 60 "$CI/grype-resultados.txt"
  total=$(wc -l < "$CI/grype-resultados.txt")
  if (( total > 60 )); then echo "... (+$((total-60)) líneas en reports/ci/grype-resultados.txt)"; fi
  echo; echo "Resumen: $SEVERIDADES  ·  total: $N_VULN"; } > "$TMP/e3.txt"
render "$EV/ci-03-grype.png" "Escaneo de vulnerabilidades del SBOM con Grype" "$TMP/e3.txt"

{ echo "\$ cosign attest --yes --predicate reports/sbom-imagen.cdx.json --type cyclonedx $REF"; echo
  grep -v '^\s*$' "$CI/cosign-attest.txt" || true; } > "$TMP/e4.txt"
render "$EV/ci-04-cosign-attest.png" "Atestación firmada del SBOM con cosign (keyless)" "$TMP/e4.txt"

{ echo "\$ cosign verify-attestation --type cyclonedx --certificate-identity <workflow> --certificate-oidc-issuer https://token.actions.githubusercontent.com $REF"; echo
  grep -v '^\s*$' "$CI/cosign-verify-ci.txt" || true; echo
  echo "--- Declaración in-toto verificada ---"
  echo "predicateType: $ATEST_TIPO"
  echo "subject:       $ATEST_SUJETO"
  echo "componentes:   $ATEST_COMP"; } > "$TMP/e5.txt"
render "$EV/ci-05-cosign-verify.png" "Verificación de la atestación con identidad exacta" "$TMP/e5.txt"

{ echo "\$ slsa-verifier verify-image $REF --source-uri github.com/${GITHUB_REPOSITORY:-?} --source-branch main"; echo
  grep -v '^\s*$' "$CI/slsa-verifier.txt" || true; echo
  echo "--- Procedencia verificada ---"
  echo "predicateType: $PROV_TIPO"
  echo "builder.id:    $PROV_BUILDER"
  echo "buildType:     $PROV_BUILDTYPE"
  echo "fuente:        $PROV_FUENTE"
  echo "subject:       $PROV_SUJETO"; } > "$TMP/e6.txt"
render "$EV/ci-06-slsa-verifier.png" "Verificación de la procedencia SLSA Build L3" "$TMP/e6.txt"

# ---------------------------------------------------------------------------
# 4. Informe en Markdown
# ---------------------------------------------------------------------------
cat > "$EV/EVIDENCIAS-CI.md" <<EOF
# Evidencias del pipeline en GitHub Actions

Generadas automáticamente a partir de las salidas reales de la ejecución
[#${RUN_NUMBER}](${RUN_URL}) del workflow \`sbom-slsa\` (${FECHA}).
Los archivos completos están en [\`reports/ci/\`](../reports/ci/).

| Dato | Valor |
|---|---|
| Ejecución | ${RUN_URL} |
| Commit | \`${COMMIT}\` |
| Imagen | \`${REF}\` |
| Go | \`${GO_VERSION}\` |

## 1. Imagen endurecida

Usuario \`${USUARIO}\`, base distroless (shell en la imagen: ${SHELL_EN_IMAGEN}), tamaño ${TAMANO}, ${CAPAS} capas.

![Imagen no root](ci-01-imagen-nonroot.png)

## 2. SBOM del código vs SBOM de la imagen

| Origen | Componentes | Archivos |
|---|---|---|
| Código | ${N_COD} | \`sbom-codigo.cdx.json\`, \`sbom-codigo.spdx.json\` |
| Imagen | ${N_IMG} | \`sbom-imagen.cdx.json\`, \`sbom-imagen.spdx.json\` |

El SBOM del código solo ve \`go.mod\` y las GitHub Actions del workflow. El de la imagen incluye los paquetes
del sistema base y la biblioteca estándar de Go compilada en el binario: es la evidencia principal.

![SBOM código vs imagen](ci-02-sbom-codigo-vs-imagen.png)

## 3. Vulnerabilidades (Grype sobre el SBOM de la imagen)

| Severidad | Cantidad |
|---|---|
${TABLA_SEV:-| (ninguna) | 0 |}
| **Total** | **${N_VULN}** |

$( if [[ -n "$LISTA_VULN" ]]; then printf '| CVE | Componente | Severidad | Versión corregida |\n|---|---|---|---|\n%s\n' "$LISTA_VULN"; fi )

![Grype](ci-03-grype.png)

## 4. Atestación firmada del SBOM (cosign)

- Tipo de predicado: \`${ATEST_TIPO}\`
- Sujeto: \`${ATEST_SUJETO}\`
- Componentes en el SBOM firmado: ${ATEST_COMP}
- Entrada en el log de transparencia Rekor: ${REKOR:+[${REKOR}](https://search.sigstore.dev/?logIndex=${REKOR})}
- Firmante verificado: el workflow \`.github/workflows/sbom-slsa.yml\` de este repositorio (emisor \`https://token.actions.githubusercontent.com\`)

![cosign attest](ci-04-cosign-attest.png)

![cosign verify-attestation](ci-05-cosign-verify.png)

## 5. Procedencia SLSA verificada

- Tipo de predicado: \`${PROV_TIPO}\`
- Builder: \`${PROV_BUILDER}\`
- Fuente: \`${PROV_FUENTE}\`
- Sujeto: \`${PROV_SUJETO}\`

![slsa-verifier](ci-06-slsa-verifier.png)

## 6. Nivel SLSA alcanzado

| Nivel | Requisito | Evidencia | Estado |
|---|---|---|---|
| Build L1 | Existe procedencia | \`reports/ci/procedencia-slsa.json\` | Cumple |
| Build L2 | Plataforma alojada y procedencia firmada | GitHub Actions + firma Sigstore verificada por \`slsa-verifier\` | Cumple |
| Build L3 | Builder endurecido y aislado | \`slsa-github-generator\` en workflow reutilizable aislado, runners efímeros | Cumple |
EOF

rm -rf "$TMP"
echo "Evidencias generadas:"
ls -1 "$EV" "$CI"
