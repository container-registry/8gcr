{{/*
=============================================================================
Internal URL helpers
=============================================================================
*/}}

{{/*
Return the Core internal URL. The port stays explicit: go-containerregistry
reads a portless single-label host as a Docker Hub namespace (#790).
*/}}
{{- define "harbor.core.url" -}}
http://{{ include "harbor.fullname" . }}-core:{{ include "harbor.core.service.port" . }}
{{- end }}

{{/*
Container port
*/}}
{{- define "harbor.core.port" -}}
8080
{{- end }}

{{/*
Core Service port (core.servicePort)
*/}}
{{- define "harbor.core.service.port" -}}
{{- .Values.core.servicePort | default 80 -}}
{{- end }}

{{/* TOKEN_SERVICE_URL */}}
{{- define "harbor.token.service.url" -}}
{{ include "harbor.core.url" . }}/service/token
{{- end -}}

{{/*
Return the Portal internal URL
*/}}
{{- define "harbor.portal.url" -}}
{{- if .Values.portal.url -}}
{{- .Values.portal.url -}}
{{- else -}}
http://{{ include "harbor.fullname" . }}-portal
{{- end -}}
{{- end }}

{{/*
Container port
*/}}
{{- define "harbor.portal.port" -}}
80
{{- end }}

{{/*
Container port
*/}}
{{- define "harbor.portal.service.port" -}}
8080
{{- end }}

{{/*
Return the Registry name
*/}}
{{- define "harbor.registry.name" -}}
{{ include "harbor.fullname" . }}-registry
{{- end }}

{{/*
Return the Registry internal URL
*/}}
{{- define "harbor.registry.url" -}}
http://{{ include "harbor.fullname" . }}-registry:5000
{{- end }}

{{/*
Container port
*/}}
{{- define "harbor.registry.port" -}}
5000
{{- end }}

{{/*
The registryctl sidecar exists for registry images without the GC deletion
API: vanilla goharbor (image.source=upstream) and Harbor Next releases before
2.17.0. Their jobservice deletes GC blobs through registryctl, and on 404 it
drops the DB rows and keeps the blobs, so pointing it at such a registry
would leak storage silently. Harbor Next 2.17.0+ registries serve the
deletion API themselves. registry.controller.enabled overrides the guess for
images the tag can't classify (digests, custom tags).
*/}}
{{- define "harbor.registryctl.enabled" -}}
{{- $set := (.Values.registry.controller | default dict).enabled -}}
{{- if kindIs "bool" $set -}}
{{- if $set -}}true{{- end -}}
{{- else if or (eq (.Values.image.source | default "8gcr") "upstream") (include "harbor.registry.preGCAPI" .) -}}true
{{- end -}}
{{- end }}

{{/*
True when the 8gcr registry image is a release older than 2.17.0, the first
with the GC deletion API (pinned tags, or the 2.16 appVersion on main before
the 2.17 release). Digests and non-release tags are taken as current builds.
Only major.minor.patch is compared: prereleases of 2.17.0 count as new, and
sprig can't parse every prerelease a tag may carry (rc.01).
*/}}
{{- define "harbor.registry.preGCAPI" -}}
{{- $img := .Values.registry.image | default dict -}}
{{- if and (ne (.Values.image.source | default "8gcr") "upstream") (not $img.digest) -}}
{{- $tag := $img.tag | default .Chart.AppVersion | toString -}}
{{- if regexMatch "^v?[0-9]+\\.[0-9]+\\.[0-9]+(-[0-9A-Za-z.-]+)?(\\+[0-9A-Za-z.-]+)?$" $tag -}}
{{- if semverCompare "<2.17.0" (regexReplaceAll "^v?([0-9]+\\.[0-9]+\\.[0-9]+).*$" $tag "${1}") -}}true{{- end -}}
{{- end -}}
{{- end -}}
{{- end }}

{{/*
registryctl image. Harbor Next sidecars follow the registry tag so a pinned
registry.image.tag keeps a matching registryctl.
*/}}
{{- define "harbor.registryctl.image" -}}
{{- $img := deepCopy (.Values.registry.controller.image | default dict) -}}
{{- if and (ne (.Values.image.source | default "8gcr") "upstream") (not $img.tag) (not $img.digest) -}}
{{- $_ := set $img "tag" (.Values.registry.image.tag | default .Chart.AppVersion) -}}
{{- end -}}
{{- include "harbor.image" (dict "imageRoot" $img "component" "registryctl" "root" .) -}}
{{- end }}

{{- define "harbor.registryctl.port" -}}
8080
{{- end }}

{{/* The harbor-scanner-trivy subchart wins when both modes are enabled. TODO(2.17): drop built-in mode. */}}
{{- define "harbor.trivy.builtin" -}}
{{ and .Values.trivy.enabled (not (index .Values "harbor-scanner-trivy").enabled) }}
{{- end }}

{{/*
REGISTRY_CONTROLLER_URL for core and jobservice
*/}}
{{- define "harbor.registryController.url" -}}
{{- if include "harbor.registryctl.enabled" . -}}
http://{{ include "harbor.fullname" . }}-registry:{{ include "harbor.registryctl.port" . }}
{{- else -}}
{{ include "harbor.registry.url" . }}
{{- end -}}
{{- end }}

{{/*
Return the Trivy adapter URL (if enabled)
*/}}
{{- define "harbor.trivy.url" -}}
{{- $sub := index .Values "harbor-scanner-trivy" -}}
{{- if $sub.enabled -}}
http://{{ include "harbor.trivy" . }}:{{ ($sub.service).port | default 8080 }}
{{- else -}}
http://{{ include "harbor.trivy" . }}:8080
{{- end -}}
{{- end }}

{{- define "harbor.trivy.enabled" -}}
{{ or .Values.trivy.enabled (index .Values "harbor-scanner-trivy").enabled }}
{{- end }}

{{/*
=============================================================================
Component name helpers (used by noProxy and other cross-component references)
=============================================================================
*/}}

{{- define "harbor.portal" -}}
  {{- printf "%s-portal" (include "harbor.fullname" .) -}}
{{- end -}}

{{- define "harbor.core" -}}
  {{- printf "%s-core" (include "harbor.fullname" .) -}}
{{- end -}}

{{- define "harbor.valkey" -}}
  {{- printf "%s-valkey" .Release.Name -}}
{{- end -}}

{{- define "harbor.registry" -}}
  {{- printf "%s-registry" (include "harbor.fullname" .) -}}
{{- end -}}

{{- define "harbor.database" -}}
  {{- printf "%s-database" (include "harbor.fullname" .) -}}
{{- end -}}

{{/* Subchart mode mirrors harbor-scanner-trivy's fullname helper. */}}
{{- define "harbor.trivy" -}}
  {{- $sub := index .Values "harbor-scanner-trivy" -}}
  {{- $name := default "harbor-scanner-trivy" $sub.nameOverride -}}
  {{- if not $sub.enabled -}}
    {{- printf "%s-trivy" (include "harbor.fullname" .) -}}
  {{- else if $sub.fullnameOverride -}}
    {{- $sub.fullnameOverride | trunc 63 | trimSuffix "-" -}}
  {{- else -}}
    {{- ternary .Release.Name (printf "%s-%s" .Release.Name $name) (contains $name .Release.Name) | trunc 63 | trimSuffix "-" -}}
  {{- end -}}
{{- end -}}

{{- define "harbor.nginx" -}}
  {{- printf "%s-nginx" (include "harbor.fullname" .) -}}
{{- end -}}

{{- define "harbor.exporter" -}}
  {{- printf "%s-exporter" (include "harbor.fullname" .) -}}
{{- end -}}

{{- define "harbor.ingress" -}}
  {{- printf "%s-ingress" (include "harbor.fullname" .) -}}
{{- end -}}

{{- define "harbor.ingress.secret" -}}
{{- printf "%s-ingress-tls" (include "harbor.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "harbor.ingress.primaryHost" -}}
{{- if gt (len .Values.ingress.hosts) 0 -}}
{{- (index .Values.ingress.hosts 0).host -}}
{{- else -}}
{{- (urlParse .Values.externalURL).hostname -}}
{{- end -}}
{{- end -}}

{{- define "harbor.route" -}}
  {{- printf "%s-route" (include "harbor.fullname" .) -}}
{{- end -}}

{{- define "harbor.noProxy" -}}
  {{- printf "%s,%s,%s,%s,%s,%s,%s,%s" (include "harbor.core" .) (include "harbor.jobservice" .) (include "harbor.database" .) (include "harbor.registry" .) (include "harbor.portal" .) (include "harbor.trivy" .) (include "harbor.exporter" .) .Values.proxy.noProxy -}}
{{- end -}}

{{/*
=============================================================================
Metrics helpers
=============================================================================
*/}}

{{/*
Container subpath
*/}}
{{- define "harbor.metrics.path" -}}
/metrics
{{- end }}

{{/*
Container port
*/}}
{{- define "harbor.metrics.port" -}}
8001
{{- end }}

{{/*
=============================================================================
External URL helpers
=============================================================================
*/}}

{{/*
Return the external URL
*/}}
{{- define "harbor.externalURL" -}}
{{- .Values.externalURL }}
{{- end }}

{{/*
Return the core external URL (same as externalURL for now)
*/}}
{{- define "harbor.coreURL" -}}
{{- include "harbor.externalURL" . }}
{{- end }}
