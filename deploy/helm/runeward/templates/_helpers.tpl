{{/* Expand the chart name. */}}
{{- define "runeward.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Fully qualified app name. */}}
{{- define "runeward.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* Common labels. */}}
{{- define "runeward.labels" -}}
app.kubernetes.io/name: {{ include "runeward.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
{{- end -}}

{{/* Selector labels. */}}
{{- define "runeward.selectorLabels" -}}
app.kubernetes.io/name: {{ include "runeward.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/* Service account name. */}}
{{- define "runeward.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "runeward.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* Image tag: image.tag, or the release tag ("v" + appVersion) images are published under. */}}
{{- define "runeward.imageTag" -}}
{{- default (printf "v%s" .Chart.AppVersion) .Values.image.tag -}}
{{- end -}}

{{/* Container image reference. */}}
{{- define "runeward.image" -}}
{{- printf "%s:%s" .Values.image.repository (include "runeward.imageTag" .) -}}
{{- end -}}

{{/* Egress sidecar image: egress.image, or the matching runeward-egress release. */}}
{{- define "runeward.egressImage" -}}
{{- default (printf "%s-egress:%s" .Values.image.repository (include "runeward.imageTag" .)) .Values.egress.image -}}
{{- end -}}

{{/* Name of the profiles Secret (existing or chart-created). */}}
{{- define "runeward.profilesSecretName" -}}
{{- if .Values.profiles.existingSecret -}}
{{- .Values.profiles.existingSecret -}}
{{- else -}}
{{- printf "%s-profiles" (include "runeward.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/*
Volume source for the profiles mount. Profiles can contain secret material, so
the chart stores them in a Secret by default. An existing ConfigMap is still
honored for backward compatibility.
*/}}
{{- define "runeward.profilesVolume" -}}
{{- if .Values.profiles.existingConfigMap -}}
configMap:
  name: {{ .Values.profiles.existingConfigMap }}
  optional: true
{{- else -}}
secret:
  secretName: {{ include "runeward.profilesSecretName" . }}
  optional: true
{{- end -}}
{{- end -}}

{{/* Name of the server API token Secret (existing or chart-created). */}}
{{- define "runeward.serverTokenSecretName" -}}
{{- default (printf "%s-server-token" (include "runeward.fullname" .)) .Values.server.auth.existingSecret -}}
{{- end -}}

{{/* Name of the server TLS Secret (existing or chart-created). */}}
{{- define "runeward.serverTLSSecretName" -}}
{{- default (printf "%s-server-tls" (include "runeward.fullname" .)) .Values.server.tls.existingSecret -}}
{{- end -}}
