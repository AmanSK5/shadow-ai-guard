{{- define "ai-guard.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "ai-guard.fullname" -}}
{{- $name := include "ai-guard.name" . -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "ai-guard.labels" -}}
app.kubernetes.io/name: {{ include "ai-guard.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "ai-guard.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ai-guard.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/* Name of the Secret holding the bearer token. */}}
{{- define "ai-guard.secretName" -}}
{{- if .Values.auth.existingSecret -}}
{{- .Values.auth.existingSecret -}}
{{- else -}}
{{- include "ai-guard.fullname" . -}}
{{- end -}}
{{- end -}}

{{/* Name of the ConfigMap holding the compiled registry. */}}
{{- define "ai-guard.registryConfigMap" -}}
{{- if .Values.registry.existingConfigMap -}}
{{- .Values.registry.existingConfigMap -}}
{{- else -}}
{{- printf "%s-registry" (include "ai-guard.fullname" .) -}}
{{- end -}}
{{- end -}}
