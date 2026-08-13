{{/*
SPDX-FileCopyrightText: 2026 Portscanner contributors
SPDX-License-Identifier: MIT
*/}}

{{- define "portscanner.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end }}

{{- define "portscanner.fullname" -}}
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
{{- end }}

{{- define "portscanner.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
app.kubernetes.io/name: {{ include "portscanner.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "portscanner.selectorLabels" -}}
app.kubernetes.io/name: {{ include "portscanner.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: operator
{{- end }}

{{- define "portscanner.operatorServiceAccountName" -}}
{{- default (printf "%s-operator" (include "portscanner.fullname" .)) .Values.operator.serviceAccount.name -}}
{{- end }}

{{- define "portscanner.scannerServiceAccountName" -}}
{{- default (printf "%s-scanner" (include "portscanner.fullname" .)) .Values.scanner.serviceAccount.name -}}
{{- end }}

{{- define "portscanner.operatorImage" -}}
{{- $repository := required "operator.image.repository is required" .Values.operator.image.repository -}}
{{- $digest := required "operator.image.digest is required" .Values.operator.image.digest -}}
{{- if not (regexMatch "^sha256:[0-9a-f]{64}$" $digest) -}}
{{- fail "operator.image.digest must be a lowercase sha256 OCI digest" -}}
{{- end -}}
{{- printf "%s@%s" $repository $digest -}}
{{- end }}

{{- define "portscanner.scannerImage" -}}
{{- $repository := required "scanner.image.repository is required" .Values.scanner.image.repository -}}
{{- $digest := required "scanner.image.digest is required" .Values.scanner.image.digest -}}
{{- if not (regexMatch "^sha256:[0-9a-f]{64}$" $digest) -}}
{{- fail "scanner.image.digest must be a lowercase sha256 OCI digest" -}}
{{- end -}}
{{- printf "%s@%s" $repository $digest -}}
{{- end }}
