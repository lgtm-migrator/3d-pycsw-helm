{{/* vim: set filetype=mustache: */}}
{{/*
Expand the name of the chart.
*/}}
{{- define "catalog.name" -}}
{{- default .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "catalog.fullname" -}}
{{- $name := default .Chart.Name -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "catalog" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "pycsw-pg-connection-string" -}}
{{- "postgresql://${DB_USER}" -}}
{{- if .Values.shared.DB.requirePassword -}}
{{- ":${DB_PASSWORD}" -}}
{{- end -}}
{{- "@${DB_HOST}:${DB_PORT}/${DB_NAME}" -}}
{{- if .Values.shared.DB.SSL.enabled -}}
{{- "?sslmode=require" -}}
{{- if .Values.postgresSecret.caFileKey -}}
{{- "&sslrootcert=" -}}/.postgresql/ca.pem
{{- end -}}
{{- if .Values.postgresSecret.certFileKey -}}
{{- "&sslcert=" -}}/.postgresql/cert.pem
{{- end -}}
{{- if .Values.postgresSecret.keyFileKey -}}
{{- "&sslkey=" -}}/.postgresql/key.pem
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "pycsw.cors.allowedHeaders" -}}
{{- $headerList := list -}}
{{- if ne .Values.pycsw.env.cors.allowedHeaders "" -}}
{{- range $k, $v := (split "," .Values.pycsw.env.cors.allowedHeaders) -}}
{{- $headerList = append $headerList $v -}}
{{- end -}}
{{- if ne .Values.authentication.opa.customHeaderName "" -}}
{{- $headerList = append $headerList .Values.authentication.opa.customHeaderName -}}
{{- end -}}
{{- $headerList = uniq $headerList -}}
{{-  quote (join "," $headerList) -}}
{{- else -}}
{{- .Values.authentication.opa.customHeaderName | quote -}}
{{- end -}}
{{- end -}}