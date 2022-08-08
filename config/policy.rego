package envoy.authz

import input.attributes.request.http as http_request
import input.parsed_query as query_params

# Decline until I allow it.
default allow = false

### TOKEN ###
# Gets the token form query
jwt_token = token {
  token := io.jwt.decode(query_params.token[0])
}

# Gets the token form header
{{- if .Values.shared.authentication.opa.customHeaderName }}
jwt_token = token {
  token := io.jwt.decode(http_request.headers[{{ .Values.shared.authentication.opa.customHeaderName | lower | quote }}])
}
{{- end }}

# extract payload from token
payload = payload {
  [_, payload, _] := jwt_token
}
### TOKEN ###

### Resources Access ###
user_has_resource_access[payload] {
  lower(payload.d[_]) = {{ .Values.shared.authentication.opa.domains | lower | quote }}
}
### Resources Access ###

### ORIGIN ###
# Checks if origin is in allowed origin
valid_origin[payload] {
  payload.ao[_] = http_request.headers.origin
}

# Checks if origin is allowed origin (if ao is not an arr)
valid_origin[payload] {
  payload.ao == http_request.headers.origin
}

# Checks if there is allowed origin
valid_origin[payload] {
  not payload.ao
}
### ORIGIN ###

# allow authenticated acess
allow {
  valid_origin[payload]
  user_has_resource_access[payload]
}

# allow cors preflight WITHOUT AUTHENTICATION
allow {
  http_request.method == "OPTIONS"
  _ = http_request.headers["access-control-request-method"]
  _ = http_request.headers["access-control-request-headers"]
}
