# Authorization Router
#
# Routes ext_authz requests to the appropriate policy based on context.
# This allows a single OPA instance to handle both gateway auth and egress auth.
#
# Routing is based on the x-authz-context header or source port:
# - "gateway" -> agentd.gateway.authz
# - "egress"  -> agentd.egress.authz

package agentd.authz

import rego.v1

import data.agentd.gateway.authz as gateway
import data.agentd.egress.authz as egress

# Determine which auth context we're in
authz_context := context if {
    context := input.attributes.request.http.headers["x-authz-context"]
} else := context if {
    # Infer from destination port or path patterns
    dest_port := input.attributes.destination.address.socketAddress.portValue
    dest_port == 8443
    context := "egress"
} else := "gateway"

# Route to appropriate policy
default allow := false

allow if {
    authz_context == "gateway"
    gateway.allow
}

allow if {
    authz_context == "egress"
    egress.allow
}

# Aggregate headers from sub-policies
headers := gateway.headers if {
    authz_context == "gateway"
}

headers := egress.headers if {
    authz_context == "egress"
}

# Response headers
response_headers := egress.response_headers if {
    authz_context == "egress"
}

# Deny reasons for debugging
deny_reasons := gateway.deny_reasons if {
    authz_context == "gateway"
}

deny_reasons := egress.deny_reasons if {
    authz_context == "egress"
}
