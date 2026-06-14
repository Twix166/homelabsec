ui = true
api_addr = "http://127.0.0.1:8200"
cluster_addr = "http://127.0.0.1:8201"

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}

storage "file" {
  path = "/bao/file"
}

# Audit devices, production TLS settings, HA storage, and auth methods are enabled
# during bootstrap after the service is reachable and recovery material can be
# stored in Vaultwarden/offline break-glass. Do not place tokens or unseal keys
# in this file.
