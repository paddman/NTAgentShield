# Signed Agent Enrollment and mTLS

NTAgentShield uses a two-stage trust bootstrap so an unenrolled endpoint never needs a long-lived shared credential.

## Trust flow

1. An operator initializes the Control Plane enrollment CA once.
2. The operator creates a short-lived, tenant-scoped enrollment token.
3. The endpoint creates or loads its persistent Ed25519 identity key locally.
4. The endpoint creates an Ed25519 CSR and sends it to the HTTPS enrollment endpoint with the bootstrap token.
5. The Control Plane verifies the signed token, consumes its nonce once, validates the CSR, and signs a client certificate.
6. The endpoint verifies that the returned certificate contains its own public key, has the requested Agent ID, chains to the returned CA, and is valid for TLS client authentication.
7. Future remote transport can use the issued certificate for mutual TLS.

The bootstrap token is not a permanent Agent secret. It is HMAC-signed, tenant-scoped, time-limited, and its nonce is persisted in SQLite so a successfully consumed token cannot be replayed after a Control Plane restart.

## Control Plane setup

Set an enrollment signing secret with at least 32 characters. Do not commit this value.

```bash
export NTSHIELD_ENROLLMENT_ENABLED=true
export NTSHIELD_ENROLLMENT_SIGNING_SECRET='replace-with-a-long-random-secret'

ntshield init-ca
ntshield enrollment-token --tenant demo-tenant --ttl 600 > enrollment.token
```

The default CA paths are:

```text
./data/pki/enrollment-ca.crt
./data/pki/enrollment-ca.key
```

`init-ca` refuses to overwrite an existing CA.

## Enrollment endpoint

Bootstrap enrollment must be exposed over server-authenticated HTTPS. For example:

```bash
ntshield serve \
  --host 0.0.0.0 \
  --port 8443 \
  --ssl-certfile /etc/ntshield/server.crt \
  --ssl-keyfile /etc/ntshield/server.key
```

The enrollment API is:

```text
POST /v1/enrollment
Authorization: Bearer <short-lived-token>
```

Do not expose an HTTP-only enrollment listener on an untrusted network.

## Endpoint enrollment

Copy the short-lived token to the endpoint through an approved provisioning path, then run:

```bash
cd agent

go run ./cmd/ntagentshield-enroll \
  --config config/agent.example.json \
  --endpoint https://control.example/v1/enrollment \
  --token-file enrollment.token
```

For a private bootstrap CA, add:

```text
--bootstrap-ca /path/to/bootstrap-ca.crt
```

On success the Agent data directory contains:

```text
agent-identity.key     persistent Ed25519 identity private key
certs/client.crt       issued TLS client certificate
certs/ca.crt           issuing NTAgentShield CA certificate
```

The enrollment CLI prints the certificate paths, expiration time, and identity fingerprint. It never prints the private key.

## mTLS listener

A Control Plane listener can require client certificates:

```bash
ntshield serve \
  --host 0.0.0.0 \
  --port 9443 \
  --ssl-certfile /etc/ntshield/server.crt \
  --ssl-keyfile /etc/ntshield/server.key \
  --ssl-ca-certs ./data/pki/enrollment-ca.crt \
  --require-client-cert
```

Use separate bootstrap and mTLS listeners, or equivalent reverse-proxy routing. An endpoint that does not yet have a client certificate cannot call an endpoint whose TLS listener already requires one. Humanity has not yet found a way for a certificate to authenticate itself before it exists.

## Persistent signed inventory baseline

The endpoint signs its local inventory baseline with the same Ed25519 identity key. The baseline survives Agent restarts and is used to seed inventory drift detection before the next inventory snapshot.

If the baseline signature is invalid, the signer does not match the local Agent identity, or the file is malformed, Agent startup fails instead of silently accepting a new baseline. Inventory is redacted before the signed baseline is written.

## Security boundaries

- Enrollment endpoints require HTTPS.
- Bootstrap tokens are tenant-scoped and expire.
- Token nonces are one-time and persisted.
- Agent private keys are generated locally and are never returned by the Control Plane.
- Client certificates must contain the Agent's public key and ClientAuth EKU.
- Client certificates carry Agent ID in the subject and a tenant/agent URI SAN.
- The local Agent API remains loopback-only and does not become a remote command channel.
- mTLS establishes transport identity. It does not grant AI permission to mutate the endpoint.

## Windows private-key protection

Go's POSIX file mode bits are not Windows ACLs. The Agent requests restrictive file modes where supported, but production Windows packaging must additionally install the Agent data directory with a DACL limited to `SYSTEM`, `Administrators`, and the NTAgentShield service identity. Do not treat `chmod 0600` as a Windows security boundary.

## Current scope

This change provisions identity, enrollment certificates, mTLS TLS configuration, and persistent signed inventory state. It intentionally does not yet send Go Agent telemetry to the Python Control Plane because the two event schemas require an explicit, tested mapping rather than a lossy JSON shove. The next transport slice should add that mapping, a durable outbound queue, certificate rotation, and backpressure handling.
