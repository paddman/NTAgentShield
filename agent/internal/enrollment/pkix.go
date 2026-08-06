package enrollment

import "crypto/x509/pkix"

func pkixName(agentID string) pkix.Name {
	return pkix.Name{
		CommonName:   agentID,
		Organization: []string{"NTAgentShield"},
	}
}
