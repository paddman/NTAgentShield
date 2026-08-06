package transport

import "github.com/paddman/NTAgentShield/internal/enrollment"

func (c *Client) Metadata() enrollment.Metadata {
	if c == nil {
		return enrollment.Metadata{}
	}
	return c.metadata
}
