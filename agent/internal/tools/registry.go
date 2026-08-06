package tools

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/paddman/NTAgentShield/internal/model"
	"github.com/paddman/NTAgentShield/internal/policy"
)

type Spec struct {
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Risk        model.ActionRisk `json:"risk"`
}

type Result struct {
	Tool string      `json:"tool"`
	Data interface{} `json:"data,omitempty"`
}

type Tool interface {
	Spec() Spec
	Execute(context.Context, map[string]interface{}) (interface{}, error)
}

type Registry struct {
	mu     sync.RWMutex
	tools  map[string]Tool
	policy *policy.Engine
}

func NewRegistry(engine *policy.Engine) *Registry {
	return &Registry{tools: map[string]Tool{}, policy: engine}
}

func (r *Registry) Register(tool Tool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	spec := tool.Spec()
	if spec.Name == "" {
		return errors.New("tool name is required")
	}
	if _, exists := r.tools[spec.Name]; exists {
		return fmt.Errorf("tool %q is already registered", spec.Name)
	}
	r.tools[spec.Name] = tool
	return nil
}

func (r *Registry) Specs() []Spec {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]Spec, 0, len(r.tools))
	for _, tool := range r.tools {
		result = append(result, tool.Spec())
	}
	return result
}

func (r *Registry) Execute(ctx context.Context, request model.ActionRequest) (Result, model.Decision, error) {
	r.mu.RLock()
	tool, exists := r.tools[request.Tool]
	r.mu.RUnlock()
	if !exists {
		return Result{}, model.Decision{Allowed: false, Reason: "unknown tool", Risk: request.Risk}, fmt.Errorf("unknown tool %q", request.Tool)
	}
	request.Risk = tool.Spec().Risk
	decision := r.policy.Evaluate(request)
	if !decision.Allowed {
		return Result{}, decision, nil
	}
	data, err := tool.Execute(ctx, request.Args)
	if err != nil {
		return Result{}, decision, err
	}
	return Result{Tool: request.Tool, Data: data}, decision, nil
}
