// Command plugin is mock-plugin-1: a minimal CCF agent plugin speaking protocol v2.
// It exists to exercise plugin tooling (plugin-probe, the plugin release flow) against
// a real binary, not to assess anything. It follows plugin-github-settings' main.go.
package main

import (
	"context"
	"errors"

	policyManager "github.com/compliance-framework/agent/policy-manager"
	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/agent/runner/proto"
	mockrunner "github.com/compliance-framework/mock-agent/runner"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
)

// pluginName is the plugin's name, and the value of the "plugin" label on its evidence.
const pluginName = "mock-plugin-1"

var (
	_ runner.RunnerV2   = (*MockPlugin)(nil)
	_ mockrunner.Plugin = (*MockPlugin)(nil)
)

// MockPlugin implements runner.RunnerV2 (and mock-agent's runner.Plugin).
type MockPlugin struct {
	logger     hclog.Logger
	policyData map[string]interface{}
}

// Name implements mock-agent's runner.Plugin.
func (p *MockPlugin) Name() string {
	return pluginName
}

// Configure accepts any configuration; it keeps only the policy data, for later Evals.
func (p *MockPlugin) Configure(req *proto.ConfigureRequest) (*proto.ConfigureResponse, error) {
	p.logger.Debug("Configured", "config_keys", len(req.GetConfig()))
	if policyData := req.GetPolicyData(); policyData != nil {
		p.policyData = policyData.AsMap()
	} else {
		p.policyData = nil
	}
	return &proto.ConfigureResponse{}, nil
}

// subjectTemplates are the subject templates the plugin registers on Init.
func subjectTemplates() []*proto.SubjectTemplate {
	return []*proto.SubjectTemplate{
		{
			Name:                pluginName,
			Type:                proto.SubjectType_SUBJECT_TYPE_COMPONENT,
			TitleTemplate:       "Mock plugin: {{ .plugin }}",
			DescriptionTemplate: "Mock component evaluated by {{ .plugin }}",
			PurposeTemplate:     "Exercises CCF plugin tooling against a real plugin binary",
			IdentityLabelKeys:   []string{"plugin"},
			SelectorLabels:      []*proto.SubjectLabelSelector{},
			LabelSchema: []*proto.SubjectLabelSchema{
				{Key: "plugin", Description: "The name of the mock plugin"},
			},
		},
	}
}

// Init registers the subject template, and the risk templates of each policy path.
func (p *MockPlugin) Init(req *proto.InitRequest, apiHelper runner.ApiHelper) (*proto.InitResponse, error) {
	return runner.InitWithSubjectsAndRisksFromPolicies(context.Background(), p.logger, req, apiHelper, subjectTemplates())
}

// fixedInput is the data every Eval runs the policies against.
func fixedInput() map[string]interface{} {
	return map[string]interface{}{
		"plugin":  pluginName,
		"enabled": true,
	}
}

// Eval evaluates each policy path against fixedInput and sends the resulting evidence.
func (p *MockPlugin) Eval(req *proto.EvalRequest, apiHelper runner.ApiHelper) (*proto.EvalResponse, error) {
	ctx := context.Background()

	subjects := []*proto.Subject{
		{Type: proto.SubjectType_SUBJECT_TYPE_COMPONENT, Identifier: "mock/" + pluginName},
	}
	components := []*proto.Component{
		{
			Identifier:  "mock/" + pluginName,
			Type:        "service",
			Title:       "Mock plugin component",
			Description: "A fixed component reported by mock-plugin-1.",
			Purpose:     "To exercise CCF plugin tooling.",
		},
	}
	actors := []*proto.OriginActor{
		{
			Title: "Continuous Compliance Framework - mock-plugin-1",
			Type:  "tool",
			Links: []*proto.Link{
				{
					Href: "https://github.com/compliance-framework/mock-plugin-1",
					Rel:  policyManager.Pointer("reference"),
				},
			},
		},
	}

	var evalErr error
	evidences := make([]*proto.Evidence, 0)
	for _, policyPath := range req.GetPolicyPaths() {
		processor := policyManager.NewPolicyProcessor(
			p.logger,
			map[string]string{"plugin": pluginName},
			subjects,
			components,
			nil,
			actors,
			nil,
			p.policyData,
		)
		evidence, err := processor.GenerateResults(ctx, policyPath, fixedInput())
		evidences = append(evidences, evidence...)
		evalErr = errors.Join(evalErr, err)
	}

	if len(evidences) > 0 {
		if err := apiHelper.CreateEvidence(ctx, evidences); err != nil {
			p.logger.Error("Failed to send evidence", "error", err)
			return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, err
		}
	}

	if evalErr != nil {
		p.logger.Error("Failed to evaluate policies", "error", evalErr)
		return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, evalErr
	}
	return &proto.EvalResponse{Status: proto.ExecutionStatus_SUCCESS}, nil
}

func main() {
	logger := hclog.New(&hclog.LoggerOptions{
		Level:      hclog.Debug,
		JSONFormat: true,
	})

	goplugin.Serve(&goplugin.ServeConfig{
		HandshakeConfig: runner.HandshakeConfig,
		Plugins: map[string]goplugin.Plugin{
			"runner": &runner.RunnerV2GRPCPlugin{
				Impl: &MockPlugin{logger: logger},
			},
		},
		GRPCServer: goplugin.DefaultGRPCServer,
	})
}
