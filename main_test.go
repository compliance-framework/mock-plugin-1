package main

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/compliance-framework/agent/runner/proto"
	"github.com/hashicorp/go-hclog"
	"google.golang.org/protobuf/types/known/structpb"
)

// fakeApiHelper records what a plugin sends to the agent.
type fakeApiHelper struct {
	mu                sync.Mutex
	subjectTemplates  []*proto.SubjectTemplate
	riskTemplates     map[string][]*proto.RiskTemplate
	evidence          []*proto.Evidence
	upsertSubjectsErr error
}

func (f *fakeApiHelper) CreateEvidence(_ context.Context, evidence []*proto.Evidence) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.evidence = append(f.evidence, evidence...)
	return nil
}

func (f *fakeApiHelper) UpsertRiskTemplates(_ context.Context, packageName string, templates []*proto.RiskTemplate) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.riskTemplates == nil {
		f.riskTemplates = map[string][]*proto.RiskTemplate{}
	}
	f.riskTemplates[packageName] = append(f.riskTemplates[packageName], templates...)
	return nil
}

func (f *fakeApiHelper) UpsertSubjectTemplates(_ context.Context, templates []*proto.SubjectTemplate) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.upsertSubjectsErr != nil {
		return f.upsertSubjectsErr
	}
	f.subjectTemplates = append(f.subjectTemplates, templates...)
	return nil
}

func newTestPlugin() *MockPlugin {
	return &MockPlugin{logger: hclog.NewNullLogger()}
}

func TestName(t *testing.T) {
	if got := newTestPlugin().Name(); got != "mock-plugin-1" {
		t.Fatalf("Name() = %q, want %q", got, "mock-plugin-1")
	}
}

func TestInitUpsertsOneSubjectTemplate(t *testing.T) {
	api := &fakeApiHelper{}
	resp, err := newTestPlugin().Init(&proto.InitRequest{PolicyPaths: []string{"testdata/policies"}}, api)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	if resp == nil {
		t.Fatal("Init returned a nil response")
	}
	if len(api.subjectTemplates) != 1 {
		t.Fatalf("got %d subject templates, want 1", len(api.subjectTemplates))
	}
	tmpl := api.subjectTemplates[0]
	if tmpl.GetName() != pluginName || tmpl.GetType() != proto.SubjectType_SUBJECT_TYPE_COMPONENT {
		t.Errorf("subject template = %s/%s, want %s/SUBJECT_TYPE_COMPONENT", tmpl.GetName(), tmpl.GetType(), pluginName)
	}
	// The test policy declares no risk_templates, so its package is upserted with none.
	if templates, ok := api.riskTemplates["compliance_framework.mock_enabled"]; !ok || len(templates) != 0 {
		t.Errorf("risk templates = %v, want the mock_enabled package with no templates", api.riskTemplates)
	}
}

func TestInitFailsWhenSubjectTemplatesCannotBeUpserted(t *testing.T) {
	want := errors.New("api unavailable")
	_, err := newTestPlugin().Init(&proto.InitRequest{}, &fakeApiHelper{upsertSubjectsErr: want})
	if !errors.Is(err, want) {
		t.Fatalf("Init error = %v, want %v", err, want)
	}
}

func TestConfigureAcceptsAnyConfig(t *testing.T) {
	policyData, err := structpb.NewStruct(map[string]interface{}{"threshold": 1})
	if err != nil {
		t.Fatal(err)
	}
	p := newTestPlugin()
	_, err = p.Configure(&proto.ConfigureRequest{
		Config:     map[string]string{"anything": "goes"},
		PolicyData: policyData,
	})
	if err != nil {
		t.Fatalf("Configure: %v", err)
	}
	if p.policyData["threshold"] != float64(1) {
		t.Errorf("policy data = %v, want threshold=1", p.policyData)
	}
}

func TestEvalSendsOneEvidence(t *testing.T) {
	api := &fakeApiHelper{}
	p := newTestPlugin()
	if _, err := p.Configure(&proto.ConfigureRequest{}); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	resp, err := p.Eval(&proto.EvalRequest{PolicyPaths: []string{"testdata/policies"}}, api)
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if resp.GetStatus() != proto.ExecutionStatus_SUCCESS {
		t.Errorf("status = %s, want SUCCESS", resp.GetStatus())
	}
	if len(api.evidence) != 1 {
		t.Fatalf("got %d evidence, want 1", len(api.evidence))
	}
	ev := api.evidence[0]
	if ev.GetTitle() != "Mock plugin is enabled" {
		t.Errorf("title = %q", ev.GetTitle())
	}
	if ev.GetStatus().GetState() != proto.EvidenceStatusState_EVIDENCE_STATUS_STATE_SATISFIED {
		t.Errorf("state = %s, want SATISFIED", ev.GetStatus().GetState())
	}
	if ev.GetLabels()["plugin"] != pluginName {
		t.Errorf("labels = %v, want plugin=%s", ev.GetLabels(), pluginName)
	}
}

func TestEvalFailsOnABadPolicyPath(t *testing.T) {
	api := &fakeApiHelper{}
	resp, err := newTestPlugin().Eval(&proto.EvalRequest{PolicyPaths: []string{"testdata/does-not-exist"}}, api)
	if err == nil {
		t.Fatal("Eval: want an error for a missing policy path")
	}
	if resp.GetStatus() != proto.ExecutionStatus_FAILURE {
		t.Errorf("status = %s, want FAILURE", resp.GetStatus())
	}
	if len(api.evidence) != 0 {
		t.Errorf("got %d evidence, want none", len(api.evidence))
	}
}
