package main

import (
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
)

// TestPluginBinaryServesRunnerV2 builds the plugin binary and drives it the way the agent
// does: go-plugin with runner.HandshakeConfig, dispense "runner", then Init and Eval over
// gRPC, with the ApiHelper served back to the plugin through the broker.
func TestPluginBinaryServesRunnerV2(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and launches the plugin binary")
	}

	bin := filepath.Join(t.TempDir(), "plugin")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}

	client := goplugin.NewClient(&goplugin.ClientConfig{
		HandshakeConfig: runner.HandshakeConfig,
		Plugins: map[string]goplugin.Plugin{
			"runner": &runner.RunnerV2GRPCPlugin{},
		},
		Cmd:              exec.Command(bin),
		AllowedProtocols: []goplugin.Protocol{goplugin.ProtocolGRPC},
		Logger:           hclog.NewNullLogger(),
	})
	t.Cleanup(client.Kill)

	rpcClient, err := client.Client()
	if err != nil {
		t.Fatalf("connect to plugin: %v", err)
	}
	raw, err := rpcClient.Dispense("runner")
	if err != nil {
		t.Fatalf("dispense runner: %v", err)
	}
	plugin, ok := raw.(runner.RunnerV2)
	if !ok {
		t.Fatalf("dispensed %T, want a runner.RunnerV2", raw)
	}

	if _, err := plugin.Configure(&proto.ConfigureRequest{Config: map[string]string{"any": "value"}}); err != nil {
		t.Fatalf("Configure: %v", err)
	}

	api := &fakeApiHelper{}
	if _, err := plugin.Init(&proto.InitRequest{}, api); err != nil {
		t.Fatalf("Init: %v", err)
	}
	api.mu.Lock()
	if len(api.subjectTemplates) != 1 || api.subjectTemplates[0].GetName() != pluginName {
		t.Errorf("subject templates = %v, want the one %s template", api.subjectTemplates, pluginName)
	}
	api.mu.Unlock()

	policyPath, err := filepath.Abs("testdata/policies")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := plugin.Eval(&proto.EvalRequest{PolicyPaths: []string{policyPath}}, api)
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if resp.GetStatus() != proto.ExecutionStatus_SUCCESS {
		t.Errorf("Eval status = %s, want SUCCESS", resp.GetStatus())
	}
	api.mu.Lock()
	defer api.mu.Unlock()
	if len(api.evidence) != 1 {
		t.Errorf("got %d evidence over gRPC, want 1", len(api.evidence))
	}
}
