# mock-plugin-1

Mock repo for developing CCF release automation. Not a product.

It is a real, minimal CCF agent plugin speaking protocol v2 (`runner.RunnerV2`, served
under `"runner"`), so plugin tooling such as plugin-probe and the plugin release flow
can run against it:

- `Configure` accepts any config;
- `Init` registers one subject template, plus the risk templates of each policy path;
- `Eval` evaluates each policy path against a fixed input and sends the evidence.

```sh
go test ./...                                      # includes launching the built binary over go-plugin
go test -short ./...                               # unit tests only
goreleaser build --snapshot --clean --single-target
```

`testdata/policies` holds a policy that yields one piece of evidence.
