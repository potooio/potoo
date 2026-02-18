# Adapter Guide

## Overview

Adapters are the pluggable components that parse specific constraint resource types into normalized `Constraint` models. Each adapter knows how to read a particular CRD or native Kubernetes resource and extract the information needed for constraint indexing and developer notification.

## Adapter Interface

Every adapter implements this interface (defined in `internal/types/adapter.go`):

```go
type Adapter interface {
    // Name returns a unique identifier for this adapter (e.g., "cilium-network-policy").
    Name() string

    // Handles returns the GVRs this adapter can parse.
    // The discovery engine uses this to route objects to the correct adapter.
    Handles() []schema.GroupVersionResource

    // Parse converts an unstructured Kubernetes object into zero or more
    // normalized Constraint models. Returns multiple constraints when a
    // single policy object contains multiple rules.
    //
    // Parse must be safe to call concurrently.
    // Parse must not modify the input object.
    // Parse should return a descriptive error on failure, not panic.
    Parse(ctx context.Context, obj *unstructured.Unstructured) ([]Constraint, error)
}
```

## Writing a New Adapter

### Step 1: Create the adapter package

```
internal/adapters/myadapter/
├── adapter.go        # Adapter implementation
├── adapter_test.go   # Tests
└── testdata/          # Fixture YAML files
    ├── basic_policy.yaml
    ├── complex_policy.yaml
    └── edge_case.yaml
```

### Step 2: Implement the interface

```go
package myadapter

import (
    "context"

    "k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
    "k8s.io/apimachinery/pkg/runtime/schema"
    "github.com/potooio/docs/internal/types"
)

type Adapter struct{}

func New() *Adapter {
    return &Adapter{}
}

func (a *Adapter) Name() string {
    return "my-policy-engine"
}

func (a *Adapter) Handles() []schema.GroupVersionResource {
    return []schema.GroupVersionResource{
        {Group: "mypolicy.io", Version: "v1", Resource: "mypolicies"},
    }
}

func (a *Adapter) Parse(ctx context.Context, obj *unstructured.Unstructured) ([]types.Constraint, error) {
    // 1. Extract fields from the unstructured object
    spec, found, err := unstructured.NestedMap(obj.Object, "spec")
    if err != nil || !found {
        return nil, fmt.Errorf("missing spec: %w", err)
    }

    // 2. Parse policy-specific fields
    // Use unstructured.NestedString, NestedSlice, NestedMap, etc.
    // DO NOT import typed client libraries as hard dependencies.

    // 3. Build normalized Constraint(s)
    constraint := types.Constraint{
        UID:            obj.GetUID(),
        Source:         schema.GroupVersionResource{Group: "mypolicy.io", Version: "v1", Resource: "mypolicies"},
        Name:           obj.GetName(),
        Namespace:      obj.GetNamespace(),
        ConstraintType: types.ConstraintTypeAdmission,
        Effect:         "deny",
        Severity:       types.SeverityWarning,
        Summary:        "Human-readable description of what this policy does",
        RawObject:      obj.DeepCopy(),
    }

    return []types.Constraint{constraint}, nil
}
```

### Step 3: Register the adapter

In `internal/adapters/registry.go`, add your adapter to the registry:

```go
func NewRegistry() *Registry {
    r := &Registry{}
    r.Register(networkpolicy.New())
    r.Register(resourcequota.New())
    r.Register(cilium.New())
    r.Register(myadapter.New())  // Add here
    return r
}
```

### Step 4: Write tests

```go
func TestParse_BasicPolicy(t *testing.T) {
    adapter := New()
    obj := loadFixture(t, "testdata/basic_policy.yaml")

    constraints, err := adapter.Parse(context.Background(), obj)
    require.NoError(t, err)
    require.Len(t, constraints, 1)

    assert.Equal(t, "my-policy", constraints[0].Name)
    assert.Equal(t, types.ConstraintTypeAdmission, constraints[0].ConstraintType)
    assert.Equal(t, types.SeverityWarning, constraints[0].Severity)
}
```

## Best Practices

1. **Parse from `unstructured.Unstructured`**, not typed clients. This prevents import-time panics when the CRD isn't installed.

2. **Handle missing fields gracefully**. CRD schemas change between versions. Use defensive field access:
   ```go
   val, found, err := unstructured.NestedString(obj.Object, "spec", "action")
   if !found {
       val = "deny" // sensible default
   }
   ```

3. **Return multiple constraints** when a single policy object contains multiple rules. A Kyverno ClusterPolicy with 5 rules should produce 5 Constraint objects.

4. **Write clear Summary strings**. These appear in developer notifications. Bad: "CiliumNetworkPolicy ingress rule". Good: "Allows ingress only from pods with label app=frontend on port 8080".

5. **Set Severity appropriately**:
   - `Critical`: Active traffic drops, admission rejections in Enforce mode
   - `Warning`: Audit-mode violations, approaching quota limits, missing prerequisites
   - `Info`: Informational constraints that aren't actively blocking anything

6. **Include RemediationHint** when possible. "Add label `team: your-team` to your pod" is more useful than "label required."

7. **Populate AffectedNamespaces and WorkloadSelector** for accurate correlation. If you can't determine scope, leave them empty — the generic indexer will treat it as potentially cluster-wide.

## Testing Fixtures

Store test fixtures as YAML files in `testdata/`. Each fixture should be a complete Kubernetes object:

```yaml
# testdata/basic_policy.yaml
apiVersion: mypolicy.io/v1
kind: MyPolicy
metadata:
  name: require-labels
  namespace: default
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
  rules:
    - name: must-have-team-label
      validate:
        message: "All pods must have a 'team' label"
        pattern:
          metadata:
            labels:
              team: "?*"
```

Load fixtures with the shared test helper:

```go
func loadFixture(t *testing.T, path string) *unstructured.Unstructured {
    t.Helper()
    data, err := os.ReadFile(path)
    require.NoError(t, err)

    obj := &unstructured.Unstructured{}
    err = yaml.Unmarshal(data, &obj.Object)
    require.NoError(t, err)

    return obj
}
```
