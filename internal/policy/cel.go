package policy

import (
	"context"
	"fmt"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

// CELExpression represents a single CEL expression to evaluate.
type CELExpression struct {
	Name    string `yaml:"name" json:"name"`
	Expr    string `yaml:"expr" json:"expr"`
	Message string `yaml:"message" json:"message"`
}

// CELEvaluator evaluates CEL expressions against input data.
type CELEvaluator struct {
	env         *cel.Env
	expressions map[string]cel.Program
}

// NewCELEvaluator creates a new CEL evaluator with the given expressions.
func NewCELEvaluator(exprs []CELExpression) (*CELEvaluator, error) {
	if len(exprs) == 0 {
		return nil, fmt.Errorf("no CEL expressions provided")
	}

	// Create CEL environment with 'input' variable
	env, err := cel.NewEnv(
		cel.Variable("input", cel.DynType),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL environment: %w", err)
	}

	// Compile all expressions
	programs := make(map[string]cel.Program)
	for _, expr := range exprs {
		if expr.Name == "" {
			return nil, fmt.Errorf("CEL expression missing name")
		}
		if expr.Expr == "" {
			return nil, fmt.Errorf("CEL expression '%s' missing expr", expr.Name)
		}

		// Compile expression
		ast, issues := env.Compile(expr.Expr)
		if issues != nil && issues.Err() != nil {
			return nil, fmt.Errorf("failed to compile CEL expression '%s': %w", expr.Name, issues.Err())
		}

		// Check that expression returns boolean
		if ast.OutputType() != cel.BoolType {
			return nil, fmt.Errorf("CEL expression '%s' must return boolean, got %v", expr.Name, ast.OutputType())
		}

		// Create program
		prg, err := env.Program(ast)
		if err != nil {
			return nil, fmt.Errorf("failed to create program for CEL expression '%s': %w", expr.Name, err)
		}

		programs[expr.Name] = prg
	}

	return &CELEvaluator{
		env:         env,
		expressions: programs,
	}, nil
}

// Evaluate evaluates all CEL expressions against the input data.
// Returns a map of expression names to their results (true/false).
// Returns error if evaluation fails.
func (e *CELEvaluator) Evaluate(ctx context.Context, input map[string]interface{}) (map[string]bool, error) {
	if e.expressions == nil {
		return nil, fmt.Errorf("CEL evaluator not initialized")
	}

	results := make(map[string]bool)

	for name, prg := range e.expressions {
		// Evaluate expression
		out, _, err := prg.Eval(map[string]interface{}{
			"input": input,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to evaluate CEL expression '%s': %w", name, err)
		}

		// Extract boolean result
		boolVal, err := extractBool(out)
		if err != nil {
			return nil, fmt.Errorf("CEL expression '%s' did not return boolean: %w", name, err)
		}

		results[name] = boolVal
	}

	return results, nil
}

// extractBool extracts a boolean value from a CEL ref.Val.
func extractBool(val ref.Val) (bool, error) {
	if types.IsBool(val) {
		return val.Value().(bool), nil
	}
	return false, fmt.Errorf("expected boolean, got %v", val.Type())
}

// EvidenceToMap converts Evidence to a map suitable for CEL input.
// This provides a simplified view of evidence for policy evaluation.
func EvidenceToMap(ev interface{}) map[string]interface{} {
	// For now, return a generic map representation
	// In practice, we'd want to convert the Evidence struct to a map
	// with proper field names that match the CEL expressions
	if m, ok := ev.(map[string]interface{}); ok {
		return m
	}
	
	// Fallback: wrap in evidence key
	return map[string]interface{}{
		"evidence": ev,
	}
}
