package policy

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// LoadCELPolicyFiles loads CEL expressions from external .cel files.
//
// File format:
//   # Comment lines start with #
//   expression_name = expression_body
//
// Multi-line expressions are supported by ending lines with backslash:
//   long_expression = first_part +
//                     second_part +
//                     third_part
//
// Example file (.provenix/policies/security.cel):
//   # Security policy
//   no_critical_vulns = vulnerabilities.critical == 0
//   max_high_vulns = vulnerabilities.high <= 5
//   allow = no_critical_vulns && max_high_vulns
//
// Returns a list of CELExpression structs ready for evaluation.
func LoadCELPolicyFiles(filePaths []string) ([]CELExpression, error) {
	var allExpressions []CELExpression

	for _, filePath := range filePaths {
		expressions, err := parseCELFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to parse %s: %w", filePath, err)
		}
		allExpressions = append(allExpressions, expressions...)
	}

	return allExpressions, nil
}

// parseCELFile parses a single .cel file and returns CEL expressions.
func parseCELFile(filePath string) ([]CELExpression, error) {
	// Resolve absolute path
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve path: %w", err)
	}

	// Open file
	file, err := os.Open(absPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	var expressions []CELExpression
	scanner := bufio.NewScanner(file)
	lineNum := 0

	var currentName string
	var currentExpr strings.Builder
	var inMultiLine bool

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// Skip empty lines and comments
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Check for line continuation (backslash at end)
		hasContinuation := strings.HasSuffix(trimmed, "\\")
		if hasContinuation {
			trimmed = strings.TrimSuffix(trimmed, "\\")
		}

		if !inMultiLine {
			// Start of new expression
			parts := strings.SplitN(trimmed, "=", 2)
			if len(parts) != 2 {
				return nil, fmt.Errorf("line %d: invalid syntax, expected 'name = expression'", lineNum)
			}

			currentName = strings.TrimSpace(parts[0])
			exprPart := strings.TrimSpace(parts[1])

			if currentName == "" {
				return nil, fmt.Errorf("line %d: expression name cannot be empty", lineNum)
			}

			// Validate that name doesn't contain spaces or special characters
			if strings.ContainsAny(currentName, " \t") {
				return nil, fmt.Errorf("line %d: expression name cannot contain spaces: %q", lineNum, currentName)
			}

			currentExpr.Reset()
			currentExpr.WriteString(exprPart)

			if hasContinuation {
				inMultiLine = true
			} else {
				// Complete single-line expression
				expressions = append(expressions, CELExpression{
					Name: currentName,
					Expr: currentExpr.String(),
					Message: fmt.Sprintf("Failed policy check: %s (from %s:%d)", 
						currentName, filepath.Base(filePath), lineNum),
				})
			}
		} else {
			// Continuation of multi-line expression
			currentExpr.WriteString(" ")
			currentExpr.WriteString(trimmed)

			if !hasContinuation {
				// End of multi-line expression
				expressions = append(expressions, CELExpression{
					Name: currentName,
					Expr: currentExpr.String(),
					Message: fmt.Sprintf("Failed policy check: %s (from %s)", 
						currentName, filepath.Base(filePath)),
				})
				inMultiLine = false
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	if inMultiLine {
		return nil, fmt.Errorf("unexpected end of file: unclosed multi-line expression '%s'", currentName)
	}

	return expressions, nil
}

// FilterExpressionsByName filters expressions to only include the specified entry point.
// If entryPoint is empty, returns all expressions.
func FilterExpressionsByName(expressions []CELExpression, entryPoint string) []CELExpression {
	if entryPoint == "" {
		return expressions
	}

	var filtered []CELExpression
	for _, expr := range expressions {
		if expr.Name == entryPoint {
			filtered = append(filtered, expr)
		}
	}
	return filtered
}
