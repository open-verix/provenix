package cli

import "time"

// VEXStatus represents the exploitability status of a vulnerability
type VEXStatus string

const (
	VEXStatusNotAffected        VEXStatus = "not_affected"
	VEXStatusAffected           VEXStatus = "affected"
	VEXStatusFixed              VEXStatus = "fixed"
	VEXStatusUnderInvestigation VEXStatus = "under_investigation"
)

// VEXJustification explains why a vulnerability is marked as not_affected
type VEXJustification string

const (
	JustificationComponentNotPresent              VEXJustification = "component_not_present"
	JustificationVulnerableCodeNotPresent         VEXJustification = "vulnerable_code_not_present"
	JustificationVulnerableCodeNotInExecutePath   VEXJustification = "vulnerable_code_not_in_execute_path"
	JustificationVulnerableCodeCannotBeControlled VEXJustification = "vulnerable_code_cannot_be_controlled_by_adversary"
	JustificationInlineMitigationsExist           VEXJustification = "inline_mitigations_already_exist"
)

// VEXMergeStrategy defines how to merge multiple VEX documents
type VEXMergeStrategy string

const (
	MergeStrategyLatest   VEXMergeStrategy = "latest"   // Keep most recent statement per vuln
	MergeStrategyUnion    VEXMergeStrategy = "union"    // Include all unique statements
	MergeStrategyOverride VEXMergeStrategy = "override" // Later files override earlier
)

// MergedVEXDocument represents the result of merging multiple VEX docs
type MergedVEXDocument struct {
	Context    string                `json:"@context"`
	ID         string                `json:"@id"`
	Author     string                `json:"author"`
	Timestamp  time.Time             `json:"timestamp"`
	Version    string                `json:"version"`
	Tooling    string                `json:"tooling,omitempty"`
	Statements []VEXStatement        `json:"statements"`
	Metadata   *VEXMergeMetadata     `json:"metadata,omitempty"`
}

// VEXMergeMetadata tracks merge operation details
type VEXMergeMetadata struct {
	SourceDocuments []string         `json:"source_documents"`
	MergeStrategy   VEXMergeStrategy `json:"merge_strategy"`
	MergedAt        time.Time        `json:"merged_at"`
	Conflicts       []VEXConflict    `json:"conflicts,omitempty"`
}

// VEXConflict represents a conflict during merge
type VEXConflict struct {
	VulnerabilityID string    `json:"vulnerability_id"`
	ConflictingDocs []string  `json:"conflicting_docs"`
	Resolution      string    `json:"resolution"`
}

// VEXFilterCriteria defines filtering options
type VEXFilterCriteria struct {
	Status        []VEXStatus
	Severity      []string // critical, high, medium, low
	Product       string
	Justification []VEXJustification
	StartDate     *time.Time
	EndDate       *time.Time
}

// VEXValidationResult contains validation results
type VEXValidationResult struct {
	Valid    bool                  `json:"valid"`
	Errors   []VEXValidationError  `json:"errors,omitempty"`
	Warnings []VEXValidationError  `json:"warnings,omitempty"`
	Format   string                `json:"format"`
	Version  string                `json:"version,omitempty"`
}

// VEXValidationError represents a validation error or warning
type VEXValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
	Code    string `json:"code"`
}

// VEXUpdateRequest represents a request to update a VEX statement
type VEXUpdateRequest struct {
	VulnerabilityID   string           `json:"vulnerability_id"`
	Status            VEXStatus        `json:"status"`
	Justification     VEXJustification `json:"justification,omitempty"`
	Statement         string           `json:"statement,omitempty"`
	ActionStatement   string           `json:"action_statement,omitempty"`
	ImpactStatement   string           `json:"impact_statement,omitempty"`
	UpdatedBy         string           `json:"updated_by,omitempty"`
	Timestamp         time.Time        `json:"timestamp"`
}

// VEXStatementHistory tracks changes to a VEX statement over time
type VEXStatementHistory struct {
	VulnerabilityID string             `json:"vulnerability_id"`
	Updates         []VEXUpdateRequest `json:"updates"`
}

// CycloneDXVEX represents a CycloneDX VEX document structure
type CycloneDXVEX struct {
	BOMFormat   string                     `json:"bomFormat"`
	SpecVersion string                     `json:"specVersion"`
	Version     int                        `json:"version"`
	Metadata    *CycloneDXMetadata         `json:"metadata,omitempty"`
	Vulnerabilities []CycloneDXVulnerability `json:"vulnerabilities"`
}

// CycloneDXMetadata represents metadata in CycloneDX format
type CycloneDXMetadata struct {
	Timestamp  time.Time                `json:"timestamp,omitempty"`
	Tools      []CycloneDXTool          `json:"tools,omitempty"`
	Authors    []CycloneDXContact       `json:"authors,omitempty"`
}

// CycloneDXTool represents a tool in CycloneDX format
type CycloneDXTool struct {
	Vendor  string `json:"vendor,omitempty"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// CycloneDXContact represents contact information
type CycloneDXContact struct {
	Name  string `json:"name,omitempty"`
	Email string `json:"email,omitempty"`
}

// CycloneDXVulnerability represents a vulnerability in CycloneDX VEX
type CycloneDXVulnerability struct {
	ID          string                    `json:"id"`
	Source      *CycloneDXSource          `json:"source,omitempty"`
	Analysis    *CycloneDXAnalysis        `json:"analysis,omitempty"`
	Affects     []CycloneDXAffect         `json:"affects,omitempty"`
}

// CycloneDXSource represents vulnerability source
type CycloneDXSource struct {
	Name string `json:"name"`
	URL  string `json:"url,omitempty"`
}

// CycloneDXAnalysis represents vulnerability analysis
type CycloneDXAnalysis struct {
	State         string   `json:"state"`
	Justification string   `json:"justification,omitempty"`
	Response      []string `json:"response,omitempty"`
	Detail        string   `json:"detail,omitempty"`
}

// CycloneDXAffect represents affected components
type CycloneDXAffect struct {
	Ref      string                `json:"ref"`
	Versions []CycloneDXVersion    `json:"versions,omitempty"`
}

// CycloneDXVersion represents version information
type CycloneDXVersion struct {
	Version string `json:"version,omitempty"`
	Status  string `json:"status,omitempty"`
}
