// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package issuers

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// GitHubIssuer is the only GitHub Actions issuer accepted (github.com).
const GitHubIssuer = "https://token.actions.githubusercontent.com"

// GitHubAlgorithms are the only signature algorithms GitHub tokens may use.
var GitHubAlgorithms = []string{"RS256"}

// JobType says which workflow claim an entry binds on (PAP-1 §3.3).
type JobType string

// Job types.
const (
	// JobWorkflow is an ordinary job: it binds on workflow_ref.
	JobWorkflow JobType = "workflow"
	// JobReusable is a job that calls a reusable workflow: it binds on
	// job_workflow_ref, the called workflow's path and ref.
	JobReusable JobType = "reusable_workflow"
)

var (
	numericID   = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)
	workflowRef = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/[^@\s]+@refs/(heads|tags)/[^\s]+$`)
	gitSHA      = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

// GitHubBinding pins GitHub Actions tokens to one agent (HR-093, HR-140).
type GitHubBinding struct {
	RepositoryID      string
	RepositoryOwnerID string
	JobType           JobType
	// WorkflowRefs are accepted values of workflow_ref (ordinary jobs) or
	// job_workflow_ref (reusable workflows), each on a branch or tag.
	WorkflowRefs []string
	// WorkflowSHAs optionally pin exact revisions (workflow_sha or
	// job_workflow_sha); empty accepts any revision of the refs.
	WorkflowSHAs      []string
	Environment       string
	RunnerEnvironment string
}

// Validate checks that the binding pins immutable ids and protected-looking
// refs only (HR-140). Repository names are never enough: they can be
// renamed and reused (T-035).
func (b GitHubBinding) Validate() error {
	var errs []string
	if !numericID.MatchString(b.RepositoryID) || !numericID.MatchString(b.RepositoryOwnerID) {
		errs = append(errs, "repository_id and repository_owner_id must be numeric ids")
	}
	if b.JobType != JobWorkflow && b.JobType != JobReusable {
		errs = append(errs, "job type must be workflow or reusable_workflow")
	}
	if len(b.WorkflowRefs) == 0 || len(b.WorkflowRefs) > 20 {
		errs = append(errs, "1 to 20 workflow refs are required")
	}
	for _, r := range b.WorkflowRefs {
		if !workflowRef.MatchString(r) || strings.Contains(r, "*") || strings.Contains(r, "refs/pull/") {
			errs = append(errs, fmt.Sprintf("workflow ref %q must be owner/repo/path@refs/heads/… or @refs/tags/… with no wildcard", r))
		}
	}
	for _, s := range b.WorkflowSHAs {
		if !gitSHA.MatchString(s) {
			errs = append(errs, fmt.Sprintf("workflow sha %q must be 40 hex digits", s))
		}
	}
	if len(b.WorkflowSHAs) > 20 || len(b.Environment) > 255 ||
		(b.RunnerEnvironment != "" && b.RunnerEnvironment != "github-hosted" && b.RunnerEnvironment != "self-hosted") {
		errs = append(errs, "sha, environment or runner environment pin")
	}
	if len(errs) > 0 {
		return fmt.Errorf("%w: %s", ErrInvalidEntry, strings.Join(errs, "; "))
	}
	return nil
}

// Widening lists what next accepts that prev did not (HR-141). A nil prev
// means a new entry, which widens by definition.
func (b GitHubBinding) Widening(prev *GitHubBinding) []string {
	if prev == nil {
		return []string{"new trusted issuer entry"}
	}
	var out []string
	if prev.RepositoryID != b.RepositoryID || prev.RepositoryOwnerID != b.RepositoryOwnerID || prev.JobType != b.JobType {
		out = append(out, "repository or job type changed")
	}
	out = append(out, widenedList("workflow_refs", prev.WorkflowRefs, b.WorkflowRefs)...)
	out = append(out, widenedList("workflow_shas", prev.WorkflowSHAs, b.WorkflowSHAs)...)
	out = append(out, widenedPin("environment", prev.Environment, b.Environment)...)
	out = append(out, widenedPin("runner_environment", prev.RunnerEnvironment, b.RunnerEnvironment)...)
	return out
}

// GitHubClaims are the claims of a GitHub Actions OIDC token whose
// signature, issuer and algorithm were already verified.
type GitHubClaims struct {
	Issuer            string         `json:"iss"`
	Audience          jsontext.Value `json:"aud"`
	JTI               string         `json:"jti"`
	RepositoryID      string         `json:"repository_id"`
	RepositoryOwnerID string         `json:"repository_owner_id"`
	Ref               string         `json:"ref"`
	RefProtected      jsontext.Value `json:"ref_protected"`
	EventName         string         `json:"event_name"`
	WorkflowRef       string         `json:"workflow_ref"`
	WorkflowSHA       string         `json:"workflow_sha"`
	JobWorkflowRef    string         `json:"job_workflow_ref"`
	JobWorkflowSHA    string         `json:"job_workflow_sha"`
	Environment       string         `json:"environment"`
	RunnerEnvironment string         `json:"runner_environment"`
	SHA               string         `json:"sha"`
}

// ParseGitHubClaims decodes a verified payload; unknown claims are ignored,
// duplicate members are rejected.
func ParseGitHubClaims(payload []byte) (GitHubClaims, error) {
	var c GitHubClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return c, rejected("github claims: %v", err)
	}
	return c, nil
}

// refProtected accepts GitHub's "true" string or a JSON true.
func refProtected(v jsontext.Value) bool {
	s := strings.TrimSpace(string(v))
	return s == "true" || s == `"true"`
}

// audienceIs requires aud to be exactly want: a single string, or an array
// holding only want.
func audienceIs(v jsontext.Value, want string) bool {
	var one string
	if err := json.Unmarshal(v, &one); err == nil {
		return one == want
	}
	var many []string
	if err := json.Unmarshal(v, &many); err == nil {
		return len(many) == 1 && many[0] == want
	}
	return false
}

// MatchGitHub applies the GitHub preset to verified claims. The rules that
// no configuration can disable (HR-093):
//   - issuer is GitHubIssuer and aud is exactly pantherclaw:<org>;
//   - repository_id and repository_owner_id equal the pinned ids;
//   - ref_protected is true;
//   - event_name is not pull_request or pull_request_target, and the ref is
//     not under refs/pull/ (pull_request_review and similar events run the
//     pull request's code);
//   - the workflow claim of the entry's job type is one of the pinned refs
//     (and its sha one of the pinned shas, when pinned); an ordinary-job
//     entry also refuses a token from a job that ran a reusable workflow.
func MatchGitHub(b GitHubBinding, org ids.OrgID, c GitHubClaims) (Match, error) {
	if err := b.Validate(); err != nil {
		return Match{}, err
	}
	switch {
	case c.Issuer != GitHubIssuer:
		return Match{}, rejected("issuer %q", c.Issuer)
	case !audienceIs(c.Audience, Audience(org)):
		return Match{}, rejected("audience")
	case c.RepositoryID != b.RepositoryID || c.RepositoryOwnerID != b.RepositoryOwnerID:
		return Match{}, rejected("repository or owner id")
	case c.EventName == "pull_request" || c.EventName == "pull_request_target":
		return Match{}, rejected("event %s runs code not reviewed into a protected ref", c.EventName)
	case strings.HasPrefix(c.Ref, "refs/pull/"):
		return Match{}, rejected("ref %s is a pull request", c.Ref)
	case !refProtected(c.RefProtected):
		return Match{}, rejected("ref %s is not protected", c.Ref)
	case b.Environment != "" && c.Environment != b.Environment:
		return Match{}, rejected("environment")
	case b.RunnerEnvironment != "" && c.RunnerEnvironment != b.RunnerEnvironment:
		return Match{}, rejected("runner environment")
	}
	ref, sha := c.WorkflowRef, c.WorkflowSHA
	if b.JobType == JobReusable {
		ref, sha = c.JobWorkflowRef, c.JobWorkflowSHA
	} else if c.JobWorkflowRef != "" && c.JobWorkflowRef != c.WorkflowRef {
		return Match{}, rejected("an ordinary-job entry does not accept a reusable workflow")
	}
	if !slices.Contains(b.WorkflowRefs, ref) {
		return Match{}, rejected("workflow ref %q not pinned", ref)
	}
	if len(b.WorkflowSHAs) > 0 && !slices.Contains(b.WorkflowSHAs, sha) {
		return Match{}, rejected("workflow sha not pinned")
	}
	return Match{Binding: Binding{
		"repository_id":       c.RepositoryID,
		"repository_owner_id": c.RepositoryOwnerID,
		"workflow":            ref,
	}}, nil
}
