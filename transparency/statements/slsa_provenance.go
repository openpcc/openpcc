// Copyright 2025 Nonvolatile Inc. d/b/a Confident Security

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     https://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package statements

import (
	"encoding/json"
	"fmt"
	"maps"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
	slsa02 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	"github.com/openpcc/openpcc/transparency"
)

// FromSLSA02ProvenanceStatement converts the intoto provenance statement into a [transparency.Statement]
// that the rest of our transparency package can work with.
//
// Caution: This is a lossy process, this method strips sensitive information.
//
// Intoto statements can contain a lot of sensitive information we might not want to share with our users.
// For example, pull request based statements include the PR description and branch names.
func FromSLSA02ProvenanceStatement(p *intoto.ProvenanceStatementSLSA02) (*transparency.Statement, error) {
	if p.PredicateType != slsa02.PredicateSLSAProvenance {
		return nil, fmt.Errorf("unexpected predicate type %s, wanted %s", p.PredicateType, slsa02.PredicateSLSAProvenance)
	}

	s := &transparency.Statement{
		PredicateType: p.PredicateType,
		Subject:       make([]transparency.StatementSubject, len(p.Subject)),
		Predicate:     make(map[string]any),
	}

	// copy the subject
	for i, subject := range p.Subject {
		s.Subject[i] = transparency.StatementSubject{
			Name:   subject.Name,
			Digest: maps.Clone(subject.Digest),
		}
	}

	err := copyPredicateViaJSON(p.Predicate, &s.Predicate)
	if err != nil {
		return nil, fmt.Errorf("failed to copy predicate: %w", err)
	}

	sanitizeSLSA02Predicate(s.Predicate)

	err = s.Validate()
	if err != nil {
		return nil, fmt.Errorf("unexpected invalid statement: %w", err)
	}

	return s, nil
}

func sanitizeSLSA02Predicate(predicate map[string]any) {
	invocationVal, ok := predicate["invocation"]
	if !ok {
		return
	}

	invocation, ok := invocationVal.(map[string]any)
	if !ok {
		return
	}

	environmentVal, ok := invocation["environment"]
	if !ok {
		return
	}

	environment, ok := environmentVal.(map[string]any)
	if !ok {
		return
	}

	// 
	// can contain detailed PR information, title, description, comments etc.
	environment["github_event_payload"] = map[string]any{}

	// can contain branch names
	environment["github_base_ref"] = ""

	// can contain branch names
	environment["github_head_ref"] = ""
}

func ToSLSA02ProvenanceStatement(s *transparency.Statement) (*intoto.ProvenanceStatementSLSA02, error) {
	err := s.Validate()
	if err != nil {
		return nil, fmt.Errorf("invalid statement: %w", err)
	}

	if s.PredicateType != slsa02.PredicateSLSAProvenance {
		return nil, fmt.Errorf("unexpected predicate type %s, wanted %s", s.PredicateType, slsa02.PredicateSLSAProvenance)
	}

	p := &intoto.ProvenanceStatementSLSA02{
		//nolint:staticcheck
		StatementHeader: intoto.StatementHeader{
			PredicateType: s.PredicateType,
			//nolint:staticcheck
			Subject: make([]intoto.Subject, len(s.Subject)),
		},
	}

	// copy the subject
	for i, subject := range s.Subject {
		//nolint:staticcheck
		p.Subject[i] = intoto.Subject{
			Name:   subject.Name,
			Digest: maps.Clone(subject.Digest),
		}
	}

	err = copyPredicateViaJSON(s.Predicate, &p.Predicate)
	if err != nil {
		return nil, fmt.Errorf("failed to copy predicate: %w", err)
	}

	return p, nil
}

// copyPredicateViaJSON in some cases we wish to copy a strongly typed predicate to a map[string]any for
// use with transparency.Statement.Predicate which indexes keys using their JSON keys. Not ideal, but the
// alternative is to specify keys by hand.
func copyPredicateViaJSON(from, to any) error {
	b, err := json.Marshal(from)
	if err != nil {
		return fmt.Errorf("failed to marshal from: %w", err)
	}
	err = json.Unmarshal(b, to)
	if err != nil {
		return fmt.Errorf("failed to unmarshal intermediate json: %w", err)
	}
	return nil
}
