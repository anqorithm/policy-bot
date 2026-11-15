// Copyright 2021 Palantir Technologies, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package predicate

import (
	"context"
	"fmt"
	"testing"

	"github.com/palantir/policy-bot/policy/common"
	"github.com/palantir/policy-bot/pull"
	"github.com/palantir/policy-bot/pull/pulltest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

func TestHasValidSignatures(t *testing.T) {
	pTrue := HasValidSignatures(true)
	pFalse := HasValidSignatures(false)

	testCases := []SignatureTestCase{
		{
			"ValidGpgSignature",
			&pulltest.Context{
				AuthorValue: "mhaypenny",
				CommitsValue: []*pull.Commit{
					{
						SHA:       "abcdef123456789",
						Author:    "mhaypenny",
						Committer: "mhaypenny",
						Signature: &pull.Signature{
							Type:    pull.SignatureGpg,
							IsValid: true,
							Signer:  "ttest",
							State:   "VALID",
							KeyID:   "3AA5C34371567BD2",
						},
					},
				},
			},
			&common.PredicateResult{
				Satisfied:       true,
				Values:          []string{"abcdef123456789"},
				ConditionValues: []string{"valid signatures"},
			},
		},
		{
			"ValidSshSignature",
			&pulltest.Context{
				AuthorValue: "mhaypenny",
				CommitsValue: []*pull.Commit{
					{
						SHA:       "abcdef123456789",
						Author:    "mhaypenny",
						Committer: "mhaypenny",
						Signature: &pull.Signature{
							Type:           pull.SignatureSSH,
							IsValid:        true,
							Signer:         "ttest",
							State:          "VALID",
							KeyFingerprint: "Hello",
						},
					},
				},
			},
			&common.PredicateResult{
				Satisfied:       true,
				Values:          []string{"abcdef123456789"},
				ConditionValues: []string{"valid signatures"},
			},
		},
		{
			"InvalidSignature",
			&pulltest.Context{
				AuthorValue: "mhaypenny",
				CommitsValue: []*pull.Commit{
					{
						SHA:       "abcdef123456789",
						Author:    "mhaypenny",
						Committer: "mhaypenny",
						Signature: &pull.Signature{
							Type:    pull.SignatureGpg,
							IsValid: false,
							Signer:  "ttest",
							State:   "INVALID",
							KeyID:   "3AA5C34371567BD2",
						},
					},
				},
			},
			&common.PredicateResult{
				Satisfied:       false,
				Values:          []string{"abcdef123456789"},
				ConditionValues: []string{"valid signatures"},
			},
		},
		{
			"NoSignature",
			&pulltest.Context{
				AuthorValue: "mhaypenny",
				CommitsValue: []*pull.Commit{
					{
						SHA:       "abcdef123456789",
						Author:    "mhaypenny",
						Committer: "mhaypenny",
						Signature: nil,
					},
				},
			},
			&common.PredicateResult{
				Satisfied:       false,
				Values:          []string{"abcdef123456789"},
				ConditionValues: []string{"valid signatures"},
			},
		},
	}

	runSignatureTests(t, pTrue, testCases)

	// Invert the expected outcomes and test against the false predicate
	for idx := range testCases {
		testCases[idx].ExpectedPredicateResult.Satisfied = !testCases[idx].ExpectedPredicateResult.Satisfied
	}
	runSignatureTests(t, pFalse, testCases)
}

func TestHasValidSignaturesBy(t *testing.T) {
	p := &HasValidSignaturesBy{
		common.Actors{
			Teams:         []string{"testorg/team"},
			Users:         []string{"mhaypenny"},
			Organizations: []string{"testorg"},
		},
	}

	runSignatureTests(t, p, []SignatureTestCase{
		{
			"ValidSignatureByUser",
			&pulltest.Context{
				AuthorValue: "mhaypenny",
				CommitsValue: []*pull.Commit{
					{
						SHA:       "abcdef123456789",
						Author:    "mhaypenny",
						Committer: "mhaypenny",
						Signature: &pull.Signature{
							Type:    pull.SignatureGpg,
							IsValid: true,
							Signer:  "mhaypenny",
							State:   "VALID",
							KeyID:   "3AA5C34371567BD2",
						},
					},
				},
			},
			&common.PredicateResult{
				Satisfied: true,
				Values:    []string{"abcdef123456789"},
				ConditionsMap: map[string][]string{
					"Organizations": p.Organizations,
					"Teams":         p.Teams,
					"Users":         p.Users,
				},
			},
		},
		{
			"ValidSignatureButNotUser",
			&pulltest.Context{
				AuthorValue: "badcommitter",
				CommitsValue: []*pull.Commit{
					{
						SHA:       "abcdef123456789",
						Author:    "badcommitter",
						Committer: "badcommitter",
						Signature: &pull.Signature{
							Type:    pull.SignatureGpg,
							IsValid: true,
							Signer:  "badcommitter",
							State:   "VALID",
							KeyID:   "3AD5C34671567BC3",
						},
					},
				},
			},
			&common.PredicateResult{
				Satisfied: false,
				Values:    []string{"badcommitter"},
				ConditionsMap: map[string][]string{
					"Organizations": p.Organizations,
					"Teams":         p.Teams,
					"Users":         p.Users,
				},
			},
		},
		{
			"ValidSignatureByTeamMember",
			&pulltest.Context{
				AuthorValue: "ttest",
				TeamMemberships: map[string][]string{
					"ttest": {
						"testorg/team",
					},
				},
				CommitsValue: []*pull.Commit{
					{
						SHA:       "abcdef123456789",
						Author:    "ttest",
						Committer: "ttest",
						Signature: &pull.Signature{
							Type:    pull.SignatureGpg,
							IsValid: true,
							Signer:  "ttest",
							State:   "VALID",
							KeyID:   "3AA5C34371567BD2",
						},
					},
				},
			},
			&common.PredicateResult{
				Satisfied: true,
				Values:    []string{"abcdef123456789"},
				ConditionsMap: map[string][]string{
					"Organizations": p.Organizations,
					"Teams":         p.Teams,
					"Users":         p.Users,
				},
			},
		},
		{
			"NoSignature",
			&pulltest.Context{
				AuthorValue: "mhaypenny",
				CommitsValue: []*pull.Commit{
					{
						SHA:       "abcdef123456789",
						Author:    "mhaypenny",
						Committer: "mhaypenny",
						Signature: nil,
					},
				},
			},
			&common.PredicateResult{
				Satisfied: false,
				Values:    []string{"abcdef123456789"},
				ConditionsMap: map[string][]string{
					"Organizations": p.Organizations,
					"Teams":         p.Teams,
					"Users":         p.Users,
				},
			},
		},
	})
}

func TestHasValidSignaturesByKeys(t *testing.T) {
	p := &HasValidSignaturesByKeys{
		KeyIDs: []string{"3AA5C34371567BD2"},
	}

	runSignatureTests(t, p, []SignatureTestCase{
		{
			"ValidSignatureByValidKey",
			&pulltest.Context{
				AuthorValue: "mhaypenny",
				CommitsValue: []*pull.Commit{
					{
						SHA:       "abcdef123456789",
						Author:    "ttest",
						Committer: "ttest",
						Signature: &pull.Signature{
							Type:    pull.SignatureGpg,
							IsValid: true,
							Signer:  "mhaypenny",
							State:   "VALID",
							KeyID:   "3AA5C34371567BD2",
						},
					},
				},
			},
			&common.PredicateResult{
				Satisfied:       true,
				Values:          []string{"abcdef123456789"},
				ConditionValues: []string{"3AA5C34371567BD2"},
			},
		},
		{
			"ValidSignatureByInvalidKey",
			&pulltest.Context{
				AuthorValue: "mhaypenny",
				CommitsValue: []*pull.Commit{
					{
						SHA:       "abcdef123456789",
						Author:    "ttest",
						Committer: "ttest",
						Signature: &pull.Signature{
							Type:    pull.SignatureGpg,
							IsValid: true,
							Signer:  "mhaypenny",
							State:   "VALID",
							KeyID:   "3AB5C35371567CE7",
						},
					},
				},
			},
			&common.PredicateResult{
				Satisfied:       false,
				Values:          []string{"3AB5C35371567CE7"},
				ConditionValues: []string{"3AA5C34371567BD2"},
			},
		},
		{
			"InvalidSignatureByInvalidKey",
			&pulltest.Context{
				AuthorValue: "mhaypenny",
				CommitsValue: []*pull.Commit{
					{
						SHA:       "abcdef123456789",
						Author:    "ttest",
						Committer: "ttest",
						Signature: &pull.Signature{
							Type:    pull.SignatureGpg,
							IsValid: false,
							Signer:  "mhaypenny",
							State:   "BAD_EMAIL",
							KeyID:   "3AB5C35371567CE7",
						},
					},
				},
			},
			&common.PredicateResult{
				Satisfied:       false,
				Values:          []string{"abcdef123456789"},
				ConditionValues: []string{"3AA5C34371567BD2"},
			},
		},
	})
}

func TestHasValidSignaturesByKeysFingerprints(t *testing.T) {
	gpg := &pull.Signature{Type: pull.SignatureGpg, IsValid: true, KeyID: "gpg-key"}
	ssh := &pull.Signature{Type: pull.SignatureSSH, IsValid: true, KeyFingerprint: "ssh-key"}
	tests := map[string]struct {
		Signatures []*pull.Signature
		Satisfied  bool
	}{
		"allowed SSH":                         {[]*pull.Signature{ssh}, true},
		"allowed GPG":                         {[]*pull.Signature{gpg}, true},
		"mixed allowed signatures":            {[]*pull.Signature{gpg, ssh}, true},
		"unlisted SSH":                        {[]*pull.Signature{{Type: pull.SignatureSSH, IsValid: true, KeyFingerprint: "other"}}, false},
		"GPG ID cannot match SSH fingerprint": {[]*pull.Signature{{Type: pull.SignatureGpg, IsValid: true, KeyID: "ssh-key"}}, false},
		"SSH fingerprint cannot match GPG ID": {[]*pull.Signature{{Type: pull.SignatureSSH, IsValid: true, KeyFingerprint: "gpg-key"}}, false},
		"invalid SSH":                         {[]*pull.Signature{{Type: pull.SignatureSSH, KeyFingerprint: "ssh-key", State: "INVALID"}}, false},
		"mixed with invalid signature":        {[]*pull.Signature{gpg, {Type: pull.SignatureSSH, KeyFingerprint: "ssh-key", State: "INVALID"}}, false},
		"unsupported signature":               {[]*pull.Signature{{Type: pull.SignatureSmime, IsValid: true}}, false},
		"unsigned commit":                     {[]*pull.Signature{nil}, false},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var pred HasValidSignaturesByKeys
			require.NoError(t, yaml.Unmarshal([]byte("key_ids: [gpg-key]\nkey_fingerprints: [ssh-key]"), &pred))
			prctx := &pulltest.Context{}
			for i, signature := range tt.Signatures {
				prctx.CommitsValue = append(prctx.CommitsValue, &pull.Commit{SHA: fmt.Sprintf("commit%d", i), Signature: signature})
			}
			result, err := pred.Evaluate(context.Background(), prctx)
			require.NoError(t, err)
			assert.Equal(t, tt.Satisfied, result.Satisfied)
			assert.Equal(t, []string{"gpg-key", "ssh-key"}, result.ConditionValues)
			assert.Equal(t, []string{"gpg-key"}, pred.KeyIDs)
		})
	}
}

type SignatureTestCase struct {
	Name                    string
	Context                 pull.Context
	ExpectedPredicateResult *common.PredicateResult
}

func runSignatureTests(t *testing.T, p Predicate, cases []SignatureTestCase) {
	ctx := context.Background()

	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			predicateResult, err := p.Evaluate(ctx, tc.Context)
			if assert.NoError(t, err, "evaluation failed") {
				assertPredicateResult(t, tc.ExpectedPredicateResult, predicateResult)
			}
		})
	}
}
