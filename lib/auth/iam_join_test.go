package auth

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gravitational/teleport/api/types"
	"github.com/stretchr/testify/require"
)

type mockHTTPClient struct {
	nodeIdentity awsIdentity
}

func (m mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	responseBody := fmt.Sprintf(`{
		"GetCallerIdentityResponse": {
			"GetCallerIdentityResult": {
				"Account": "%s",
				"Arn": "%s"
			}}}`, m.nodeIdentity.Account, m.nodeIdentity.Arn)

	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(responseBody)),
	}, nil
}

func TestIAMJoin(t *testing.T) {
	a := newAuthServer(t)

	isNil := func(err error) bool {
		if err != nil {
			log.WithError(err).Error("unexpected error")
		}
		return err == nil
	}

	testCases := []struct {
		desc         string
		tokenSpec    types.ProvisionTokenSpecV2
		expectError  func(error) bool
		nodeIdentity awsIdentity
	}{
		{
			desc: "basic passing case",
			tokenSpec: types.ProvisionTokenSpecV2{
				Roles: []types.SystemRole{types.RoleNode},
				Allow: []*types.TokenRule{
					&types.TokenRule{
						AWSAccount: "",
					},
				},
				JoinMethod: types.JoinMethodIAM,
			},
			nodeIdentity: awsIdentity{
				Account: "1234",
				Arn:     "arn:aws::1111",
			},
			expectError: isNil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			ctx := context.Background()

			// add token to auth server
			token, err := types.NewProvisionTokenFromSpec("test-token",
				time.Now().Add(time.Minute),
				tc.tokenSpec)
			require.NoError(t, err)
			require.NoError(t, a.UpsertToken(ctx, token))
			t.Cleanup(func() { require.NoError(t, a.DeleteToken(ctx, token.GetName())) })

			challenge := "dummy-challenge"
			signedRequest, err := createSignedSTSIdentityRequest(challenge)
			require.NoError(t, err)
			req := &types.RegisterUsingTokenRequest{
				Token:              "test-token",
				HostID:             "test-node",
				Role:               types.RoleNode,
				STSIdentityRequest: signedRequest,
			}

			httpClient := mockHTTPClient{
				nodeIdentity: tc.nodeIdentity,
			}

			err = a.checkIAMRequest(ctx, httpClient, challenge, req)
			require.True(t, tc.expectError(err))
		})
	}
}
