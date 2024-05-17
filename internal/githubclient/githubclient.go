package githubclient

import (
	"context"
	"fmt"
	"net/http"

	"github.com/google/go-github/v62/github"

	"k8s.io/apimachinery/pkg/util/sets"
)

const emptyUserMeansTheAuthenticatedUser = ""

type UserInfo struct {
	ID    string
	Login string
}

type TeamInfo struct {
	Name string
	Slug string
	Org  string
}

type GitHubInterface interface {
	GetUserInfo() (*UserInfo, error)
	GetOrgMembership() ([]string, error)
	GetTeamMembership(allowedOrganizations sets.Set[string]) ([]TeamInfo, error)
}

type githubClient struct {
	client *github.Client
}

var _ GitHubInterface = (*githubClient)(nil)

func NewGitHubClient(httpClient *http.Client, apiBaseURL, token string) (GitHubInterface, error) {
	if httpClient == nil {
		return nil, fmt.Errorf("httpClient cannot be nil")
	}

	if token == "" {
		return nil, fmt.Errorf("token cannot be empty string")
	}

	if apiBaseURL == "https://github.com" {
		apiBaseURL = "https://api.github.com/"
	}

	client, err := github.NewClient(httpClient).WithEnterpriseURLs(apiBaseURL, "")
	if err != nil {
		return nil, fmt.Errorf("unable to create GitHub client using WithEnterpriseURLs: %w", err)
	}

	if client.BaseURL.Scheme != "https" {
		return nil, fmt.Errorf(`apiBaseURL must use "https" protocol, found "%s" instead`, client.BaseURL.Scheme)
	}

	return &githubClient{
		client: client.WithAuthToken(token),
	}, nil
}

// GetUserInfo returns the "Login" and "ID" attributes of the logged-in user.
// TODO: where should context come from?
func (g *githubClient) GetUserInfo() (*UserInfo, error) {
	user, response, err := g.client.Users.Get(context.Background(), emptyUserMeansTheAuthenticatedUser)
	if err != nil {
		return nil, fmt.Errorf("error fetching authenticated user: %w", err)
	}
	if user == nil { // untested
		return nil, fmt.Errorf("error fetching authenticated user: user is nil")
	}
	if response == nil { // untested
		return nil, fmt.Errorf("error fetching authenticated user: response is nil")
	}
	if user.ID == nil {
		return nil, fmt.Errorf(`the "ID" attribute is missing for authenticated user`)
	}
	if user.Login == nil {
		return nil, fmt.Errorf(`the "login" attribute is missing for authenticated user`)
	}

	return &UserInfo{
		Login: user.GetLogin(),
		ID:    fmt.Sprintf("%d", user.GetID()),
	}, nil
}

// GetOrgMembership returns an array of the "Login" attributes for all organizations to which the authenticated user belongs.
// TODO: where should context come from?
// TODO: what happens if login is nil?
// TODO: what is a good page size?
func (g *githubClient) GetOrgMembership() ([]string, error) {
	organizationLoginStrings := make([]string, 0)

	opt := &github.ListOptions{PerPage: 10}
	// get all pages of results
	for {
		organizationResults, response, err := g.client.Organizations.List(context.Background(), emptyUserMeansTheAuthenticatedUser, opt)
		if err != nil {
			return nil, fmt.Errorf("error fetching organizations for authenticated user: %w", err)
		}

		for _, organization := range organizationResults {
			organizationLoginStrings = append(organizationLoginStrings, organization.GetLogin())
		}
		if response.NextPage == 0 {
			break
		}
		opt.Page = response.NextPage
	}

	return organizationLoginStrings, nil
}

func isOrgAllowed(allowedOrganizations sets.Set[string], login string) bool {
	return len(allowedOrganizations) == 0 || allowedOrganizations.Has(login)
}

// GetTeamMembership returns a description of each team to which the authenticated user belongs.
// If allowedOrganizations is not empty, will filter the results to only those teams which belong to the allowed organizations.
// Parent teams will also be returned.
// TODO: where should context come from?
// TODO: what happens if org or login or id are nil?
// TODO: what is a good page size?
func (g *githubClient) GetTeamMembership(allowedOrganizations sets.Set[string]) ([]TeamInfo, error) {
	teamInfos := make([]TeamInfo, 0)

	opt := &github.ListOptions{PerPage: 10}
	// get all pages of results
	for {
		teamsResults, response, err := g.client.Teams.ListUserTeams(context.Background(), opt)
		if err != nil {
			return nil, fmt.Errorf("error fetching team membership for authenticated user: %w", err)
		}

		for _, team := range teamsResults {
			org := team.GetOrganization().GetLogin()

			if !isOrgAllowed(allowedOrganizations, org) {
				continue
			}

			teamInfos = append(teamInfos, TeamInfo{
				Name: team.GetName(),
				Slug: team.GetSlug(),
				Org:  org,
			})

			parent := team.GetParent()
			if parent != nil {
				parentOrg := parent.GetOrganization().GetLogin()
				if !isOrgAllowed(allowedOrganizations, parentOrg) {
					continue
				}

				teamInfos = append(teamInfos, TeamInfo{
					Name: parent.GetName(),
					Slug: parent.GetSlug(),
					Org:  parentOrg,
				})
			}
		}
		if response.NextPage == 0 {
			break
		}
		opt.Page = response.NextPage
	}

	return teamInfos, nil
}
