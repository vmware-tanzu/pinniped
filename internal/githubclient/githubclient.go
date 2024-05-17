package githubclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/google/go-github/v62/github"

	"k8s.io/apimachinery/pkg/util/sets"
)

const (
	emptyUserMeansTheAuthenticatedUser = ""
	pageSize                           = 100
)

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
	GetUserInfo(ctx context.Context) (*UserInfo, error)
	GetOrgMembership(ctx context.Context) (sets.Set[string], error)
	GetTeamMembership(ctx context.Context, allowedOrganizations sets.Set[string]) ([]*TeamInfo, error)
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
func (g *githubClient) GetUserInfo(ctx context.Context) (*UserInfo, error) {
	const errorPrefix = "error fetching authenticated user"

	user, _, err := g.client.Users.Get(ctx, emptyUserMeansTheAuthenticatedUser)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", errorPrefix, err)
	}
	if user == nil { // untested
		return nil, fmt.Errorf("%s: user is nil", errorPrefix)
	}

	userInfo := &UserInfo{
		Login: user.GetLogin(),
		ID:    fmt.Sprintf("%d", user.GetID()),
	}
	if userInfo.ID == "0" {
		return nil, fmt.Errorf(`%s: the "id" attribute is missing`, errorPrefix)
	}
	if userInfo.Login == "" {
		return nil, fmt.Errorf(`%s: the "login" attribute is missing`, errorPrefix)
	}
	return userInfo, nil
}

// GetOrgMembership returns an array of the "Login" attributes for all organizations to which the authenticated user belongs.
func (g *githubClient) GetOrgMembership(ctx context.Context) (sets.Set[string], error) {
	const errorPrefix = "error fetching organizations for authenticated user"

	organizationLogins := sets.New[string]()

	opt := &github.ListOptions{PerPage: pageSize}
	// get all pages of results
	for {
		organizationResults, response, err := g.client.Organizations.List(ctx, emptyUserMeansTheAuthenticatedUser, opt)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", errorPrefix, err)
		}

		for _, organization := range organizationResults {
			organizationLogins.Insert(organization.GetLogin())
		}
		if response.NextPage == 0 {
			break
		}
		opt.Page = response.NextPage
	}

	if organizationLogins.Has("") {
		return nil, fmt.Errorf(`%s: one or more organizations is missing the "login" attribute`, errorPrefix)
	}

	return organizationLogins, nil
}

func isOrgAllowed(allowedOrganizations sets.Set[string], login string) bool {
	return len(allowedOrganizations) == 0 || allowedOrganizations.Has(login)
}

func buildAndValidateTeam(githubTeam *github.Team) (*TeamInfo, error) {
	if githubTeam.GetOrganization() == nil {
		return nil, errors.New(`missing the "organization" attribute for a team`)
	}
	organizationLogin := githubTeam.GetOrganization().GetLogin()
	if organizationLogin == "" {
		return nil, errors.New(`missing the organization's "login" attribute for a team`)
	}

	teamInfo := &TeamInfo{
		Name: githubTeam.GetName(),
		Slug: githubTeam.GetSlug(),
		Org:  organizationLogin,
	}
	if teamInfo.Name == "" {
		return nil, errors.New(`the "name" attribute is missing for a team`)
	}
	if teamInfo.Slug == "" {
		return nil, errors.New(`the "slug" attribute is missing for a team`)
	}
	return teamInfo, nil
}

// GetTeamMembership returns a description of each team to which the authenticated user belongs.
// If allowedOrganizations is not empty, will filter the results to only those teams which belong to the allowed organizations.
// Parent teams will also be returned.
func (g *githubClient) GetTeamMembership(ctx context.Context, allowedOrganizations sets.Set[string]) ([]*TeamInfo, error) {
	const errorPrefix = "error fetching team membership for authenticated user"
	teamInfos := make([]*TeamInfo, 0)

	opt := &github.ListOptions{PerPage: pageSize}
	// get all pages of results
	for {
		teamsResults, response, err := g.client.Teams.ListUserTeams(ctx, opt)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", errorPrefix, err)
		}

		for _, team := range teamsResults {
			teamInfo, err := buildAndValidateTeam(team)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", errorPrefix, err)
			}

			if !isOrgAllowed(allowedOrganizations, teamInfo.Org) {
				continue
			}

			teamInfos = append(teamInfos, teamInfo)

			parent := team.GetParent()
			if parent != nil {
				teamInfo, err := buildAndValidateTeam(parent)
				if err != nil {
					return nil, fmt.Errorf("%s: %w", errorPrefix, err)
				}

				if !isOrgAllowed(allowedOrganizations, teamInfo.Org) {
					continue
				}

				teamInfos = append(teamInfos, teamInfo)
			}
		}
		if response.NextPage == 0 {
			break
		}
		opt.Page = response.NextPage
	}

	return teamInfos, nil
}
