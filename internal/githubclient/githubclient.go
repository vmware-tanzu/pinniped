// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package githubclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/google/go-github/v66/github"
	"k8s.io/apimachinery/pkg/util/sets"

	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/internal/setutil"
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
	GetOrgMembership(ctx context.Context) ([]string, error)
	GetTeamMembership(ctx context.Context, allowedOrganizations *setutil.CaseInsensitiveSet) ([]TeamInfo, error)
}

type githubClient struct {
	client *github.Client
}

var _ GitHubInterface = (*githubClient)(nil)

func NewGitHubClient(httpClient *http.Client, apiBaseURL, token string) (GitHubInterface, error) {
	const errorPrefix = "unable to build new github client"

	if httpClient == nil {
		return nil, fmt.Errorf("%s: httpClient cannot be nil", errorPrefix)
	}

	parsedURL, err := url.Parse(apiBaseURL)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", errorPrefix, err)
	}

	if !strings.HasSuffix(parsedURL.Path, "/") {
		parsedURL.Path += "/"
	}

	if parsedURL.Scheme != "https" {
		return nil, fmt.Errorf(`%s: apiBaseURL must use "https" protocol, found %q instead`, errorPrefix, parsedURL.Scheme)
	}

	if token == "" {
		return nil, fmt.Errorf("%s: token cannot be empty string", errorPrefix)
	}

	client := github.NewClient(httpClient).WithAuthToken(token)
	client.BaseURL = parsedURL

	return &githubClient{
		client: client,
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
	plog.Trace("got raw GitHub API user results", "user", user)

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

	plog.Trace("calculated response from GitHub user endpoint", "user", userInfo)
	return userInfo, nil
}

// GetOrgMembership returns an array of the "Login" attributes for all organizations to which the authenticated user belongs.
func (g *githubClient) GetOrgMembership(ctx context.Context) ([]string, error) {
	const errorPrefix = "error fetching organizations for authenticated user"

	organizationLogins := sets.New[string]()

	opt := &github.ListOptions{PerPage: pageSize}
	// get all pages of results
	for {
		organizationResults, response, err := g.client.Organizations.List(ctx, emptyUserMeansTheAuthenticatedUser, opt)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", errorPrefix, err)
		}
		plog.Trace("got raw GitHub API org results", "orgs", organizationResults, "hasNextPage", response.NextPage)

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

	plog.Trace("calculated response from GitHub org membership endpoint", "orgs", organizationLogins.UnsortedList())
	return organizationLogins.UnsortedList(), nil
}

func isOrgAllowed(allowedOrganizations *setutil.CaseInsensitiveSet, login string) bool {
	return allowedOrganizations.Empty() || allowedOrganizations.ContainsIgnoringCase(login)
}

func buildAndValidateParentTeam(githubTeam *github.Team, organizationLogin string) (*TeamInfo, error) {
	return buildTeam(githubTeam, organizationLogin)
}

func buildAndValidateTeam(githubTeam *github.Team) (*TeamInfo, error) {
	if githubTeam.GetOrganization() == nil {
		return nil, errors.New(`missing the "organization" attribute for a team`)
	}
	organizationLogin := githubTeam.GetOrganization().GetLogin()
	if organizationLogin == "" {
		return nil, errors.New(`missing the organization's "login" attribute for a team`)
	}

	return buildTeam(githubTeam, organizationLogin)
}

func buildTeam(githubTeam *github.Team, organizationLogin string) (*TeamInfo, error) {
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
func (g *githubClient) GetTeamMembership(ctx context.Context, allowedOrganizations *setutil.CaseInsensitiveSet) ([]TeamInfo, error) {
	const errorPrefix = "error fetching team membership for authenticated user"
	teamInfos := sets.New[TeamInfo]()

	opt := &github.ListOptions{PerPage: pageSize}
	// get all pages of results
	for {
		teamsResults, response, err := g.client.Teams.ListUserTeams(ctx, opt)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", errorPrefix, err)
		}
		plog.Trace("got raw GitHub API team results", "teams", teamsResults, "hasNextPage", response.NextPage)

		for _, team := range teamsResults {
			teamInfo, err := buildAndValidateTeam(team)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", errorPrefix, err)
			}

			if !isOrgAllowed(allowedOrganizations, teamInfo.Org) {
				continue
			}

			teamInfos.Insert(*teamInfo)

			parent := team.GetParent()
			if parent != nil {
				// The GitHub API does not return the Organization for the Parent of the team.
				// Use the org of the child as the org of the parent, since they must come from the same org.
				parentTeamInfo, err := buildAndValidateParentTeam(parent, teamInfo.Org)
				if err != nil {
					return nil, fmt.Errorf("%s: %w", errorPrefix, err)
				}

				teamInfos.Insert(*parentTeamInfo)
			}
		}
		if response.NextPage == 0 {
			break
		}
		opt.Page = response.NextPage
	}

	// Sort by org and then by name, just so we always return teams in the same order.
	sortedTeams := teamInfos.UnsortedList()
	slices.SortStableFunc(sortedTeams, func(a, b TeamInfo) int {
		orgsCompared := strings.Compare(a.Org, b.Org)
		if orgsCompared == 0 {
			return strings.Compare(a.Slug, b.Slug)
		}
		return orgsCompared
	})

	plog.Trace("calculated response from GitHub teams endpoint", "teams", sortedTeams)
	return sortedTeams, nil
}
