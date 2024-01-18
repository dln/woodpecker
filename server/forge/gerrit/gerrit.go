package gerrit

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/andygrunwald/go-gerrit"
	"github.com/rs/zerolog/log"

	"go.woodpecker-ci.org/woodpecker/v2/server/forge"
	"go.woodpecker-ci.org/woodpecker/v2/server/forge/common"
	forge_types "go.woodpecker-ci.org/woodpecker/v2/server/forge/types"
	"go.woodpecker-ci.org/woodpecker/v2/server/model"
)

type Gerrit struct {
	url            string
	client         *gerrit.Client
	clonePrefix    string
	clonePrefixSSH string
}

type Opts struct {
	GerritURL      string
	GerritUsername string
	GerritPassword string
	URL            string // Gerrit server url.
	SkipVerify     bool   // Skip ssl verification.
}

// New returns a Forge implementation that integrates with Gerrit
func New(opts Opts) (forge.Forge, error) {
	u, err := url.Parse(opts.URL)
	if err != nil {
		return nil, err
	}
	host, _, err := net.SplitHostPort(u.Host)
	if err == nil {
		u.Host = host
	}

	ctx := context.Background()
	c, err := gerrit.NewClient(ctx, opts.GerritURL, nil)
	if err != nil {
		return nil, err
	}
	c.Authentication.SetBasicAuth(opts.GerritUsername, opts.GerritPassword)

	g := Gerrit{
		client: c,
		url:    opts.GerritURL,
	}

	info, _, err := c.Config.GetServerInfo(ctx)
	if err != nil {
		return nil, err
	}

	d, ok := info.Download.Schemes["http"]
	if ok { // FIXME: What to do if not ok?
		g.clonePrefix = d.URL[:len(d.URL)-10] // remove ${project}    FIXME: Is this always true?
	}
	d, ok = info.Download.Schemes["ssh"]
	if ok { // FIXME: What to do if not ok?
		g.clonePrefix = d.URL[:len(d.URL)-10] // remove ${project}    FIXME: Is this always true?
	}

	return &g, nil
}

// Name returns the string name of this driver
func (c *Gerrit) Name() string {
	return "gerrit"
}

// URL returns the root url of a configured forge
func (c *Gerrit) URL() string {
	return c.url
}

// Login is mocked
func (c *Gerrit) Login(ctx context.Context, w http.ResponseWriter, req *http.Request) (*model.User, error) {
	log.Debug().Msgf("Gerrit Login")
	user := model.User{
		Login:         "gerrit",
		Token:         "token",
		Secret:        "secret",
		Expiry:        time.Now().UTC().Unix() + 86400,
		Avatar:        "",
		ForgeRemoteID: model.ForgeRemoteID("remote-id"),
	}

	return &user, nil
}

// Auth is not implemented
func (c *Gerrit) Auth(ctx context.Context, token, _ string) (string, error) {
	log.Debug().Msgf("Gerrit Auth")
	return "gerrit-user", nil
}

// Teams is not supported by the Gerrit driver.
func (c *Gerrit) Teams(ctx context.Context, u *model.User) ([]*model.Team, error) {
	log.Debug().Msgf("Gerrit Teams")
	return nil, nil
}

// TeamPerm is not supported by the Gerrit driver.
func (c *Gerrit) TeamPerm(_ *model.User, _ string) (*model.Perm, error) {
	log.Debug().Msgf("Gerrit TeamPerm")
	return nil, nil
}

// Repo returns the Gerrit repository.
func (c *Gerrit) Repo(ctx context.Context, u *model.User, remoteID model.ForgeRemoteID, owner, name string) (*model.Repo, error) {
	log.Debug().Msgf("Gerrit Repo")
	p, _, err := c.client.Projects.GetProject(ctx, string(remoteID))
	if err != nil {
		log.Err(err)
		return nil, err
	}
	return c.toRepo(p), nil
}

// Repos returns a list of all repositories on the Gerrit server.
func (c *Gerrit) Repos(ctx context.Context, u *model.User) ([]*model.Repo, error) {
	log.Debug().Msgf("Gerrit Repos")

	opt := &gerrit.ProjectOptions{
		Description: true,
	}
	projs, _, err := c.client.Projects.ListProjects(ctx, opt)
	if err != nil {
		log.Err(err)
		return nil, err
	}

	result := make([]*model.Repo, len(*projs))
	i := 0
	for _, proj := range *projs {
		log.Debug().Msgf("Gerrit Repos: %#v", proj)
		result[i] = c.toRepo(&proj)
		i++
	}

	return result, nil
}

// File fetches the file from the Gerrit repository and returns its contents.
func (c *Gerrit) File(ctx context.Context, u *model.User, r *model.Repo, b *model.Pipeline, f string) ([]byte, error) {
	log.Debug().Msgf("Gerrit File")
	content := []byte("Hello, world!")
	return content, nil
}

func (c *Gerrit) Dir(ctx context.Context, u *model.User, r *model.Repo, b *model.Pipeline, f string) ([]*forge_types.FileMeta, error) {
	log.Debug().Msgf("Gerrit Dir")
	var files []*forge_types.FileMeta
	return files, nil
}

// Status
func (c *Gerrit) Status(ctx context.Context, user *model.User, repo *model.Repo, pipeline *model.Pipeline, workflow *model.Workflow) error {
	log.Debug().Msgf("Gerrit Status")
	return nil
}

// Netrc returns a netrc file capable of authenticating Gerrit requests and
// cloning Gerrit repositories. The netrc will use the global machine account
// when configured.
func (c *Gerrit) Netrc(u *model.User, r *model.Repo) (*model.Netrc, error) {
	log.Debug().Msgf("Gerrit Netrc")
	login := ""
	token := ""

	if u != nil {
		login = u.Login
		token = u.Token
	}

	host, err := common.ExtractHostFromCloneURL(r.Clone)
	if err != nil {
		return nil, err
	}

	return &model.Netrc{
		Login:    login,
		Password: token,
		Machine:  host,
	}, nil
}

// Activate activates the repository
func (c *Gerrit) Activate(ctx context.Context, u *model.User, r *model.Repo, link string) error {
	log.Debug().Msgf("Gerrit Activate")
	return nil
}

// Deactivate deactivates the repository
func (c *Gerrit) Deactivate(ctx context.Context, u *model.User, r *model.Repo, link string) error {
	log.Debug().Msgf("Gerrit Deactivate")
	return nil
}

// Branches returns the names of all branches for the named repository.
func (c *Gerrit) Branches(ctx context.Context, u *model.User, r *model.Repo, p *model.ListOptions) ([]string, error) {
	log.Debug().Msgf("Gerrit Branches")
	lb, _, err := c.client.Projects.ListBranches(ctx, string(r.ForgeRemoteID), nil)
	if err != nil {
		return nil, err
	}

	n := p.Page*p.PerPage - p.PerPage
	m := n + p.PerPage

	branches := make([]string, 0)
	for i, b := range *lb {
		if i >= n && i < m && strings.HasPrefix(b.Ref, "refs/heads/") {
			branches = append(branches, b.Ref[11:])
		}
	}

	return branches, nil
}

// BranchHead returns the sha of the head (latest commit) of the specified branch
func (c *Gerrit) BranchHead(ctx context.Context, u *model.User, r *model.Repo, branch string) (string, error) {
	log.Debug().Msgf("Gerrit BranchHead")
	return "1111111111111111111111111111111111111111", nil
}

// PullRequuests lists Changes for a repository in Gerrit.
func (c *Gerrit) PullRequests(ctx context.Context, u *model.User, r *model.Repo, p *model.ListOptions) ([]*model.PullRequest, error) {
	log.Debug().Msgf("Gerrit PullRequests")

	opt := &gerrit.QueryChangeOptions{
		QueryOptions: gerrit.QueryOptions{
			Query: []string{"status:open+project:" + r.Name},
		},
	}

	changes, _, err := c.client.Changes.QueryChanges(ctx, opt)
	if err != nil {
		return nil, err
	}

	n := p.Page*p.PerPage - p.PerPage
	m := n + p.PerPage

	prs := make([]*model.PullRequest, 0)
	for i, c := range *changes {
		if i >= n && i < m {
			pr := model.PullRequest{
				Index: model.ForgeRemoteID(fmt.Sprint(c.Number)),
				Title: c.Subject,
			}
			prs = append(prs, &pr)
		}
	}

	return prs, nil
}

// Hook parses the incoming Gerrit webhook and returns the Repository and Pipeline
// details. If the hook is unsupported nil values are returned.
func (c *Gerrit) Hook(ctx context.Context, r *http.Request) (*model.Repo, *model.Pipeline, error) {
	log.Debug().Msgf("Gerrit Hook")
	return nil, nil, nil
}

// OrgMembership returns if user is member of organization and if user
// is admin/owner in this organization.
func (c *Gerrit) OrgMembership(ctx context.Context, u *model.User, owner string) (*model.OrgPerm, error) {
	log.Debug().Msgf("Gerrit OrgMembership")
	return &model.OrgPerm{Member: true, Admin: true}, nil
}

func (c *Gerrit) Org(ctx context.Context, u *model.User, owner string) (*model.Org, error) {
	log.Debug().Msgf("Gerrit Org")
	return &model.Org{
		Name:    owner,
		IsUser:  true,
		Private: false,
	}, nil
}

func (c *Gerrit) toRepo(proj *gerrit.ProjectInfo) *model.Repo {
	perm := &model.Perm{
		Pull:  true,
		Push:  true,
		Admin: true,
	}
	r := model.Repo{
		ForgeRemoteID: model.ForgeRemoteID(proj.ID),
		Clone:         c.clonePrefix + proj.ID,
		CloneSSH:      c.clonePrefixSSH + proj.ID,
		Owner:         "gerrit",
		Name:          proj.ID,
		FullName:      proj.ID,
		ForgeURL:      c.url + "/q/project:" + proj.ID,
		IsSCMPrivate:  false,
		Branch:        "main",
		Perm:          perm,
		PREnabled:     true,
	}
	return &r
}
