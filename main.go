package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Vuln struct {
	Name    string
	Version string
}

var vulnerable = []Vuln{
	{"backslash", "0.2.1"},
	{"chalk-template", "1.1.1"},
	{"supports-hyperlinks", "4.1.1"},
	{"has-ansi", "6.0.1"},
	{"simple-swizzle", "0.2.3"},
	{"color-string", "2.1.1"},
	{"error-ex", "1.3.3"},
	{"color-name", "2.0.1"},
	{"is-arrayish", "0.3.3"},
	{"slice-ansi", "7.1.1"},
	{"color-convert", "3.1.1"},
	{"wrap-ansi", "9.0.1"},
	{"ansi-regex", "6.2.1"},
	{"supports-color", "10.2.1"},
	{"strip-ansi", "7.1.1"},
	{"chalk", "5.6.1"},
	{"debug", "4.4.2"},
	{"ansi-styles", "6.2.2"},
}

var lockFileNames = map[string]bool{
	"yarn.lock":           true,
	"package-lock.json":   true,
	"npm-shrinkwrap.json": true,
	"pnpm-lock.yaml":      true,
	"package.json":        true,
}

type LastCommit struct {
	ID            string    `json:"id"`
	ShortID       string    `json:"short_id"`
	AuthorName    string    `json:"author_name"`
	AuthorEmail   string    `json:"author_email"`
	CommittedDate time.Time `json:"committed_date"`
	WebURL        string    `json:"web_url,omitempty"`
}

type Finding struct {
	ProjectID      int64       `json:"project_id"`
	ProjectPath    string      `json:"project_path"`
	ProjectName    string      `json:"project_name"`
	WebURL         string      `json:"web_url"`
	DefaultBranch  string      `json:"default_branch"`
	Branch         string      `json:"branch"`
	FilePath       string      `json:"file_path"`
	FileURL        string      `json:"file_url"`
	Package        string      `json:"package"`
	Version        string      `json:"version"`
	MatchedLine    int         `json:"matched_line,omitempty"`
	MatchPreview   string      `json:"match_preview,omitempty"`
	LastCommit     *LastCommit `json:"last_commit,omitempty"`
	DetectionNotes string      `json:"detection_notes,omitempty"`
}

type Report struct {
	GeneratedAt time.Time `json:"generated_at"`
	GitLabURL   string    `json:"gitlab_url"`
	Findings    []Finding `json:"vulnerabilities"`
}

// ====== GitLab API минимальный клиент ======

type GitLabClient struct {
	base   string
	token  string
	client *http.Client
}

func NewGitLabClient(base, token string) *GitLabClient {
	tr := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		MaxIdleConns:        200,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
		ForceAttemptHTTP2:   true,
	}
	return &GitLabClient{
		base:  strings.TrimRight(base, "/"),
		token: token,
		client: &http.Client{
			Timeout:   45 * time.Second,
			Transport: tr,
		},
	}
}

func (g *GitLabClient) do(ctx context.Context, method, p string, q url.Values) (*http.Response, error) {
	u := g.base + p
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("PRIVATE-TOKEN", g.token)
	req.Header.Set("Accept", "application/json")
	return g.client.Do(req)
}

func (g *GitLabClient) getRaw(ctx context.Context, p string, q url.Values) (*http.Response, error) {
	u := g.base + p
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("PRIVATE-TOKEN", g.token)
	return g.client.Do(req)
}

// ====== Структуры GitLab ======

type Project struct {
	ID             int64  `json:"id"`
	PathWithNS     string `json:"path_with_namespace"`
	Name           string `json:"name"`
	WebURL         string `json:"web_url"`
	DefaultBranch  string `json:"default_branch"`
	Archived       bool   `json:"archived"`
	LastActivityAt string `json:"last_activity_at"`
}

type TreeItem struct {
	Path string `json:"path"`
	Type string `json:"type"`
}

type Commit struct {
	ID            string `json:"id"`
	ShortID       string `json:"short_id"`
	AuthorName    string `json:"author_name"`
	AuthorEmail   string `json:"author_email"`
	CommittedDate string `json:"committed_date"`
	WebURL        string `json:"web_url"`
}

type Branch struct {
	Name    string `json:"name"`
	Default bool   `json:"default"`
}

func listAllProjects(ctx context.Context, gl *GitLabClient, includeArchived bool) ([]Project, error) {
	var out []Project
	page := 1
	for {
		q := url.Values{}
		q.Set("membership", "true")
		q.Set("simple", "true")
		q.Set("per_page", "100")
		q.Set("page", strconv.Itoa(page))
		resp, err := gl.do(ctx, "GET", "/api/v4/projects", q)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != 200 {
			b, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			return nil, fmt.Errorf("list projects: http %d: %s", resp.StatusCode, string(b))
		}
		var batch []Project
		if err := json.NewDecoder(resp.Body).Decode(&batch); err != nil {
			_ = resp.Body.Close()
			return nil, err
		}
		_ = resp.Body.Close()
		if len(batch) == 0 {
			break
		}
		for _, p := range batch {
			if !includeArchived && p.Archived {
				continue
			}
			out = append(out, p)
		}
		page++
	}
	return out, nil
}

func listRepoTreeAll(ctx context.Context, gl *GitLabClient, projectID int64, ref string) ([]TreeItem, error) {
	var out []TreeItem
	page := 1
	for {
		q := url.Values{}
		q.Set("ref", ref)
		q.Set("recursive", "true")
		q.Set("per_page", "100")
		q.Set("page", strconv.Itoa(page))
		resp, err := gl.do(ctx, "GET",
			fmt.Sprintf("/api/v4/projects/%d/repository/tree", projectID), q)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != 200 {
			b, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			return nil, fmt.Errorf("tree: http %d: %s", resp.StatusCode, string(b))
		}
		var batch []TreeItem
		if err := json.NewDecoder(resp.Body).Decode(&batch); err != nil {
			_ = resp.Body.Close()
			return nil, err
		}
		_ = resp.Body.Close()
		if len(batch) == 0 {
			break
		}
		out = append(out, batch...)
		page++
	}
	return out, nil
}

func getFileRaw(ctx context.Context, gl *GitLabClient, projectID int64, filePath, ref string) ([]byte, error) {
	encPath := url.PathEscape(filePath)
	resp, err := gl.getRaw(ctx, fmt.Sprintf("/api/v4/projects/%d/repository/files/%s/raw", projectID, encPath),
		url.Values{"ref": []string{ref}})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("raw %s: http %d: %s", filePath, resp.StatusCode, string(b))
	}
	return io.ReadAll(resp.Body)
}

func getLastCommitForPath(ctx context.Context, gl *GitLabClient, projectID int64, ref, filePath string) (*LastCommit, error) {
	q := url.Values{}
	q.Set("ref_name", ref)
	q.Set("path", filePath)
	q.Set("per_page", "1")
	resp, err := gl.do(ctx, "GET", fmt.Sprintf("/api/v4/projects/%d/repository/commits", projectID), q)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("commits: http %d: %s", resp.StatusCode, string(b))
	}
	var commits []Commit
	if err := json.NewDecoder(resp.Body).Decode(&commits); err != nil {
		return nil, err
	}
	if len(commits) == 0 {
		return nil, nil
	}
	c := commits[0]
	t, _ := time.Parse(time.RFC3339, c.CommittedDate)
	return &LastCommit{
		ID:            c.ID,
		ShortID:       c.ShortID,
		AuthorName:    c.AuthorName,
		AuthorEmail:   c.AuthorEmail,
		CommittedDate: t,
		WebURL:        c.WebURL,
	}, nil
}

func listBranchesAll(ctx context.Context, gl *GitLabClient, projectID int64) ([]Branch, error) {
	var out []Branch
	page := 1
	for {
		q := url.Values{}
		q.Set("per_page", "100")
		q.Set("page", strconv.Itoa(page))
		resp, err := gl.do(ctx, "GET", fmt.Sprintf("/api/v4/projects/%d/repository/branches", projectID), q)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != 200 {
			b, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			return nil, fmt.Errorf("branches: http %d: %s", resp.StatusCode, string(b))
		}
		var batch []Branch
		if err := json.NewDecoder(resp.Body).Decode(&batch); err != nil {
			_ = resp.Body.Close()
			return nil, err
		}
		_ = resp.Body.Close()
		if len(batch) == 0 {
			break
		}
		out = append(out, batch...)
		page++
	}
	return out, nil
}

type match struct {
	pkg       string
	version   string
	line      int
	preview   string
	detection string
}

func scanYarnLock(content []byte, vulns []Vuln) []match {
	lines := bytes.Split(content, []byte("\n"))
	want := make(map[string]string, len(vulns))
	for _, v := range vulns {
		want[v.Name] = v.Version
	}
	var matches []match

	// Регексы
	headerRe := regexp.MustCompile(`^"?(@?[^"@/]+/)?([A-Za-z0-9_.\-]+)@`) // "name@" или @scope/name@
	versionRe1 := regexp.MustCompile(`^\s*version\s+"?([0-9]+\.[0-9]+\.[0-9]+)"?\s*$`)
	versionRe2 := regexp.MustCompile(`^\s*version:\s+"?([0-9]+\.[0-9]+\.[0-9]+)"?\s*$`)

	currentPkg := ""
	for i := 0; i < len(lines); i++ {
		line := string(bytes.TrimSpace(lines[i]))
		if strings.HasSuffix(line, ":") && !strings.HasPrefix(line, "version") {
			m := headerRe.FindStringSubmatch(line)
			if m != nil {
				header := strings.TrimSuffix(line, ":")
				name := header
				name = strings.Trim(name, `"`)
				if at := strings.LastIndex(name, "@"); at > 0 {
					name = name[:at]
				}
				if strings.Contains(name, "/") && strings.HasPrefix(name, "@") {
					currentPkg = name
				} else {
					if slash := strings.Index(name, "@"); slash > 0 {
						name = name[:slash]
					}
					currentPkg = name
				}
			} else {
				currentPkg = ""
			}
			continue
		}
		if currentPkg != "" {
			if m := versionRe1.FindStringSubmatch(line); m != nil {
				if v, ok := want[currentPkg]; ok && v == m[1] {
					preview := line
					matches = append(matches, match{
						pkg:       currentPkg,
						version:   m[1],
						line:      i + 1,
						preview:   preview,
						detection: "yarn.lock block version",
					})
				}
			} else if m := versionRe2.FindStringSubmatch(line); m != nil {
				if v, ok := want[currentPkg]; ok && v == m[1] {
					preview := line
					matches = append(matches, match{
						pkg:       currentPkg,
						version:   m[1],
						line:      i + 1,
						preview:   preview,
						detection: "yarn.lock block version:",
					})
				}
			}
			if strings.TrimSpace(line) == "" {
				currentPkg = ""
			}
		}
	}
	return matches
}

func scanPackageLockJSON(content []byte, vulns []Vuln) []match {
	type any = interface{}
	var root any
	if err := json.Unmarshal(content, &root); err != nil {
		return nil
	}
	want := make(map[string]string, len(vulns))
	for _, v := range vulns {
		want[v.Name] = v.Version
	}
	var matches []match
	visit := func(node any) {}
	var walk func(node any)
	walk = func(node any) {
		switch n := node.(type) {
		case map[string]any:
			var name, ver string
			if v, ok := n["name"].(string); ok {
				name = v
			}
			if v, ok := n["version"].(string); ok {
				ver = v
			}
			if name != "" && ver != "" {
				if want[name] == ver {
					matches = append(matches, match{
						pkg:       name,
						version:   ver,
						line:      0,
						preview:   fmt.Sprintf(`"name":"%s","version":"%s"`, name, ver),
						detection: "package-lock packages/name+version",
					})
				}
			}
			if deps, ok := n["dependencies"].(map[string]any); ok {
				for depName, depVal := range deps {
					if m2, ok2 := depVal.(map[string]any); ok2 {
						if ver2, okv := m2["version"].(string); okv {
							if want[depName] == ver2 {
								matches = append(matches, match{
									pkg:       depName,
									version:   ver2,
									detection: "package-lock dependencies map",
								})
							}
						}
					}
				}
			}
			for _, v := range n {
				walk(v)
			}
		case []any:
			for _, v := range n {
				walk(v)
			}
		}
	}
	_ = visit
	walk(root)
	return uniqueMatches(matches)
}

// -- pnpm-lock.yaml: без YAML зависимостей — быстрые эвристики по ключам "/name@version:"
func scanPnpmLock(content []byte, vulns []Vuln) []match {
	text := string(content)
	var matches []match
	for _, v := range vulns {
		// варианты ключей: "/name@x.y.z:" или "'/name@x.y.z':"
		p := regexp.MustCompile(fmt.Sprintf(`(?m)^['"]?/%s@%s['"]?:`, regexp.QuoteMeta(v.Name), regexp.QuoteMeta(v.Version)))
		loc := p.FindStringIndex(text)
		if loc != nil {
			line := 1 + bytes.Count(content[:loc[0]], []byte("\n"))
			snippet := firstLineAt(content, loc[0])
			matches = append(matches, match{
				pkg:       v.Name,
				version:   v.Version,
				line:      line,
				preview:   snippet,
				detection: "pnpm-lock key",
			})
			continue
		}
		// fallback: имя и версия поблизости
		nameNear := regexp.MustCompile(fmt.Sprintf(`(?m)^\s*name:\s*['"]?%s['"]?\s*$`, regexp.QuoteMeta(v.Name)))
		if m1 := nameNear.FindStringIndex(text); m1 != nil {
			// ищем рядом version:
			win := text[m1[0]:min(m1[0]+500, len(text))]
			rev := regexp.MustCompile(fmt.Sprintf(`(?m)^\s*version:\s*['"]?%s['"]?\s*$`, regexp.QuoteMeta(v.Version)))
			if rev.FindStringIndex(win) != nil {
				line := 1 + bytes.Count(content[:m1[0]], []byte("\n"))
				matches = append(matches, match{
					pkg:       v.Name,
					version:   v.Version,
					line:      line,
					preview:   "name/version block",
					detection: "pnpm name+version block",
				})
			}
		}
	}
	return uniqueMatches(matches)
}

func firstLineAt(content []byte, idx int) string {
	start := idx
	for start > 0 && content[start-1] != '\n' {
		start--
	}
	end := idx
	for end < len(content) && content[end] != '\n' {
		end++
	}
	return string(content[start:end])
}

func uniqueMatches(in []match) []match {
	type key struct{ n, v string }
	seen := map[key]bool{}
	var out []match
	for _, m := range in {
		k := key{m.pkg, m.version}
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, m)
	}
	return out
}

// ====== package.json scanning ======
func scanPackageJSON(content []byte, vulns []Vuln) []match {
	type PkgJSON struct {
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
		PeerDependencies     map[string]string `json:"peerDependencies"`
		Resolutions          map[string]string `json:"resolutions"`
		Overrides            any               `json:"overrides"`
	}
	var pj PkgJSON
	if err := json.Unmarshal(content, &pj); err != nil {
		return nil
	}
	want := make(map[string]string, len(vulns))
	for _, v := range vulns {
		want[v.Name] = v.Version
	}
	var matches []match
	addFrom := func(m map[string]string, det string) {
		for n, ver := range m {
			if want[n] == ver {
				matches = append(matches, match{pkg: n, version: ver, detection: det})
			}
		}
	}
	if pj.Dependencies != nil {
		addFrom(pj.Dependencies, "package.json dependencies")
	}
	if pj.DevDependencies != nil {
		addFrom(pj.DevDependencies, "package.json devDependencies")
	}
	if pj.OptionalDependencies != nil {
		addFrom(pj.OptionalDependencies, "package.json optionalDependencies")
	}
	if pj.PeerDependencies != nil {
		addFrom(pj.PeerDependencies, "package.json peerDependencies")
	}
	if pj.Resolutions != nil {
		addFrom(pj.Resolutions, "package.json resolutions")
	}
	if ov, ok := pj.Overrides.(map[string]any); ok {
		tmp := make(map[string]string)
		for name, raw := range ov {
			if s, ok := raw.(string); ok {
				tmp[name] = s
			}
		}
		if len(tmp) > 0 {
			addFrom(tmp, "package.json overrides")
		}
	}
	return uniqueMatches(matches)
}

// ====== Основная логика ======

var (
	verboseFlag       = flag.Bool("v", false, "verbose logging")
	fileConcurrency   = flag.Int("file-concurrency", 4, "parallel files per project")
	branchConcurrency = flag.Int("branch-concurrency", 3, "parallel branches per project")
	activeWithinDays  = flag.Int("active-within-days", 90, "only scan projects active within N days")
)

func main() {
	var (
		concurrency     = flag.Int("concurrency", 6, "parallel projects")
		includeArchived = flag.Bool("include-archived", false, "include archived projects")
	)
	flag.Parse()

	log.SetOutput(os.Stderr)
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	base := os.Getenv("GITLAB_URL")
	token := os.Getenv("GITLAB_TOKEN")
	if base == "" || token == "" {
		fmt.Fprintln(os.Stderr, "Set GITLAB_URL and GITLAB_TOKEN environment variables")
		os.Exit(2)
	}
	ctx := context.Background()
	gl := NewGitLabClient(base, token)

	projects, err := listAllProjects(ctx, gl, *includeArchived)
	if err != nil {
		fail(err)
	}
	cutoff := time.Now().Add(-time.Duration(*activeWithinDays) * 24 * time.Hour)
	var filtered []Project
	for _, p := range projects {
		if !*includeArchived && p.Archived {
			continue
		}
		if p.LastActivityAt == "" {
			continue
		}
		if t, err := time.Parse(time.RFC3339, p.LastActivityAt); err == nil {
			if t.Before(cutoff) {
				continue
			}
			filtered = append(filtered, p)
		}
	}
	projects = filtered
	log.Printf("[INFO] Projects fetched: %d, after last-activity filter (%d days): %d", len(filtered)+0, *activeWithinDays, len(projects))

	type job struct{ P Project }
	jobs := make(chan job)
	var mu sync.Mutex
	var findings []Finding
	var wg sync.WaitGroup

	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				fs, _ := scanProject(ctx, gl, j.P)
				mu.Lock()
				findings = append(findings, fs...)
				mu.Unlock()
			}
		}()
	}

	for _, p := range projects {
		// пропустим проекты без веток (редко)
		jobs <- job{P: p}
	}
	close(jobs)
	wg.Wait()

	rep := Report{
		GeneratedAt: time.Now().UTC(),
		GitLabURL:   base,
		Findings:    findings,
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(rep); err != nil {
		fail(err)
	}
}

func scanProject(ctx context.Context, gl *GitLabClient, p Project) ([]Finding, error) {
	branches, err := listBranchesAll(ctx, gl, p.ID)
	if err != nil || len(branches) == 0 {
		return nil, err
	}
	if *verboseFlag {
		log.Printf("[INFO] %s: scanning %d branches", p.PathWithNS, len(branches))
	}
	var all []Finding
	var mu sync.Mutex
	var wg sync.WaitGroup
	n := *branchConcurrency
	if n < 1 {
		n = 1
	}
	if n > len(branches) {
		n = len(branches)
	}
	jobs := make(chan string)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ref := range jobs {
				fs, _ := scanProjectOnRef(ctx, gl, p, ref)
				if len(fs) > 0 {
					mu.Lock()
					all = append(all, fs...)
					mu.Unlock()
				}
			}
		}()
	}
	for _, b := range branches {
		jobs <- b.Name
	}
	close(jobs)
	wg.Wait()
	return all, nil
}

func scanProjectOnRef(ctx context.Context, gl *GitLabClient, p Project, ref string) ([]Finding, error) {
	start := time.Now()
	log.Printf("[INFO] Scanning %s @ %s", p.PathWithNS, ref)
	tree, err := listRepoTreeAll(ctx, gl, p.ID, ref)
	if err != nil {
		return nil, err
	}
	var targets []TreeItem
	for _, it := range tree {
		if it.Type != "blob" {
			continue
		}
		_, name := path.Split(it.Path)
		if lockFileNames[name] {
			targets = append(targets, it)
		}
	}
	if len(targets) == 0 {
		if *verboseFlag {
			log.Printf("[DEBUG] %s@%s: no lock files found", p.PathWithNS, ref)
		}
		return nil, nil
	}
	if *verboseFlag {
		log.Printf("[DEBUG] %s@%s: %d candidate files", p.PathWithNS, ref, len(targets))
	}
	var (
		res []Finding
		mu  sync.Mutex
		wg  sync.WaitGroup
	)
	n := *fileConcurrency
	if n < 1 {
		n = 1
	}
	if n > len(targets) {
		n = len(targets)
	}
	jobs := make(chan TreeItem)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range jobs {
				if *verboseFlag {
					log.Printf("[DEBUG] %s@%s: scanning %s", p.PathWithNS, ref, t.Path)
				}
				body, err := getFileRaw(ctx, gl, p.ID, t.Path, ref)
				if err != nil {
					if *verboseFlag {
						log.Printf("[WARN] %s@%s: raw fetch failed for %s: %v", p.PathWithNS, ref, t.Path, err)
					}
					continue
				}
				var ms []match
				switch {
				case strings.HasSuffix(t.Path, "yarn.lock"):
					ms = scanYarnLock(body, vulnerable)
				case strings.HasSuffix(t.Path, "package-lock.json"), strings.HasSuffix(t.Path, "npm-shrinkwrap.json"):
					ms = scanPackageLockJSON(body, vulnerable)
				case strings.HasSuffix(t.Path, "pnpm-lock.yaml"):
					ms = scanPnpmLock(body, vulnerable)
				case strings.HasSuffix(t.Path, "package.json"):
					ms = scanPackageJSON(body, vulnerable)
				default:
					ms = scanPnpmLock(body, vulnerable)
				}
				if len(ms) == 0 {
					continue
				}
				commit, _ := getLastCommitForPath(ctx, gl, p.ID, ref, t.Path)
				fileURL := fmt.Sprintf("%s/%s/-/blob/%s/%s", gl.base, p.PathWithNS, url.PathEscape(ref), url.PathEscape(t.Path))
				var local []Finding
				for _, m := range ms {
					f := Finding{
						ProjectID:      p.ID,
						ProjectPath:    p.PathWithNS,
						ProjectName:    p.Name,
						WebURL:         p.WebURL,
						DefaultBranch:  p.DefaultBranch,
						Branch:         ref,
						FilePath:       t.Path,
						FileURL:        fileURL,
						Package:        m.pkg,
						Version:        m.version,
						MatchedLine:    m.line,
						MatchPreview:   m.preview,
						DetectionNotes: m.detection,
					}
					if commit != nil {
						f.LastCommit = commit
					}
					local = append(local, f)
				}
				if *verboseFlag {
					log.Printf("[DEBUG] %s@%s: %s -> %d matches", p.PathWithNS, ref, t.Path, len(local))
				}
				mu.Lock()
				res = append(res, local...)
				mu.Unlock()
			}
		}()
	}
	for _, t := range targets {
		jobs <- t
	}
	close(jobs)
	wg.Wait()
	if *verboseFlag {
		log.Printf("[DEBUG] %s@%s: completed in %s with %d findings", p.PathWithNS, ref, time.Since(start).Round(time.Millisecond), len(res))
	}
	return res, nil
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "ERROR:", err)
	os.Exit(1)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
