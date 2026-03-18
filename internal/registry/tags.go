package registry

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	defaultRegistryHost = "registry.rancher.com"
	registryEnv         = "RKE2_PATCHER_REGISTRY"
	defaultPage         = 100
)

type Tag struct {
	Name        string
	LastUpdated time.Time
}

type tagsPage struct {
	Tags []string `json:"tags"`
}

type bearerChallenge struct {
	Realm   string
	Service string
	Scope   string
}

func ListTags(repository string, limit int) ([]Tag, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("limit must be greater than zero")
	}

	baseURL, err := resolveRegistryBaseURL()
	if err != nil {
		return nil, err
	}

	repositoryPath, err := normalizeRepository(repository)
	if err != nil {
		return nil, err
	}

	pageSize := defaultPage
	if limit < pageSize {
		pageSize = limit
	}

	next := fmt.Sprintf("%s/v2/%s/tags/list?n=%d", baseURL, escapeRepositoryPath(repositoryPath), pageSize)
	client := &http.Client{Timeout: 20 * time.Second}
	tags := make([]Tag, 0, limit)
	seen := make(map[string]struct{}, limit)
	bearerToken := ""

	for next != "" && len(tags) < limit {
		page, nextURL, resolvedToken, pageErr := getTagsPage(client, next, baseURL, repositoryPath, bearerToken)
		if pageErr != nil {
			return nil, pageErr
		}
		if strings.TrimSpace(resolvedToken) != "" {
			bearerToken = strings.TrimSpace(resolvedToken)
		}

		for _, name := range page.Tags {
			if strings.EqualFold(name, "latest") {
				continue
			}

			lowerName := strings.ToLower(name)
			if strings.HasPrefix(lowerName, "sha256-") {
				continue
			}
			if strings.HasSuffix(lowerName, ".sig") || strings.HasSuffix(lowerName, ".att") {
				continue
			}

			if _, found := seen[name]; found {
				continue
			}

			seen[name] = struct{}{}
			tags = append(tags, Tag{Name: name})

			if len(tags) == limit {
				break
			}
		}

		next = nextURL
	}

	if len(tags) == 0 {
		return nil, fmt.Errorf("no tags found for repository %q", repository)
	}

	return tags, nil
}

func LatestTag(repository string) (Tag, error) {
	tags, err := ListTags(repository, 1)
	if err != nil {
		return Tag{}, err
	}

	return tags[0], nil
}

func getTagsPage(client *http.Client, requestURL string, baseURL string, repository string, bearerToken string) (tagsPage, string, string, error) {
	page, nextURL, err := getTagsPageWithBearer(client, requestURL, baseURL, bearerToken)
	if err == nil {
		return page, nextURL, bearerToken, nil
	}

	statusErr, ok := err.(httpStatusError)
	if !ok || statusErr.StatusCode != http.StatusUnauthorized {
		return tagsPage{}, "", "", err
	}

	challenge, parseErr := parseBearerChallenge(statusErr.WWWAuthenticate)
	if parseErr != nil {
		return tagsPage{}, "", "", parseErr
	}

	if strings.TrimSpace(challenge.Scope) == "" {
		challenge.Scope = fmt.Sprintf("repository:%s:pull", repository)
	}

	token, tokenErr := fetchBearerToken(client, challenge)
	if tokenErr != nil {
		return tagsPage{}, "", "", tokenErr
	}

	page, nextURL, err = getTagsPageWithBearer(client, requestURL, baseURL, token)
	if err != nil {
		return tagsPage{}, "", "", err
	}

	return page, nextURL, token, nil
}

func getTagsPageWithBearer(client *http.Client, requestURL string, baseURL string, bearerToken string) (tagsPage, string, error) {
	request, err := http.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		return tagsPage{}, "", err
	}

	if strings.TrimSpace(bearerToken) != "" {
		request.Header.Set("Authorization", "Bearer "+strings.TrimSpace(bearerToken))
	}

	response, err := client.Do(request)
	if err != nil {
		return tagsPage{}, "", err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(io.LimitReader(response.Body, 2048))
		return tagsPage{}, "", httpStatusError{
			StatusCode:      response.StatusCode,
			Body:            strings.TrimSpace(string(bodyBytes)),
			WWWAuthenticate: strings.TrimSpace(response.Header.Get("Www-Authenticate")),
		}
	}

	var page tagsPage
	if err := json.NewDecoder(response.Body).Decode(&page); err != nil {
		return tagsPage{}, "", err
	}

	nextURL, err := parseNextPageURL(response.Header.Get("Link"), baseURL)
	if err != nil {
		return tagsPage{}, "", err
	}

	return page, nextURL, nil
}

func fetchBearerToken(client *http.Client, challenge bearerChallenge) (string, error) {
	realm := strings.TrimSpace(challenge.Realm)
	if realm == "" {
		return "", fmt.Errorf("registry authorization challenge did not include a realm")
	}

	authURL, err := url.Parse(realm)
	if err != nil {
		return "", fmt.Errorf("invalid registry authorization realm %q: %w", realm, err)
	}

	query := authURL.Query()
	if strings.TrimSpace(challenge.Service) != "" {
		query.Set("service", strings.TrimSpace(challenge.Service))
	}
	if strings.TrimSpace(challenge.Scope) != "" {
		query.Set("scope", strings.TrimSpace(challenge.Scope))
	}
	authURL.RawQuery = query.Encode()

	response, err := client.Get(authURL.String())
	if err != nil {
		return "", err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(io.LimitReader(response.Body, 2048))
		return "", fmt.Errorf("registry token endpoint returned status %d: %s", response.StatusCode, strings.TrimSpace(string(bodyBytes)))
	}

	var payload struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}

	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		return "", err
	}

	token := strings.TrimSpace(payload.Token)
	if token == "" {
		token = strings.TrimSpace(payload.AccessToken)
	}

	if token == "" {
		return "", fmt.Errorf("registry token endpoint did not return a token")
	}

	return token, nil
}

func parseBearerChallenge(headerValue string) (bearerChallenge, error) {
	trimmed := strings.TrimSpace(headerValue)
	if trimmed == "" {
		return bearerChallenge{}, fmt.Errorf("registry returned unauthorized without WWW-Authenticate header")
	}

	prefix := "bearer "
	if !strings.HasPrefix(strings.ToLower(trimmed), prefix) {
		return bearerChallenge{}, fmt.Errorf("unsupported registry auth challenge %q", headerValue)
	}

	params := strings.TrimSpace(trimmed[len(prefix):])
	parts := strings.Split(params, ",")

	challenge := bearerChallenge{}
	for _, part := range parts {
		key, value, found := strings.Cut(strings.TrimSpace(part), "=")
		if !found {
			continue
		}

		decoded := strings.Trim(strings.TrimSpace(value), "\"")
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "realm":
			challenge.Realm = decoded
		case "service":
			challenge.Service = decoded
		case "scope":
			challenge.Scope = decoded
		}
	}

	if strings.TrimSpace(challenge.Realm) == "" {
		return bearerChallenge{}, fmt.Errorf("registry authorization challenge did not include a realm")
	}

	return challenge, nil
}

func parseNextPageURL(linkHeader string, baseURL string) (string, error) {
	trimmed := strings.TrimSpace(linkHeader)
	if trimmed == "" {
		return "", nil
	}

	start := strings.Index(trimmed, "<")
	end := strings.Index(trimmed, ">")
	if start < 0 || end <= start+1 {
		return "", fmt.Errorf("invalid Link header for tags pagination: %q", linkHeader)
	}

	next := strings.TrimSpace(trimmed[start+1 : end])
	if next == "" {
		return "", nil
	}

	parsedNext, err := url.Parse(next)
	if err != nil {
		return "", fmt.Errorf("invalid next tags URL %q: %w", next, err)
	}

	if parsedNext.IsAbs() {
		return parsedNext.String(), nil
	}

	base, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	return base.ResolveReference(parsedNext).String(), nil
}

func resolveRegistryBaseURL() (string, error) {
	rawValue := strings.TrimSpace(os.Getenv(registryEnv))
	if rawValue == "" {
		rawValue = defaultRegistryHost
	}

	if !strings.Contains(rawValue, "://") {
		rawValue = "https://" + rawValue
	}

	parsed, err := url.Parse(rawValue)
	if err != nil {
		return "", fmt.Errorf("invalid %s value %q: %w", registryEnv, rawValue, err)
	}

	scheme := strings.ToLower(strings.TrimSpace(parsed.Scheme))
	if scheme != "https" && scheme != "http" {
		return "", fmt.Errorf("invalid %s value %q: scheme must be http or https", registryEnv, rawValue)
	}

	host := strings.TrimSpace(parsed.Host)
	if host == "" {
		return "", fmt.Errorf("invalid %s value %q: missing registry host", registryEnv, rawValue)
	}

	parsed.Path = strings.TrimRight(parsed.Path, "/")
	parsed.RawQuery = ""
	parsed.Fragment = ""

	return parsed.String(), nil
}

func normalizeRepository(repository string) (string, error) {
	trimmed := strings.Trim(strings.TrimSpace(repository), "/")
	if trimmed == "" {
		return "", fmt.Errorf("repository %q must be in the format <namespace>/<repo>", repository)
	}

	parts := strings.Split(trimmed, "/")
	if len(parts) < 2 {
		return "", fmt.Errorf("repository %q must be in the format <namespace>/<repo>", repository)
	}

	for _, part := range parts {
		if strings.TrimSpace(part) == "" {
			return "", fmt.Errorf("repository %q must be in the format <namespace>/<repo>", repository)
		}
	}

	return trimmed, nil
}

func escapeRepositoryPath(repository string) string {
	parts := strings.Split(repository, "/")
	escaped := make([]string, 0, len(parts))
	for _, part := range parts {
		escaped = append(escaped, url.PathEscape(part))
	}

	return strings.Join(escaped, "/")
}

type httpStatusError struct {
	StatusCode      int
	Body            string
	WWWAuthenticate string
}

func (err httpStatusError) Error() string {
	if strings.TrimSpace(err.Body) == "" {
		return fmt.Sprintf("registry API returned status %d", err.StatusCode)
	}

	return fmt.Sprintf("registry API returned status %d: %s", err.StatusCode, err.Body)
}
