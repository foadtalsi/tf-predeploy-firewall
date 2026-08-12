package licensing

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Rule pack delivery.
//
// The scanner ships with a free base pack embedded in its binary, covering
// the resource types most repos are made of. Licensed orgs additionally get
// an extended pack — the provider's full resource surface plus ForceNew data
// for every type — fetched here and overlaid on the base pack.
//
// Three properties this has to hold, in priority order:
//
//  1. A scan never fails because of us. If the control plane is down, slow,
//     or returns garbage, the scan runs on whatever pack is available: the
//     last good cached copy, or failing that the embedded base pack. A
//     billing-side outage turning a customer's PR check red would be a worse
//     failure than any it detects.
//  2. Findings never appear or vanish silently. The pack actually used is
//     reported in the scan output, so "why did this stop being flagged?" has
//     an answer.
//  3. We don't re-download 560 KB on every scan. Packs are cached on disk and
//     revalidated with an ETag, so the steady state is a 304.

// PackCacheTTL is how long a cached pack is used without revalidating.
// Packs change only when the provider ships a release, so revalidating each
// scan would spend a round trip to be told "unchanged" almost every time.
const PackCacheTTL = 24 * time.Hour

// packFetchTimeout is deliberately shorter than the client's default: a slow
// pack fetch delays every PR check, and falling back to the base pack is a
// perfectly good outcome.
const packFetchTimeout = 15 * time.Second

// RulePack is a fetched or cached pack, ready to hand to schema.LoadWith.
type RulePack struct {
	// Provider is the provider the pack describes ("aws").
	Provider string
	// Data is the gzipped pack body.
	Data []byte
	// FromCache reports whether this came from disk rather than the network.
	FromCache bool
	// ETag identifies this pack version.
	ETag string
}

// Reader returns the pack body as a reader.
func (p *RulePack) Reader() io.Reader { return bytes.NewReader(p.Data) }

// ErrNoPackAvailable means neither the network nor the cache could supply an
// extended pack. It is not a failure of the scan — the caller falls back to
// the embedded base pack.
var ErrNoPackAvailable = errors.New("no extended rule pack available")

// FetchRulePack returns the extended rule pack for a provider, preferring a
// fresh copy, then a cached one, and reporting exactly which it used.
//
// The returned error is advisory: whenever it is non-nil the caller should
// warn and continue on the base pack, never abort. A nil pack with a nil
// error is not possible — one of the two is always set.
func (c *Client) FetchRulePack(provider string) (*RulePack, error) {
	cacheDir, cacheErr := packCacheDir()

	var cached *RulePack
	if cacheErr == nil {
		cached = readCachedPack(cacheDir, provider)
		// A recent cache entry is used as-is: the network round trip would
		// almost always just confirm it.
		if cached != nil && cacheFresh(cacheDir, provider) {
			cached.FromCache = true
			return cached, nil
		}
	}

	fetched, err := c.downloadRulePack(provider, cached)
	switch {
	case err == nil && fetched != nil:
		if cacheErr == nil {
			// A cache we can't write is not worth failing over; the next scan
			// simply downloads again.
			_ = writeCachedPack(cacheDir, provider, fetched)
		}
		return fetched, nil

	case err == nil && fetched == nil && cached != nil:
		// 304 Not Modified: the cache is still correct, just stale-dated.
		if cacheErr == nil {
			_ = touchCache(cacheDir, provider)
		}
		cached.FromCache = true
		return cached, nil

	case cached != nil:
		cached.FromCache = true
		return cached, fmt.Errorf("using cached rule pack: %w", err)

	default:
		if err == nil {
			err = ErrNoPackAvailable
		}
		return nil, err
	}
}

// downloadRulePack returns (nil, nil) when the server reports the cached copy
// is still current.
func (c *Client) downloadRulePack(provider string, cached *RulePack) (*RulePack, error) {
	url := fmt.Sprintf("%s/v1/rulepacks/%s", c.APIBase, provider)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("building rule pack request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	if cached != nil && cached.ETag != "" {
		req.Header.Set("If-None-Match", cached.ETag)
	}

	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	// Copy rather than mutate: the same Client is shared with usage reporting,
	// which has its own latency budget.
	bounded := *httpClient
	bounded.Timeout = packFetchTimeout

	resp, err := bounded.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching rule pack: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotModified:
		return nil, nil
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, fmt.Errorf("rule pack refused (%s) — check the license key's plan", resp.Status)
	case http.StatusNotFound:
		return nil, fmt.Errorf("no rule pack published for provider %q", provider)
	default:
		return nil, fmt.Errorf("rule pack service returned %s", resp.Status)
	}

	// Cap the read: a pack is ~0.6 MB, and an unbounded read from a service
	// we don't control is not something a CI runner should offer.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, fmt.Errorf("reading rule pack: %w", err)
	}
	if len(body) == 0 {
		return nil, errors.New("rule pack service returned an empty body")
	}

	etag := resp.Header.Get("ETag")
	if etag == "" {
		sum := sha256.Sum256(body)
		etag = `"` + hex.EncodeToString(sum[:]) + `"`
	}
	return &RulePack{Provider: provider, Data: body, ETag: etag}, nil
}

// ---------------------------------------------------------------------------
// On-disk cache
// ---------------------------------------------------------------------------

// packCacheDir resolves where packs are cached. TFPDF_CACHE_DIR exists so a
// CI job can point it at a directory it already restores between runs
// (actions/cache), turning the steady state into zero network calls.
func packCacheDir() (string, error) {
	base := os.Getenv("TFPDF_CACHE_DIR")
	if base == "" {
		userCache, err := os.UserCacheDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(userCache, "tf-predeploy-firewall")
	}
	dir := filepath.Join(base, "rulepacks")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return dir, nil
}

// packFileName keeps the provider name from escaping the cache directory: it
// arrives from configuration, and a value like "../../etc" must not decide
// where we write.
func packFileName(provider, ext string) string {
	safe := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		default:
			return '-'
		}
	}, strings.ToLower(provider))
	if safe == "" {
		safe = "unknown"
	}
	return safe + ext
}

func readCachedPack(dir, provider string) *RulePack {
	data, err := os.ReadFile(filepath.Join(dir, packFileName(provider, ".pack.gz")))
	if err != nil || len(data) == 0 {
		return nil
	}
	etag, _ := os.ReadFile(filepath.Join(dir, packFileName(provider, ".etag")))
	return &RulePack{
		Provider: provider,
		Data:     data,
		ETag:     strings.TrimSpace(string(etag)),
	}
}

func writeCachedPack(dir, provider string, p *RulePack) error {
	packPath := filepath.Join(dir, packFileName(provider, ".pack.gz"))
	// Write via a temp file and rename: two scans can run concurrently on the
	// same runner, and a half-written pack read by the other one would be a
	// corrupt-pack error rather than a clean miss.
	tmp, err := os.CreateTemp(dir, "pack-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.Write(p.Data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), packPath); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, packFileName(provider, ".etag")), []byte(p.ETag), 0o644)
}

func cacheFresh(dir, provider string) bool {
	info, err := os.Stat(filepath.Join(dir, packFileName(provider, ".pack.gz")))
	if err != nil {
		return false
	}
	return time.Since(info.ModTime()) < PackCacheTTL
}

func touchCache(dir, provider string) error {
	now := time.Now()
	return os.Chtimes(filepath.Join(dir, packFileName(provider, ".pack.gz")), now, now)
}
