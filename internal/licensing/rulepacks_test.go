package licensing

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// newTestClient points a client at a stub server and isolates its cache in a
// temp dir, so tests never touch the developer's real cache.
func newTestClient(t *testing.T, handler http.HandlerFunc) (*Client, string) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	cacheRoot := t.TempDir()
	t.Setenv("TFPDF_CACHE_DIR", cacheRoot)

	return NewClient("test-key", srv.URL), filepath.Join(cacheRoot, "rulepacks")
}

func TestFetchRulePack_DownloadsAndCaches(t *testing.T) {
	var calls int
	c, cacheDir := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if got := r.Header.Get("Authorization"); got != "Bearer test-key" {
			t.Errorf("Authorization = %q", got)
		}
		w.Header().Set("ETag", `"v1"`)
		w.Write([]byte("PACKBODY"))
	})

	pack, err := c.FetchRulePack("aws")
	if err != nil {
		t.Fatalf("FetchRulePack: %v", err)
	}
	if string(pack.Data) != "PACKBODY" || pack.ETag != `"v1"` {
		t.Fatalf("unexpected pack %+v", pack)
	}
	if pack.FromCache {
		t.Error("first fetch should not be reported as cached")
	}

	body, err := os.ReadFile(filepath.Join(cacheDir, "aws.pack.gz"))
	if err != nil || string(body) != "PACKBODY" {
		t.Fatalf("pack not cached: %v %q", err, body)
	}

	// A second call inside the TTL must not hit the network at all.
	again, err := c.FetchRulePack("aws")
	if err != nil {
		t.Fatalf("second FetchRulePack: %v", err)
	}
	if !again.FromCache {
		t.Error("second fetch should come from cache")
	}
	if calls != 1 {
		t.Errorf("server called %d times, want 1", calls)
	}
}

func TestFetchRulePack_RevalidatesWithETagAfterTTL(t *testing.T) {
	var gotIfNoneMatch string
	c, cacheDir := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotIfNoneMatch = r.Header.Get("If-None-Match")
		w.WriteHeader(http.StatusNotModified)
	})

	seedCache(t, cacheDir, "aws", "CACHEDBODY", `"v1"`, time.Now().Add(-2*PackCacheTTL))

	pack, err := c.FetchRulePack("aws")
	if err != nil {
		t.Fatalf("FetchRulePack: %v", err)
	}
	if gotIfNoneMatch != `"v1"` {
		t.Errorf("If-None-Match = %q, want the cached ETag", gotIfNoneMatch)
	}
	if string(pack.Data) != "CACHEDBODY" || !pack.FromCache {
		t.Errorf("a 304 should reuse the cached body, got %+v", pack)
	}

	// The 304 refreshed the cache timestamp, so the next call skips the network.
	if !cacheFresh(cacheDir, "aws") {
		t.Error("cache should have been marked fresh after revalidation")
	}
}

// The core promise of this path: an outage costs coverage, never a red check.
func TestFetchRulePack_FallsBackToCacheWhenServiceIsDown(t *testing.T) {
	c, cacheDir := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})

	seedCache(t, cacheDir, "aws", "CACHEDBODY", `"v1"`, time.Now().Add(-2*PackCacheTTL))

	pack, err := c.FetchRulePack("aws")
	if pack == nil {
		t.Fatal("expected the cached pack to be used despite the outage")
	}
	if string(pack.Data) != "CACHEDBODY" || !pack.FromCache {
		t.Errorf("unexpected pack %+v", pack)
	}
	if err == nil {
		t.Error("the fallback should still be reported, so the scan can warn about it")
	}
}

func TestFetchRulePack_NoCacheAndServiceDownReturnsError(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})

	pack, err := c.FetchRulePack("aws")
	if pack != nil {
		t.Fatalf("expected no pack, got %+v", pack)
	}
	if err == nil {
		t.Fatal("expected an error the caller can turn into a warning")
	}
}

func TestFetchRulePack_UnauthorizedIsReportedClearly(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})

	_, err := c.FetchRulePack("aws")
	if err == nil {
		t.Fatal("expected an error for a refused pack")
	}
	if !contains(err.Error(), "plan") {
		t.Errorf("error should point at the plan, got %q", err)
	}
}

func TestFetchRulePack_EmptyBodyIsRejected(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	pack, err := c.FetchRulePack("aws")
	if pack != nil || err == nil {
		t.Fatalf("an empty body must not be cached as a valid pack (pack=%v err=%v)", pack, err)
	}
}

// A pack body with no ETag header still gets a stable identity, so the next
// scan can revalidate instead of re-downloading forever.
func TestFetchRulePack_SynthesisesETagWhenAbsent(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("PACKBODY"))
	})

	pack, err := c.FetchRulePack("aws")
	if err != nil {
		t.Fatalf("FetchRulePack: %v", err)
	}
	if pack.ETag == "" {
		t.Error("expected a synthesised ETag")
	}
}

// The provider name reaches this code from configuration, so it must not be
// able to choose where we write.
func TestPackFileName_RejectsPathTraversal(t *testing.T) {
	for _, in := range []string{"../../etc/passwd", "aws/../..", "", "AWS"} {
		got := packFileName(in, ".pack.gz")
		if filepath.Base(got) != got {
			t.Errorf("packFileName(%q) = %q escapes its directory", in, got)
		}
	}
}

func seedCache(t *testing.T, dir, provider, body, etag string, modTime time.Time) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	packPath := filepath.Join(dir, packFileName(provider, ".pack.gz"))
	if err := os.WriteFile(packPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, packFileName(provider, ".etag")), []byte(etag), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(packPath, modTime, modTime); err != nil {
		t.Fatal(err)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle ||
		len(needle) == 0 ||
		indexOf(haystack, needle) >= 0)
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
