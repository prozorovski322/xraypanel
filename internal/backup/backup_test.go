package backup

import (
	"strings"
	"testing"
	"time"
)

var base = time.Date(2026, 9, 28, 3, 0, 0, 0, time.UTC)

func daily(n int) []Dump {
	dumps := make([]Dump, n)
	for i := range dumps {
		dumps[i] = Dump{Path: "d" + string(rune('a'+i)), TakenAt: base.Add(-time.Duration(i) * 24 * time.Hour)}
	}
	return dumps
}

func paths(dumps []Dump) string {
	var out []string
	for _, d := range dumps {
		out = append(out, d.Path)
	}
	return strings.Join(out, ",")
}

func TestExpiredByCount(t *testing.T) {
	got := Expired(daily(5), 3, 365*24*time.Hour, base)
	if paths(got) != "dd,de" {
		t.Errorf("expired %q, want the two beyond the newest three", paths(got))
	}
}

func TestExpiredByAge(t *testing.T) {
	got := Expired(daily(5), 100, 2*24*time.Hour+time.Hour, base)
	if paths(got) != "dd,de" {
		t.Errorf("expired %q, want the two older than 2d1h", paths(got))
	}
}

// The case that matters: backups have been failing for longer than the age limit. Age-only
// rotation would now delete the one good copy left.
func TestTheNewestDumpIsNeverExpired(t *testing.T) {
	stale := []Dump{{Path: "only", TakenAt: base.Add(-90 * 24 * time.Hour)}}
	if got := Expired(stale, 1, 24*time.Hour, base); len(got) != 0 {
		t.Fatalf("the only dump, 90 days old, was expired: %q", paths(got))
	}

	old := daily(3)
	for i := range old {
		old[i].TakenAt = old[i].TakenAt.Add(-60 * 24 * time.Hour)
	}
	if got := Expired(old, 10, 30*24*time.Hour, base); paths(got) != "db,dc" {
		t.Errorf("expired %q, want everything but the newest", paths(got))
	}
}

func TestNamesRoundTrip(t *testing.T) {
	name := filePrefix + base.Format(timeLayout) + fileSuffix
	if name != "panel-20260928T030000Z.dump" {
		t.Fatalf("name is %q", name)
	}
	got, ok := parseName(name)
	if !ok || !got.Equal(base) {
		t.Errorf("parseName(%q) = %v, %t", name, got, ok)
	}

	for _, other := range []string{
		name + partialSuffix, name + checksumSuffix, "panel-yesterday.dump", "notes.txt", "panel-.dump",
	} {
		if _, ok := parseName(other); ok {
			t.Errorf("%q was taken for a published dump", other)
		}
	}
}

func TestSchedule(t *testing.T) {
	day := 24 * time.Hour

	if got := NextDue(base.Add(-2*time.Hour), day, base); !got.Equal(base.Add(22 * time.Hour)) {
		t.Errorf("a dump two hours old: next due %v, want in 22h", got)
	}
	if got := NextDue(base.Add(-3*day), day, base); !got.Equal(base) {
		t.Errorf("an overdue backup: next due %v, want now", got)
	}

	if Healthy(nil, day, base) {
		t.Error("no dump at all counted as healthy")
	}
	if !Healthy(&Dump{TakenAt: base.Add(-47 * time.Hour)}, day, base) {
		t.Error("one missed run made the check fail")
	}
	if Healthy(&Dump{TakenAt: base.Add(-49 * time.Hour)}, day, base) {
		t.Error("two missed runs still counted as healthy")
	}
}

func TestThePasswordStaysOffTheCommandLine(t *testing.T) {
	target, env, err := connection("postgres://panel:s3cr%40t@db:5432/panel?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(target, "s3cr") {
		t.Errorf("the argument carries the password: %s", target)
	}
	if target != "postgres://panel@db:5432/panel?sslmode=disable" {
		t.Errorf("target = %q", target)
	}
	if len(env) != 1 || env[0] != "PGPASSWORD=s3cr@t" {
		t.Errorf("env = %q, want the decoded password in PGPASSWORD", env)
	}

	target, env, err = connection("postgres://panel@db/panel")
	if err != nil || len(env) != 0 || target != "postgres://panel@db/panel" {
		t.Errorf("no password: %q %q %v", target, env, err)
	}
}

func TestWithDatabase(t *testing.T) {
	got, err := withDatabase("postgres://panel:pw@db:5432/panel?sslmode=disable", "panel_restored")
	if err != nil {
		t.Fatal(err)
	}
	if got != "postgres://panel:pw@db:5432/panel_restored?sslmode=disable" {
		t.Errorf("got %q", got)
	}
}

func TestContentsCheck(t *testing.T) {
	good := strings.Join([]string{
		"; Archive created at 2026-09-28 03:00:00 UTC",
		"3401; 0 16390 TABLE DATA public goose_db_version panel",
		"3402; 0 16400 TABLE DATA public nodes panel",
		"3403; 0 16410 TABLE DATA public users panel",
	}, "\n")
	if err := checkContents([]byte(good)); err != nil {
		t.Errorf("a complete listing was refused: %v", err)
	}

	// A dump of some other database, or of an empty one, is well-formed and useless.
	err := checkContents([]byte("; Archive created at 2026-09-28\n3401; 0 1 TABLE DATA public orders app\n"))
	if err == nil || !strings.Contains(err.Error(), "users") {
		t.Errorf("a foreign dump passed: %v", err)
	}
}

func TestRestoreRefusesUnsafeNames(t *testing.T) {
	r := New(Config{Dir: t.TempDir()}, nil, nil)
	for _, name := range []string{"", "Panel", "panel; DROP DATABASE panel", "panel-restored", "1panel"} {
		err := r.Restore(t.Context(), "unused.dump", name)
		if err == nil || !strings.Contains(err.Error(), "plain database name") {
			t.Errorf("Restore accepted %q: %v", name, err)
		}
	}
}
