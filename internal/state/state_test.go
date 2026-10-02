package state

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestLoadMissing(t *testing.T) {
	st, err := Load(t.TempDir())
	if err != nil || st != nil {
		t.Fatalf("пустой каталог: st=%v err=%v", st, err)
	}
}

func TestSaveLoadRoundtrip(t *testing.T) {
	dir := t.TempDir()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	in := &State{
		PanelURL:   "https://panel.example",
		ServerID:   "0192c000-0000-7000-8000-000000000001",
		ServerName: "de-fra-01",
		WsURL:      "wss://panel.example/api/agent/v1/ws",
		PrivKeyB64: base64.StdEncoding.EncodeToString(seed),
	}
	if err := Save(dir, in); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("права %v вместо 0600", info.Mode().Perm())
	}

	out, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(*out, *in) {
		t.Fatalf("roundtrip: %+v != %+v", out, in)
	}
	key, err := out.Key()
	if err != nil {
		t.Fatal(err)
	}
	if !key.Equal(ed25519.NewKeyFromSeed(seed)) {
		t.Fatal("ключ не восстановился из seed")
	}
}

func TestLoadIncomplete(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte(`{"panelUrl":"x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("ожидалась ошибка про неполное состояние")
	}
}

func TestSaveLoadPullOnly(t *testing.T) {
	dir := t.TempDir()
	in := &State{Pull: &PullState{
		Port:       23456,
		AccessKey:  "nsa_key-that-is-longer-than-thirty-two-bytes",
		ServerID:   "0192c000-0000-7000-8000-000000000001",
		ServerName: "kz-1",
	}}
	if err := Save(dir, in); err != nil {
		t.Fatal(err)
	}
	out, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(out, in) {
		t.Fatalf("roundtrip: %+v != %+v", out, in)
	}
}

func TestLoadMigratesSingleWsURL(t *testing.T) {
	dir := t.TempDir()
	seed := base64.StdEncoding.EncodeToString(make([]byte, ed25519.SeedSize))
	raw := []byte(`{"serverId":"s1","wsUrl":"wss://old.test/api/agent/v1/ws","privateKey":"` + seed + `"}`)
	if err := os.WriteFile(filepath.Join(dir, "state.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Endpoints(); len(got) != 1 || got[0] != st.WsURL {
		t.Fatalf("старый wsUrl не перенесён в список: %v", got)
	}
}
