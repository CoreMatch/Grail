package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"Grail/internal/model"
)

func digestOf(b []byte) string {
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

func TestBlobPutGetAndDigestMismatch(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("grail test payload")
	d := digestOf(data)

	n, err := s.PutBlob(bytes.NewReader(data), d, 0)
	if err != nil {
		t.Fatal(err)
	}
	if n != int64(len(data)) {
		t.Fatalf("size = %d, want %d", n, len(data))
	}
	if !s.HasBlob(d) {
		t.Fatal("blob not stored")
	}

	rc, size, err := s.OpenBlob(d)
	if err != nil {
		t.Fatal(err)
	}
	var got bytes.Buffer
	if _, err := got.ReadFrom(rc); err != nil {
		t.Fatal(err)
	}
	rc.Close()
	if size != int64(len(data)) || !bytes.Equal(got.Bytes(), data) {
		t.Fatal("blob content mismatch")
	}

	// digest 不匹配必须拒绝（残缺/伪造字节不得落盘）。
	// 用一个尚未存在的期望 digest，但流式送入别的字节。
	declared := digestOf([]byte("declared-but-not-sent"))
	if _, err := s.PutBlob(bytes.NewReader([]byte("other")), declared, 0); err == nil {
		t.Fatal("digest mismatch accepted")
	}
	if s.HasBlob(declared) {
		t.Fatal("mismatched blob must not be stored")
	}
}

func TestBlobSizeCap(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	data := bytes.Repeat([]byte("x"), 1024)
	d := digestOf(data)
	if _, err := s.PutBlob(bytes.NewReader(data), d, 512); err == nil {
		t.Fatal("size cap not enforced")
	}
	if s.HasBlob(d) {
		t.Fatal("over-cap blob must not be stored")
	}
	if _, err := s.PutBlob(bytes.NewReader(data), d, 2048); err != nil {
		t.Fatalf("within cap rejected: %v", err)
	}
}

func putTestVersion(t *testing.T, s *Store, project, channel, version string, seq int64, df *model.DerivedFrom) {
	t.Helper()
	rec := &VersionRecord{
		Envelope: &model.Envelope{Payload: []byte("{}")},
		Manifest: &model.VersionManifest{
			Project: project, Channel: channel, Version: version, Seq: seq,
			Platforms:  []string{"linux-amd64"},
			Provenance: model.Provenance{DerivedFrom: df},
		},
	}
	if err := s.PutVersion(project, channel, version, rec); err != nil {
		t.Fatal(err)
	}
}

func TestVersionLifecycleAndReferences(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	putTestVersion(t, s, "avalon", "candidate", "0.6", 1, nil)
	putTestVersion(t, s, "avalon", "release", "0.6", 1,
		&model.DerivedFrom{Channel: "candidate", Version: "0.6"})

	// 血缘引用扫描：release 0.6 指向 candidate 0.6。
	refs, err := s.ReferencedBy(model.VersionRef{Project: "avalon", Channel: "candidate", Version: "0.6"})
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 1 || refs[0].Channel != "release" || refs[0].Version != "0.6" {
		t.Fatalf("ReferencedBy = %+v, want release/0.6", refs)
	}

	// 选择状态更新。
	if err := s.SetVersionState("avalon", "candidate", "0.6", model.VersionState{Yanked: true}); err != nil {
		t.Fatal(err)
	}
	rec, err := s.GetVersion("avalon", "candidate", "0.6")
	if err != nil {
		t.Fatal(err)
	}
	if !rec.State.Yanked || rec.State.Selectable() {
		t.Fatal("yanked state not applied / selectable wrong")
	}

	// 序号分配单调。
	seq1, err := s.NextSeq("avalon", "release")
	if err != nil {
		t.Fatal(err)
	}
	seq2, err := s.NextSeq("avalon", "release")
	if err != nil {
		t.Fatal(err)
	}
	if seq1 != 1 || seq2 != 2 { // 计数器独立于已存放版本的 seq，从 1 单调递增
		t.Fatalf("seq = %d,%d want 1,2", seq1, seq2)
	}

	// journal 追加与增量读取。
	if _, err := s.AppendJournal("publish", model.VersionRef{Project: "avalon", Channel: "release", Version: "0.6"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AppendJournal("remove", model.VersionRef{Project: "avalon", Channel: "ci", Version: "x"}); err != nil {
		t.Fatal(err)
	}
	entries, cursor, err := s.JournalSince(1)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Type != "remove" || cursor != "2" {
		t.Fatalf("JournalSince(1) = %+v cursor=%s", entries, cursor)
	}

	// 物理删除。
	if err := s.DeleteVersion("avalon", "candidate", "0.6"); err != nil {
		t.Fatal(err)
	}
	rec, err = s.GetVersion("avalon", "candidate", "0.6")
	if err != nil || rec != nil {
		t.Fatal("version still present after delete")
	}
}

func TestNodeRegistry(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	info := &model.NodeInfo{NodeID: "mirror-1", PublicKey: "pk", Channels: []string{"release"}, Created: "now"}
	if err := s.PutNode(info); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetNode("mirror-1")
	if err != nil || got == nil || got.PublicKey != "pk" {
		t.Fatalf("GetNode = %+v err=%v", got, err)
	}
	nodes, err := s.ListNodes()
	if err != nil || len(nodes) != 1 {
		t.Fatalf("ListNodes = %+v err=%v", nodes, err)
	}
	if err := s.DeleteNode("mirror-1"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteNode("mirror-1"); err == nil {
		t.Fatal("deleting unknown node must fail")
	}
}

func TestVersionAndDigestValidation(t *testing.T) {
	for _, ok := range []string{"0.6", "1.0.0", "0.6-rc.1", "v2", "a.b-c_d"} {
		if !VersionRe.MatchString(ok) {
			t.Errorf("version %q should be accepted", ok)
		}
	}
	for _, bad := range []string{"", "../x", "a/b", "a b", ".hidden", "-x"} {
		if VersionRe.MatchString(bad) {
			t.Errorf("version %q should be rejected", bad)
		}
	}
	if !DigestRe.MatchString("sha256:" + strings.Repeat("a", 64)) {
		t.Error("valid digest rejected")
	}
	if DigestRe.MatchString("sha256:zz") {
		t.Error("malformed digest accepted")
	}
}
