//go:build ((darwin && arm64) || (linux && amd64)) && cgo

package manifesthost

import (
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"enkv.sh/sdk/artifact"
	manifest "enkv.sh/sdk/manifest-generator"
)

type nativeFixture struct {
	path, pid, ready, measurement string
	metadata                      artifact.Metadata
	dependency                    []byte
}

func buildNativeFixture(t *testing.T, measured, blocked bool, profile string) nativeFixture {
	t.Helper()
	dir := t.TempDir()
	f := nativeFixture{path: filepath.Join(dir, "plugin"), pid: filepath.Join(dir, "pid"), ready: filepath.Join(dir, "ready"), measurement: filepath.Join(dir, "measurement")}
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	docs := filepath.Join(root, "enkv-extensions")
	const mainModule = "example.test/manifest-native-fixture"
	descriptor := fixtureDeclaration()
	descriptor.Manifest.FormatContractID = profile
	descriptorID, err := descriptor.Identity()
	if err != nil {
		t.Fatal(err)
	}
	modules := []string{"enkv.sh/sdk/manifest-generator", "enkv.sh/sdk/protocols/manifest-generator", "enkv.sh/sdk/artifact"}
	mod := "module " + mainModule + "\n\ngo 1.27.0\n\nrequire (\n"
	for _, path := range modules {
		mod += path + " v0.1.0\n"
	}
	mod += ")\n"
	for i, path := range modules {
		local := []string{"sdk/manifest-generator", "sdk/protocols/manifest-generator", "sdk/artifact"}[i]
		mod += "replace " + path + " => " + strconv.Quote(filepath.Join(docs, local)) + "\n"
	}
	source := fmt.Sprintf(nativeFixtureMain, strconv.Quote(f.pid), strconv.Quote(f.ready), strconv.Quote(f.measurement), measured, blocked, strconv.Quote(profile), fmt.Sprintf("%#v", manifest.ID(descriptorID)))
	for name, body := range map[string]string{"go.mod": mod, "main.go": source} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	build := exec.CommandContext(ctx, "go", "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-o", f.path, ".")
	build.Dir = dir
	for _, item := range os.Environ() {
		key, _, _ := strings.Cut(item, "=")
		if !strings.HasPrefix(key, "GO") && key != "CGO_ENABLED" && key != "PWD" {
			build.Env = append(build.Env, item)
		}
	}
	build.Env = append(build.Env, "PWD="+dir, "GOWORK=off", "GOTOOLCHAIN=local", "CGO_ENABLED=0", "GOPROXY=off", "GOSUMDB=off", "GONOSUMDB=*", "GOFLAGS=", "GOOS="+runtime.GOOS, "GOARCH="+runtime.GOARCH)
	if body, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build private native fixture: %v\n%s", err, body)
	}
	if err := os.Chmod(f.path, 0700); err != nil {
		t.Fatal("private native fixture executable permissions", err)
	}
	info, err := buildinfo.ReadFile(f.path)
	if err != nil {
		t.Fatal(err)
	}
	options, err := artifact.CaptureBuildOptions(info)
	if err != nil {
		t.Fatal(err)
	}
	// These explicit trusted fixture digests test host admission mechanics.
	// They do not qualify the public source-capture producer.
	sources := []artifact.Source{{Module: mainModule, Digest: sha256.Sum256([]byte(source))}}
	for _, path := range modules {
		sources = append(sources, artifact.Source{Module: path, Digest: sha256.Sum256([]byte("manifesthost trusted fixture owner: " + path))})
	}
	slices.SortFunc(sources, func(a, b artifact.Source) int { return strings.Compare(a.Module, b.Module) })
	compiled, err := artifact.CompiledDependencies(info, sources)
	// The source imports the SDK and protocol. The artifact owner is required by
	// the SDK's module graph but contributes no package to this fixture binary.
	compiledOwners := []string{mainModule, "enkv.sh/sdk/manifest-generator", "enkv.sh/sdk/protocols/manifest-generator"}
	slices.Sort(compiledOwners)
	if err != nil || len(compiled) != len(compiledOwners) {
		t.Fatalf("compiled fixture closure: %v rows=%d", err, len(compiled))
	}
	for i, row := range compiled {
		if row.Path != compiledOwners[i] {
			t.Fatal("unexpected compiled fixture owner", row.Path)
		}
	}
	resolved := make([]artifact.Dependency, len(compiled))
	for i, row := range compiled {
		resolved[i] = row
		if row.Path == mainModule {
			resolved[i].Version = ""
		}
		if row.Replacement != nil {
			replacement := *row.Replacement
			if replacement.Version == "(devel)" {
				replacement.Version = ""
			}
			resolved[i].Replacement = &replacement
		}
	}
	const artifactModule = "enkv.sh/sdk/artifact"
	resolved = append(resolved, artifact.Dependency{Path: artifactModule, Version: "v0.1.0", Replacement: &artifact.Replacement{Path: filepath.Join(docs, "sdk/artifact"), SourceDigest: sha256.Sum256([]byte("manifesthost trusted fixture owner: " + artifactModule))}})
	slices.SortFunc(resolved, func(a, b artifact.Dependency) int { return strings.Compare(a.Path, b.Path) })
	identity, err := artifact.ExecutableIdentity(ctx, f.path)
	if err != nil {
		t.Fatal(err)
	}
	f.metadata = artifact.Metadata{Schema: "enkv/plugin-artifact/v2", Purpose: "plugin-executable", MainModule: mainModule, Command: info.Path, Platform: runtime.GOOS + "/" + runtime.GOARCH, Toolchain: info.GoVersion, BuildOptions: options, Executable: identity, Sources: sources, Resolved: resolved, Compiled: compiled}
	f.metadata, f.dependency, err = bindFixture(f.metadata, descriptor)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func nativeProjection(name string) *manifest.Projection {
	return &manifest.Projection{Schema: manifest.Schema, FormatContractID: testFormat, ConfigContractID: testConfig, Settings: []byte(`{}`),
		Selection: manifest.Selection{TargetMode: manifest.ExactRecipient, EntryMode: manifest.ExactNames}, Observation: manifest.Observation{DomainID: manifest.ID{1}, HEADRevisionID: manifest.ID{2}, SnapshotID: manifest.ID{3}}, TargetRecipientID: manifest.ID{4},
		Entries: []manifest.Entry{{Name: name, EntryIncarnationID: manifest.ID{5}, Kind: manifest.Plain, PlainValue: []byte{0, 255}}}, ResolvedEntries: []manifest.EntryIdentity{{Name: name, EntryIncarnationID: manifest.ID{5}}}, ExcludedEntries: []manifest.ExcludedEntry{}}
}

func nativeStageDirectory(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)
	return dir
}

func assertNativeSettled(t *testing.T, f nativeFixture, stage string) {
	t.Helper()
	pidBody, err := os.ReadFile(f.pid)
	if err != nil {
		t.Fatal("child did not record its process identity", err)
	}
	pid, err := strconv.Atoi(string(pidBody))
	if err != nil || pid <= 0 {
		t.Fatal("invalid child process identity")
	}
	if err := syscall.Kill(pid, 0); err != syscall.ESRCH {
		t.Fatalf("child remains after Render: pid=%d err=%v", pid, err)
	}
	var status syscall.WaitStatus
	if _, err := syscall.Wait4(pid, &status, syscall.WNOHANG, nil); err != syscall.ECHILD {
		t.Fatalf("child was not positively reaped: %v", err)
	}
	entries, err := os.ReadDir(stage)
	if err != nil || len(entries) != 0 {
		t.Fatalf("native staging remains: entries=%d err=%v", len(entries), err)
	}
}

// full_only: false
func TestNativeManifestTransportAndProcessSettlement(t *testing.T) {
	f := buildNativeFixture(t, false, false, testFormat)
	stage := nativeStageDirectory(t)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	n, err := NewNative(ctx, f.path, f.metadata, f.dependency)
	if err != nil {
		t.Fatal(err)
	}
	f.metadata = artifact.Metadata{}
	for _, condition := range []string{"complete", "failure", "short-status", "extra-status", "unknown-status", "short-artifact", "extra-artifact", "wrong-correlation", "late-exit", "deadline", "cancelled"} {
		t.Run(condition, func(t *testing.T) {
			for _, path := range []string{f.pid, f.ready} {
				if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
					t.Fatal(err)
				}
			}
			p := nativeProjection(condition)
			callCtx, callCancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer callCancel()
			if condition == "deadline" {
				callCtx, callCancel = context.WithTimeout(t.Context(), 5*time.Second)
				defer callCancel()
			}
			var result manifest.Result
			if condition == "cancelled" {
				result = cancelNativeAfterReady(t, n, callCtx, callCancel, p, f.ready)
			} else {
				result = n.Render(callCtx, manifest.Borrow(p))
			}
			defer clear(result.Artifact[:cap(result.Artifact)])
			assertNativeSettled(t, f, stage)
			want := manifest.InvalidResult
			switch condition {
			case "complete":
				want = ""
				if _, failure := manifest.MeasureArtifact(t.Context(), result.Artifact); failure != "" || len(result.Artifact) != cap(result.Artifact) {
					t.Fatal("original projection verification failed", failure)
				}
			case "failure":
				want = manifest.InvalidInput
			case "deadline":
				want = manifest.Expired
			case "cancelled":
				want = manifest.Cancelled
			}
			if result.Failure != want || want != "" && result.Artifact != nil {
				t.Fatalf("result failure=%q artifact=%d want=%q", result.Failure, len(result.Artifact), want)
			}
		})
	}
}

func cancelNativeAfterReady(t *testing.T, n *Native, ctx context.Context, cancel context.CancelFunc, p *manifest.Projection, ready string) manifest.Result {
	t.Helper()
	done := make(chan manifest.Result, 1)
	go func() { done <- n.Render(ctx, manifest.Borrow(p)) }()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case result := <-done:
			t.Fatal("child returned before cancellation", result.Failure)
		case <-ctx.Done():
			result := <-done
			t.Fatal("child did not reach cancellation gate", result.Failure)
		case <-ticker.C:
			if _, err := os.Stat(ready); err == nil {
				started := time.Now()
				cancel()
				result := <-done
				if time.Since(started) > 3*time.Second {
					t.Fatal("native users did not join promptly after cancellation")
				}
				return result
			} else if !errors.Is(err, os.ErrNotExist) {
				cancel()
				result := <-done
				t.Fatal(err, result.Failure)
			}
		}
	}
}

// full_only: false
func TestNativeManifestCancellationJoinsBlockedRequestWriter(t *testing.T) {
	f := buildNativeFixture(t, false, true, testFormat)
	stage := nativeStageDirectory(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	n, err := NewNative(ctx, f.path, f.metadata, f.dependency)
	if err != nil {
		t.Fatal(err)
	}
	f.metadata = artifact.Metadata{}
	p := nativeProjection("unused")
	p.Entries = make([]manifest.Entry, 128)
	p.ResolvedEntries = make([]manifest.EntryIdentity, 128)
	before := sha256.New()
	for i := range p.Entries {
		name := fmt.Sprintf("%03d", i)
		value := make([]byte, 65536)
		for j := range value {
			value[j] = byte(i + 1)
		}
		p.Entries[i] = manifest.Entry{Name: name, EntryIncarnationID: manifest.ID{5, byte(i)}, Kind: manifest.Plain, PlainValue: value}
		p.ResolvedEntries[i] = manifest.EntryIdentity{Name: name, EntryIncarnationID: manifest.ID{5, byte(i)}}
		_, _ = before.Write(value)
	}
	defer func() {
		for i := range p.Entries {
			clear(p.Entries[i].PlainValue)
		}
	}()
	if failure := manifest.Validate(t.Context(), p); failure != "" {
		t.Fatal(failure)
	}
	result := cancelNativeAfterReady(t, n, ctx, cancel, p, f.ready)
	if result.Failure != manifest.Cancelled || result.Artifact != nil {
		t.Fatal("blocked request cancellation transferred a result", result.Failure)
	}
	assertNativeSettled(t, f, stage)
	after := sha256.New()
	for _, e := range p.Entries {
		_, _ = after.Write(e.PlainValue)
	}
	if !slices.Equal(before.Sum(nil), after.Sum(nil)) {
		t.Fatal("borrowed plain backing changed before request-writer settlement")
	}
}

// full_only: false
func TestNativeManifestRuntimeRejectsChangedAdmittedExecutable(t *testing.T) {
	f := buildNativeFixture(t, false, false, testFormat)
	stage := nativeStageDirectory(t)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	n, err := NewNative(ctx, f.path, f.metadata, f.dependency)
	if err != nil {
		t.Fatal(err)
	}
	if n.path != f.path || n.identity != f.metadata.Executable {
		t.Fatal("retained executable identity differs")
	}
	file, err := os.OpenFile(f.path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := file.WriteAt([]byte{0}, 0)
	if err := errors.Join(writeErr, file.Close()); err != nil {
		t.Fatal(err)
	}
	r := n.Render(ctx, manifest.Borrow(nativeProjection("complete")))
	if r.Artifact != nil || r.Failure != manifest.InvalidResult {
		t.Fatal("changed executable accepted", r.Failure)
	}
	if _, err := os.Stat(f.pid); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("changed executable started")
	}
	entries, err := os.ReadDir(stage)
	if err != nil || len(entries) != 0 {
		t.Fatal("refused executable left staging", err)
	}
}

const nativeFixtureMain = `package main
import (
 "bytes"
 "context"
 "encoding/binary"
 "encoding/json"
 "os"
 "runtime"
 "strconv"
 "syscall"
 "time"
 "unsafe"
 manifest "enkv.sh/sdk/manifest-generator"
 protocol "enkv.sh/sdk/protocols/manifest-generator"
)
const pidPath = %s
const readyPath = %s
const measurementPath = %s
const measured = %t
const blocked = %t
const format = %s
var descriptor = %s
func write(path string, body []byte) { if os.WriteFile(path, body, 0600) != nil { os.Exit(81) } }
func emit(correlation manifest.ID,code byte,length uint64,body []byte,condition string) {
 status:=append([]byte("ENKV/MANIFEST/v2\x00"),correlation[:]...);status=append(status,code);status=binary.BigEndian.AppendUint64(status,length)
 if condition=="short-status"{status=status[:len(status)-1]}
 if condition=="extra-status"{status=append(status,0)}
 if condition=="unknown-status"{status[49]=7}
 if condition=="wrong-correlation"{status[17]++}
 s,a:=os.NewFile(5,"status"),os.NewFile(4,"artifact")
 if _,err:=s.Write(status);err!=nil{os.Exit(82)};if s.Close()!=nil{os.Exit(83)}
 if condition=="short-artifact"{body=body[:len(body)-1]}
 if _,err:=a.Write(body);err!=nil{os.Exit(84)}
 if condition=="extra-artifact"{if _,err:=a.Write([]byte{0});err!=nil{os.Exit(85)}}
 if a.Close()!=nil{os.Exit(86)}
}
func main(){
 write(pidPath,[]byte(strconv.Itoa(os.Getpid())))
 if len(os.Args)!=2 || os.Args[1]!=protocol.Mode || len(os.Environ())!=0{os.Exit(88)}
 var null syscall.Stat_t;if syscall.Stat("/dev/null",&null)!=nil{os.Exit(89)}
 for fd:=0;fd<6;fd++{
  var st syscall.Stat_t;if syscall.Fstat(fd,&st)!=nil{os.Exit(90)}
  if fd<3{if st.Mode&syscall.S_IFMT!=syscall.S_IFCHR || st.Rdev!=null.Rdev{os.Exit(91)};continue}
  want:=syscall.O_WRONLY;if fd==3{want=syscall.O_RDONLY}
  flags,_,err:=syscall.Syscall(syscall.SYS_FCNTL,uintptr(fd),syscall.F_GETFL,0)
  if err!=0 || st.Mode&syscall.S_IFMT!=syscall.S_IFIFO || int(flags)&syscall.O_ACCMODE!=want{os.Exit(92)}
 }
 directory,err:=os.Open("/dev/fd");if err!=nil{os.Exit(93)}
 names,err:=directory.Readdirnames(-1);if err!=nil || directory.Close()!=nil{os.Exit(94)}
 for _,name:=range names{fd,e:=strconv.Atoi(name);if e!=nil || fd<6{continue};flags,_,errno:=syscall.Syscall(syscall.SYS_FCNTL,uintptr(fd),syscall.F_GETFD,0);if errno==0 && flags&syscall.FD_CLOEXEC==0{os.Exit(95)}}
 if blocked{
  ioctl:=uintptr(0x541b);if runtime.GOOS=="darwin"{ioctl=0x4004667f};limit:=time.Now().Add(10*time.Second)
  for{var pending int32;_,_,errno:=syscall.Syscall(syscall.SYS_IOCTL,3,ioctl,uintptr(unsafe.Pointer(&pending)));if errno!=0{os.Exit(80)};if pending>0{break};if time.Now().After(limit){os.Exit(80)};time.Sleep(time.Millisecond)}
  write(readyPath,[]byte("ready"));time.Sleep(time.Minute);os.Exit(87)
 }
 request:=os.NewFile(3,"request");input,f,err:=protocol.ReadRequest(context.Background(),request)
 if err!=nil || f!="" || input.DescriptorID!=descriptor{os.Exit(96)}
 defer protocol.Dispose(&input)
 if request.Close()!=nil{os.Exit(100)}
 if input.Operation==protocol.OperationValidateSettings{
  digest,err:=protocol.SettingsRequestDigest(context.Background(),input);if err!=nil{os.Exit(96)}
  var buffer bytes.Buffer
  if string(input.Settings.Settings)=="{\"fault\":\"digest\"}"{digest[0]++}
  if protocol.WriteSettingsResponse(context.Background(),&buffer,protocol.SettingsResponse{RequestDigest:digest,Settings:[]byte("{\"normalized\":true}")})!=nil{os.Exit(96)}
  if string(input.Settings.Settings)=="{\"fault\":\"trailing\"}"{buffer.WriteByte(0)}
  emit(input.Correlation,0,uint64(buffer.Len()),buffer.Bytes(),"");return
 }
 p:=input.Projection;if p==nil || p.FormatContractID!=format{os.Exit(96)}
 condition:="";if len(p.Entries)>0{condition=p.Entries[0].Name}
 if condition=="failure"{emit(input.Correlation,1,0,nil,"");return}
 if condition=="cancelled" || condition=="deadline"{write(readyPath,[]byte("ready"));time.Sleep(time.Minute);os.Exit(87)}
 result:=[]byte("private:"+format+":"+condition)
 if measured{result=bytes.Repeat([]byte{0xa7},int(manifest.MaxArtifactBytes))}
 counts:=map[string]uint64{}
 if measured{
  counts["entry_size"]=uint64(unsafe.Sizeof(manifest.Entry{}));counts["destination_size"]=uint64(unsafe.Sizeof(manifest.Destination{}));counts["projection_size"]=uint64(unsafe.Sizeof(manifest.Projection{}))
  counts["entry_capacity"]=uint64(cap(p.Entries));counts["resolved_capacity"]=uint64(cap(p.ResolvedEntries));counts["artifact_capacity"]=uint64(cap(result))
  backing:=uint64(unsafe.Sizeof(*p))+uint64(cap(p.Entries))*104+uint64(cap(p.ResolvedEntries))*48+uint64(cap(p.ExcludedEntries))*64
  backing+=uint64(len(p.Schema)+len(p.FormatContractID)+len(p.ConfigContractID)+cap(p.Settings));if p.ServiceFilter!=nil{backing+=16+uint64(len(*p.ServiceFilter))}
  for _,e:=range p.Entries{counts["raw_capacity"]+=uint64(cap(e.PlainValue));counts["destination_capacity"]+=uint64(cap(e.Destinations));backing+=uint64(len(e.Name)+cap(e.PlainValue))+uint64(cap(e.Destinations))*248
   for _,d:=range e.Destinations{if uint64(cap(d.PolicyData))>counts["max_policy_capacity"]{counts["max_policy_capacity"]=uint64(cap(d.PolicyData))};backing+=uint64(len(d.DestinationID)+len(d.ServiceContractID)+len(d.ConsumerLocator)+len(d.TargetContractID)+len(d.CanonicalTarget)+cap(d.TargetData)+len(d.PolicyContractID)+cap(d.PolicyData))}
  }
  counts["projection_backing"]=backing
 }
 emit(input.Correlation,0,uint64(len(result)),result,condition)
 runtime.KeepAlive(p);clear(result)
 var plain []byte;if measured{plain=p.Entries[1].PlainValue}
 late:=condition=="late-exit" || measured && p.TargetRecipientID==(manifest.ID{9})
 protocol.Dispose(&input)
 if measured{
  for _,b:=range plain{if b!=0{os.Exit(99)}}
  for _,b:=range result{if b!=0{os.Exit(99)}}
  if len(p.Entries)!=0 || len(p.ResolvedEntries)!=0{os.Exit(99)}
  counts["disposed"]=1;report,err:=json.Marshal(counts);if err!=nil{os.Exit(99)};write(measurementPath,report)
 }
 if late{os.Exit(7)}
}
`

// full_only: false
func TestNativeManifestSelectedDeclarationAndPreStagingBinding(t *testing.T) {
	for _, profile := range []string{testFormat, "private-format/v2"} {
		t.Run(profile, func(t *testing.T) {
			f := buildNativeFixture(t, false, false, profile)
			stage := nativeStageDirectory(t)
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			n, err := NewNative(ctx, f.path, f.metadata, f.dependency)
			if err != nil {
				t.Fatal(err)
			}
			f.metadata = artifact.Metadata{}
			if n.format != profile {
				t.Fatal("admission did not retain declared format")
			}
			p := nativeProjection("complete")
			p.FormatContractID = profile
			result := n.Render(ctx, manifest.Borrow(p))
			defer clear(result.Artifact[:cap(result.Artifact)])
			metadata, failure := manifest.MeasureArtifact(ctx, result.Artifact)
			if result.Failure != "" || failure != "" || metadata.Length != uint64(len(result.Artifact)) || len(result.Artifact) != cap(result.Artifact) {
				t.Fatal("selected actual native renderer failed", result.Failure, failure)
			}
			if string(result.Artifact) != "private:"+profile+":complete" {
				t.Fatal("selected private format differs")
			}
			assertNativeSettled(t, f, stage)
			if err := os.Remove(f.path); err != nil {
				t.Fatal(err)
			}
			if profile == testFormat {
				p.FormatContractID = "private-format/v2"
			} else {
				p.FormatContractID = testFormat
			}
			if failure := manifest.Validate(ctx, p); failure != "" {
				t.Fatal("mismatched view is generically invalid", failure)
			}
			refused, err := n.render(ctx, manifest.Borrow(p))
			if err != ErrAdmission || refused.Artifact != nil {
				t.Fatal("format mismatch reached executable staging", err)
			}
			entries, err := os.ReadDir(stage)
			if err != nil || len(entries) != 0 {
				t.Fatal("mismatch left staging", err)
			}
		})
	}
}

// full_only: false
func TestNativeManifestSettingsBindExactRequestAndCanonicalBytes(t *testing.T) {
	f := buildNativeFixture(t, false, false, testFormat)
	stage := nativeStageDirectory(t)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	n, err := NewNative(ctx, f.path, f.metadata, f.dependency)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, settings string
		canonical      bool
		want           manifest.Failure
	}{
		{"defaults", `{}`, false, ""}, {"canonical", `{"normalized":true}`, true, ""}, {"changed-canonical", `{}`, true, manifest.InvalidResult},
		{"wrong-digest", `{"fault":"digest"}`, false, manifest.InvalidResult}, {"trailing-response", `{"fault":"trailing"}`, false, manifest.InvalidResult},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := n.ValidateSettings(ctx, manifest.SettingsRequest{FormatContractID: testFormat, ConfigContractID: testConfig, Canonical: tc.canonical, Settings: []byte(tc.settings)})
			defer clear(result.Settings[:cap(result.Settings)])
			if result.Failure != tc.want || tc.want != "" && result.Settings != nil {
				t.Fatal("settings boundary differs", result.Failure, tc.want)
			}
			if tc.want == "" && (string(result.Settings) != `{"normalized":true}` || len(result.Settings) != cap(result.Settings)) {
				t.Fatal("canonical settings were not transferred exactly")
			}
			assertNativeSettled(t, f, stage)
		})
	}
}
