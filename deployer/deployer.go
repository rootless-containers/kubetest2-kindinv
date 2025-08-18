/*
Copyright The kubetest2-kindinv Authors.
Copyright 2021 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package deployer implements the kubetest2 kind deployer
package deployer

import (
	"bytes"
	"context"
	_ "embed" // for provisionShContent
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/octago/sflags/gen/gpflag"
	"github.com/rootless-containers/kubetest2-kindinv/version"
	"github.com/spf13/pflag"
	"k8s.io/klog/v2"
	"sigs.k8s.io/boskos/client"
	"sigs.k8s.io/kubetest2/pkg/artifacts"
	"sigs.k8s.io/kubetest2/pkg/boskos"
	ktexec "sigs.k8s.io/kubetest2/pkg/exec"
	"sigs.k8s.io/kubetest2/pkg/fs"
	"sigs.k8s.io/kubetest2/pkg/types"
)

//go:embed kubetest2-kindinv-provision.sh
var provisionShContent []byte

// Name is the name of the deployer
const Name = "kindinv"

// local commands
// TODO: support injecting additional options via env
const (
	gcloud = "gcloud"
	ssh    = "ssh"
	rsync  = "rsync"
	git    = "git"
)

// the name of the files in runDir
const (
	runDirSSHKeys      = "gce-ssh-keys"
	runDirProvisionSh  = "kubetest2-kindinv-provision.sh"
	runDirKindImageTar = "kind-image.tar"
	runDirKubeconfig   = "kubeconfig"
)

// the name of the files in artifactsDir
const (
	artifactsDirLogs = "logs"
)

// Boskos
const (
	// gceProjectResourceType is called "gce" project in Boskos,
	// while it is called "gcp" project in this CLI.
	gceProjectResourceType = "gce-project"
)

// gopath returns GOPATH or an empty string.
func gopath() string {
	if goBinary, err := exec.LookPath("go"); err == nil {
		cmd := exec.Command(goBinary, "env", "GOPATH")
		if b, err := cmd.Output(); err == nil {
			return strings.TrimSpace(string(b))
		}
	}
	return os.Getenv("GOPATH")
}

// New implements deployer.New for kind
func New(opts types.Options) (types.Deployer, *pflag.FlagSet) {
	kubeRoot := "."
	if s := gopath(); s != "" {
		kubeRoot = filepath.Join(s, "src", "k8s.io", "kubernetes")
	}
	username := os.Getenv("USER")
	switch username {
	case "", "root":
		username = "user"
	}
	localUser := os.Getenv("USER")
	if localUser == "" {
		localUser = "unknown"
	}

	d := &deployer{
		commonOptions:                  opts,
		KubeRoot:                       kubeRoot,
		GCPProject:                     os.Getenv("CLOUDSDK_CORE_PROJECT"),
		GCPZone:                        os.Getenv("CLOUDSDK_COMPUTE_ZONE"),
		InstanceImage:                  "ubuntu-os-cloud/ubuntu-2404-lts-amd64",
		InstanceType:                   "n2-standard-4",
		DiskGiB:                        200,
		User:                           username,
		localUser:                      localUser,
		KindRootless:                   false,
		BoskosAcquireTimeoutSeconds:    5 * 60,
		BoskosHeartbeatIntervalSeconds: 5 * 60,
		BoskosLocation:                 "http://boskos.test-pods.svc.cluster.local.",
		boskos:                         nil,
		boskosHeartbeatClose:           make(chan struct{}),
	}
	// assertions
	var (
		_ types.DeployerWithKubeconfig = d
		_ types.DeployerWithVersion    = d
	)
	return d, bindFlags(d)
}

type deployer struct {
	commonOptions types.Options

	KubeRoot string `desc:"${GOPATH}/src/k8s.io/kubernetes"`

	GCPProject    string `desc:"GCP project, defaults to $CLOUDSDK_CORE_PROJECT"`
	GCPZone       string `desc:"GCP zone, defaults to $CLOUDSDK_COMPUTE_ZONE"`
	InstanceImage string `desc:"Instance image"`
	InstanceType  string `desc:"Instance type"`
	DiskGiB       int    `flag:"~disk-gib" desc:"Disk size in GiB"`
	User          string `desc:"remote username"`
	localUser     string

	KindRootless bool `desc:"Run kind in rootless mode"`

	isUp bool

	// Boskos flags correspond to https://github.com/kubernetes-sigs/kubetest2/blob/71238a9645df6fbd7eaac9a36f635c22f1566168/kubetest2-gce/deployer/deployer.go
	BoskosAcquireTimeoutSeconds    int    `desc:"How long (in seconds) to hang on a request to Boskos to acquire a resource before erroring."`
	BoskosHeartbeatIntervalSeconds int    `desc:"How often (in seconds) to send a heartbeat to Boskos to hold the acquired resource. 0 means no heartbeat."`
	BoskosLocation                 string `desc:"If set, manually specifies the location of the boskos server. If unset and boskos is needed, defaults to http://boskos.test-pods.svc.cluster.local."`
	// boskos struct field will be non-nil when the deployer is
	// using boskos to acquire a GCP project
	boskos *client.Client
	// this channel serves as a signal channel for the hearbeat goroutine
	// so that it can be explicitly closed
	boskosHeartbeatClose chan struct{}
}

func (d *deployer) shortRunID() string {
	id := d.commonOptions.RunID()
	if len(id) > 8 {
		id = id[:8]
	}
	return id
}

func (d *deployer) kindImageRef() string {
	return "kindest/node:runid-" + d.shortRunID()
}

func (d *deployer) instanceName() string {
	return fmt.Sprintf("kt2-%s-%s-%s", Name, d.localUser, d.shortRunID())
}

func (d *deployer) networkName() string {
	return d.instanceName()
}

func (d *deployer) firewallRuleName() string {
	return d.instanceName()
}

func (d *deployer) gcpProject() (string, error) {
	if d.GCPProject != "" {
		return d.GCPProject, nil
	}
	klog.Info("No GCP project provided, acquiring from Boskos")

	boskosClient, err := boskos.NewClient(d.BoskosLocation)
	if err != nil {
		return "", fmt.Errorf("failed to make boskos client: %w", err)
	}
	d.boskos = boskosClient

	resource, err := boskos.Acquire(
		d.boskos,
		gceProjectResourceType,
		time.Duration(d.BoskosAcquireTimeoutSeconds)*time.Second,
		time.Duration(d.BoskosHeartbeatIntervalSeconds)*time.Second,
		d.boskosHeartbeatClose,
	)

	if err != nil {
		return "", fmt.Errorf("init failed to get project from boskos: %w", err)
	}
	if resource.Name == "" {
		return "", errors.New("boskos returned an empty resource name")
	}
	d.GCPProject = resource.Name
	klog.Infof("Got project %q from boskos", d.GCPProject)

	return d.GCPProject, nil
}

func (d *deployer) sshAddr() (string, error) {
	gcpProject, err := d.gcpProject()
	if err != nil {
		return "", fmt.Errorf("failed to get GCP project: %w", err)
	}
	if d.GCPZone == "" {
		return "", errors.New("gcp-zone is unset")
	}
	return fmt.Sprintf("%s.%s.%s", d.instanceName(), d.GCPZone, gcpProject), nil
}

func (d *deployer) gcloud(ctx context.Context, args ...string) (*exec.Cmd, error) {
	gcpProject, err := d.gcpProject()
	if err != nil {
		return nil, fmt.Errorf("failed to get GCP project: %w", err)
	}
	cmd := exec.CommandContext(ctx, gcloud, append([]string{"--project=" + gcpProject}, args...)...)
	return cmd, nil
}

func (d *deployer) sshOptionPairs() []string {
	return []string{"StrictHostKeyChecking=no", "User=" + d.User}
}

func (d *deployer) ssh(ctx context.Context, args ...string) *exec.Cmd {
	var a []string
	for _, o := range d.sshOptionPairs() {
		a = append(a, "-o", o)
	}
	return exec.CommandContext(ctx, ssh, append(a, args...)...)
}

func (d *deployer) rsync(ctx context.Context, args ...string) *exec.Cmd {
	e := ssh
	for _, o := range d.sshOptionPairs() {
		e += " -o " + o
	}
	return exec.CommandContext(ctx, rsync, append([]string{"-e", e}, args...)...)
}

func (d *deployer) git(ctx context.Context, args ...string) *exec.Cmd {
	e := ssh
	for _, o := range d.sshOptionPairs() {
		e += " -o " + o
	}
	cmd := exec.CommandContext(ctx, git, args...)
	cmd.Env = append(os.Environ(), "GIT_SSH_COMMAND="+e)
	return cmd
}

func (d *deployer) gitDescribeWithRepoDir(ctx context.Context, repoDir string) (string, error) {
	cmd := d.git(ctx, "describe")
	cmd.Dir = repoDir
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	b, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to run %s: %w (stdout=%q, stderr=%q)",
			stringifyCmdArgs(cmd.Args), err, string(b), stderr.String())
	}
	return strings.TrimSpace(string(b)), nil
}

func stringifyCmdArgs(ss []string) string {
	s := "["
	for i, f := range ss {
		s += fmt.Sprintf("%q", f)
		if i < len(ss)-1 {
			s += " "
		}
	}
	s += "]"
	return s
}

func execCmd(cmd *exec.Cmd) error {
	s := stringifyCmdArgs(cmd.Args)
	if cmd.Dir != "" {
		s += fmt.Sprintf(" [In %q]", cmd.Dir)
	}
	klog.V(0).Infof("Executing: %s", s)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to run %s: %w", s, err)
	}
	return nil
}

func execCmdWithRetry(cmdFn func() *exec.Cmd, retry int) error {
	var err error
	for i := 0; i < retry; i++ {
		// cmdFn is called every time, as cmd cannot be reused after its failure
		if err = execCmd(cmdFn()); err == nil {
			return nil
		}
		time.Sleep(10 * time.Second)
	}
	return fmt.Errorf("%w (retried %d times)", err, retry)
}

func (d *deployer) remoteHome(ctx context.Context) (string, error) {
	sshAddr, err := d.sshAddr()
	if err != nil {
		return "", err
	}
	cmd := d.ssh(ctx, sshAddr, "--", "echo", "$HOME")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	b, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to run %s: %w (stdout=%q, stderr=%q)",
			stringifyCmdArgs(cmd.Args), err, string(b), stderr.String())
	}
	return strings.TrimSpace(string(b)), nil
}

func (d *deployer) kubeAPIServerPort(ctx context.Context) (int, error) {
	sshAddr, err := d.sshAddr()
	if err != nil {
		return 0, err
	}
	const kindControlPlaneContainerName = "kind-control-plane" // FIXME: avoid hard coding
	cmd := d.ssh(ctx, sshAddr, "--", "docker", "container", "port", kindControlPlaneContainerName)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	b, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("failed to run %s: %w (stdout=%q, stderr=%q)",
			stringifyCmdArgs(cmd.Args), err, string(b), stderr.String())
	}
	s := strings.TrimSpace(string(b)) // like "127.0.0.1:45825"
	_, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return 0, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0, fmt.Errorf("failed to atoi %q (split from %q): %w", portStr, s, err)
	}
	return port, nil
}

func (d *deployer) upVM(ctx context.Context) error {
	if d.GCPZone == "" {
		return errors.New("gcp-zone is unset")
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	gcePubPath := filepath.Join(home, ".ssh/google_compute_engine.pub")
	gcePubContent, err := os.ReadFile(gcePubPath)
	if err != nil {
		return err
	}
	sshKeysContent := []byte(d.User + ":" + string(gcePubContent))
	runDir := d.commonOptions.RunDir()
	sshKeysPath := filepath.Join(runDir, runDirSSHKeys)
	_ = os.RemoveAll(sshKeysPath)
	if err = os.WriteFile(sshKeysPath, sshKeysContent, 0400); err != nil {
		return err
	}

	nwName, fwRuleName, instName := d.networkName(), d.firewallRuleName(), d.instanceName()
	description := fmt.Sprintf("kubetest2-%s instance (login ID: %q)", Name, d.User)
	instImgPair := strings.SplitN(d.InstanceImage, "/", 2)

	gcloudCmds := [][]string{
		{"services", "enable", "compute.googleapis.com"}, // https://github.com/kubernetes-sigs/kubetest2/blob/71238a9645df6fbd7eaac9a36f635c22f1566168/kubetest2-gce/deployer/up.go#L156-L159
		{"compute", "networks", "create", nwName},
		{"compute", "firewall-rules", "create", fwRuleName, "--network=" + nwName, "--allow=tcp:22"},
		{"compute", "instances", "create",
			"--zone=" + d.GCPZone,
			"--description=" + description,
			"--labels=owner=" + d.localUser,
			"--network=" + nwName,
			"--image-project=" + instImgPair[0],
			"--image-family=" + instImgPair[1],
			"--machine-type=" + d.InstanceType,
			fmt.Sprintf("--boot-disk-size=%dGiB", d.DiskGiB),
			"--metadata=block-project-ssh-keys=TRUE",
			instName,
		},
		{"compute", "instances", "add-metadata", instName, "--zone=" + d.GCPZone, "--metadata-from-file=ssh-keys=" + sshKeysPath},
		{"compute", "config-ssh"},
	}
	for _, f := range gcloudCmds {
		cmd, err := d.gcloud(ctx, f...)
		if err != nil {
			return err
		}
		if err = execCmd(cmd); err != nil {
			klog.Error(err)
			// continue, to allow "already exists" errors
		}
	}

	// Check SSH connectivity
	sshAddr, err := d.sshAddr()
	if err != nil {
		return err
	}
	cmdFn := func() *exec.Cmd { return d.ssh(ctx, sshAddr, "--", "uname", "-a") }
	if err = execCmdWithRetry(cmdFn, 10); err != nil {
		return err
	}
	cmd := d.ssh(ctx, sshAddr, "--", "grep", "^PRETTY_NAME=", "/etc/os-release")
	if err = execCmd(cmd); err != nil {
		return err
	}

	// Prepare the provisioning script
	provisionShLocal := filepath.Join(runDir, runDirProvisionSh)
	_ = os.RemoveAll(provisionShLocal)
	if err = os.WriteFile(provisionShLocal, provisionShContent, 0755); err != nil {
		return err
	}
	provisionShRemote := "~/kubetest2-kindinv-provision.sh"
	cmd = d.rsync(ctx, "-av", "--progress", provisionShLocal, sshAddr+":"+provisionShRemote)
	if err = execCmd(cmd); err != nil {
		return err
	}

	// Execute the provisioning script to install Docker and kind
	cmd = d.ssh(ctx, sshAddr, "--", "sudo", provisionShRemote)
	if err = execCmd(cmd); err != nil {
		return err
	}

	// Allow the current user to use Docker
	if d.KindRootless {
		cmd = d.ssh(ctx, sshAddr, "--", "dockerd-rootless-setuptool.sh", "install", "-f")
	} else {
		cmd = d.ssh(ctx, sshAddr, "--", "sudo", "usermod -aG", "docker", d.User)
	}
	if err = execCmd(cmd); err != nil {
		return err
	}

	return nil
}

func (d *deployer) Up() error {
	ctx := context.TODO()
	// Start VM, and install Docker in it
	if err := d.upVM(ctx); err != nil {
		return err
	}
	sshAddr, err := d.sshAddr()
	if err != nil {
		return err
	}

	// Run `kind delete cluster` (for idempotence)
	cmd := d.ssh(ctx, sshAddr, "--", "kind", "delete", "cluster")
	if err = execCmd(cmd); err != nil {
		klog.V(2).Info(err) // negligible
	}

	// Run `kind create cluster`
	var kindArgs []string
	if d.commonOptions.ShouldBuild() {
		kindArgs = append(kindArgs, "--image="+d.kindImageRef())
	}
	cmd = d.ssh(ctx, append([]string{sshAddr, "--", "kind", "create", "cluster"}, kindArgs...)...)
	if err = execCmd(cmd); err != nil {
		return err
	}

	// Get kube-apiserver port
	kubeAPIPort, err := d.kubeAPIServerPort(ctx)
	if err != nil {
		return fmt.Errorf("failed to get kube-apiserver port: %w", err)
	}

	// Foward kube-apiserver port
	cmd = d.ssh(ctx, "-o", "ExitOnForwardFailure=yes", "-f", "-N",
		"-L", fmt.Sprintf("%d:127.0.0.1:%d", kubeAPIPort, kubeAPIPort), sshAddr)
	if err = execCmd(cmd); err != nil {
		return err
	}

	// Copy kubeconfig
	runDir := d.commonOptions.RunDir()
	kubeconfigRemote := "~/.kube/config"
	kubeconfigLocal := filepath.Join(runDir, runDirKubeconfig)
	cmd = d.rsync(ctx, "-av", "--progress", sshAddr+":"+kubeconfigRemote, kubeconfigLocal)
	if err = execCmd(cmd); err != nil {
		return err
	}
	klog.Infof("KUBECONFIG=%q", kubeconfigLocal)

	d.isUp = true
	return nil
}

func (d *deployer) Down() error {
	if d.GCPZone == "" {
		return errors.New("gcp-zone is unset")
	}

	ctx := context.TODO()
	klog.V(1).Info("deployer starting Down()")

	if err := d.DumpClusterLogs(); err != nil {
		klog.Warningf("Dumping cluster logs at the begin of Down() failed: %s", err)
	}

	instName, fwRuleName, nwName := d.instanceName(), d.firewallRuleName(), d.networkName()
	gcloudCmds := [][]string{
		{"--quiet", "compute", "instances", "delete", "--zone=" + d.GCPZone, instName},
		{"--quiet", "compute", "firewall-rules", "delete", fwRuleName},
		{"--quiet", "compute", "networks", "delete", nwName},
	}
	for _, f := range gcloudCmds {
		cmd, err := d.gcloud(ctx, f...)
		if err != nil {
			return err
		}
		if err := execCmd(cmd); err != nil {
			klog.Error(err)
			// continue, to allow "not found" errors
		}
	}
	if d.boskos != nil {
		klog.Info("releasing boskos project")
		err := boskos.Release(
			d.boskos,
			[]string{d.GCPProject},
			d.boskosHeartbeatClose,
		)
		if err != nil {
			return fmt.Errorf("down failed to release boskos project: %w", err)
		}
	}
	return nil
}

func (d *deployer) IsUp() (up bool, err error) {
	return d.isUp, nil
}

func (d *deployer) DumpClusterLogs() error {
	ctx := context.TODO()
	sshAddr, err := d.sshAddr()
	if err != nil {
		return err
	}
	logsRemote := "~/logs"
	cmd := d.ssh(ctx, sshAddr, "--", "kind", "export", "logs", logsRemote)
	if err := execCmd(cmd); err != nil {
		return err
	}
	artifactsDir := artifacts.BaseDir()
	logsLocal := filepath.Join(artifactsDir, artifactsDirLogs)
	cmd = d.rsync(ctx, "-av", "--progress", sshAddr+":"+logsRemote, logsLocal)
	if err = execCmd(cmd); err != nil {
		return err
	}
	return nil
}

// buildE2ERequirements was taken from https://github.com/kubernetes-sigs/kubetest2/pull/275
func (d *deployer) buildE2ERequirements() error {
	const target = "all"
	klog.V(0).Infof("Build(): build e2e requirements...\n")
	e2ePath := "test/e2e/e2e.test"
	kubectlPath := "cmd/kubectl"
	ginkgoPath := "vendor/github.com/onsi/ginkgo/v2/ginkgo"

	// make sure we have e2e requirements
	cmd := ktexec.Command("make", target,
		fmt.Sprintf("WHAT=%s %s %s", kubectlPath, e2ePath, ginkgoPath))
	cmd.SetDir(d.KubeRoot)
	ktexec.InheritOutput(cmd)
	if err := cmd.Run(); err != nil {
		return err
	}

	//move files
	const dockerizedOutput = "_output/dockerized"
	for _, binary := range commonTestBinaries {
		source := filepath.Join(d.KubeRoot, "_output/bin", binary)
		dest := filepath.Join(d.KubeRoot, dockerizedOutput, "bin", runtime.GOOS, runtime.GOARCH, binary)
		if err := fs.CopyFile(source, dest); err != nil {
			klog.Warningf("failed to copy %s to %s: %v", source, dest, err)
		}
	}

	storeCommonBinaries(d.KubeRoot, d.commonOptions.RunDir())
	return nil
}

func (d *deployer) Build() error {
	ctx := context.TODO()
	if err := d.buildE2ERequirements(); err != nil {
		return fmt.Errorf("failed to build e2e requirements: %w", err)
	}
	isUp, err := d.IsUp()
	if err != nil {
		return err
	}
	if !isUp {
		if err := d.upVM(ctx); err != nil {
			return err
		}
	}
	sshAddr, err := d.sshAddr()
	if err != nil {
		return err
	}
	remoteHome, err := d.remoteHome(ctx)
	if err != nil {
		return err
	}
	gopathKK := filepath.Join(remoteHome, "go", "src", "k8s.io", "kubernetes")

	// Clone k/k from github, assuming that cloning the repo from github
	// is faster than pushing it from the local host.
	cmd := d.ssh(ctx, sshAddr, "--",
		fmt.Sprintf(`/bin/sh -euxc "[ -e %s ] || git clone --progress https://github.com/kubernetes/kubernetes.git %s"`,
			gopathKK, gopathKK))
	if err = execCmd(cmd); err != nil {
		return err
	}
	cmd = d.ssh(ctx, sshAddr, "--",
		fmt.Sprintf(`/bin/sh -euxc "cd %s && git config --add receive.denyCurrentBranch warn"`,
			gopathKK))
	if err = execCmd(cmd); err != nil {
		return err
	}

	// Push the local changes to the remote
	headCommit, err := d.gitDescribeWithRepoDir(ctx, d.KubeRoot)
	if err != nil {
		return fmt.Errorf("failed to get the head of %q: %w", d.KubeRoot, err)
	}
	cmd = d.git(ctx, "push", "--set-upstream", "--progress", "-f",
		fmt.Sprintf("ssh://%s@%s:%s", d.User, sshAddr, gopathKK), "master")
	cmd.Dir = d.KubeRoot
	if err = execCmd(cmd); err != nil {
		return err
	}
	cmd = d.ssh(ctx, sshAddr, "--",
		fmt.Sprintf(`/bin/sh -euxc "cd %s && git checkout %s"`, gopathKK, headCommit))
	if err = execCmd(cmd); err != nil {
		return err
	}

	// Build the kind image
	cmd = d.ssh(ctx, sshAddr, "--", "kind", "build", "node-image",
		"--image="+d.kindImageRef(), gopathKK)
	if err := execCmd(cmd); err != nil {
		return err
	}
	return nil
}

func (d *deployer) Kubeconfig() (string, error) {
	runDir := d.commonOptions.RunDir()
	return filepath.Join(runDir, runDirKubeconfig), nil
}

func (d *deployer) Version() string {
	return version.GetVersion()
}

func bindFlags(d *deployer) *pflag.FlagSet {
	flags, err := gpflag.Parse(d)
	if err != nil {
		klog.Fatalf("unable to generate flags from deployer")
		return nil
	}

	flags.AddGoFlagSet(flag.CommandLine)

	return flags
}

// commonTestBinaries is from https://github.com/kubernetes-sigs/kubetest2/blob/1ad71e1e364e6a6e75b102194eaed191fbae630c/pkg/build/build.go#L76-L82
var commonTestBinaries = []string{
	"kubectl",
	"e2e.test",
	"ginkgo",
}

// storeCommonBinaries will best effort try to store commonly built binaries
// to the output directory.
// From https://github.com/kubernetes-sigs/kubetest2/blob/1ad71e1e364e6a6e75b102194eaed191fbae630c/pkg/build/build.go#L84-L101
func storeCommonBinaries(kuberoot string, outroot string) {
	const dockerizedOutput = "_output/dockerized"
	root := filepath.Join(kuberoot, dockerizedOutput, "bin", runtime.GOOS, runtime.GOARCH)
	for _, binary := range commonTestBinaries {
		source := filepath.Join(root, binary)
		dest := filepath.Join(outroot, binary)
		if _, err := os.Stat(source); err == nil {
			klog.V(2).Infof("copying %s to %s ...", source, dest)
			if err := fs.CopyFile(source, dest); err != nil {
				klog.Warningf("failed to copy %s to %s: %v", source, dest, err)
			}
		} else {
			klog.Warningf("could not find %s: %v", source, err)
		}
	}
}
