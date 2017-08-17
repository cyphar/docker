package container

import (
	"context"
	"testing"

	"github.com/docker/docker/api/types/strslice"
	"github.com/docker/docker/integration/util/request"
	"github.com/docker/docker/pkg/parsers/kernel"
)

// #34573
func TestRunVolumeLeakage(t *testing.T) {
	defer setupTest(t)()
	cli := request.NewAPIClient(t)

	// Note whether the test is running on devicemapper (where the error being
	// tested ocurred). We run it anyway just to be safe.
	info, _ := cli.Info(context.Background())
	if info.Driver != "devicemapper" {
		t.Logf("Active driver (%s) is not devicemapper, continuing anyway.", info.Driver)
	}

	// On some older kernels we cannot guarantee that out fix for this bug
	// actually works. So if there is an error the best we can do is just
	// warn about it (if the kernel is older than 3.18, when
	// torvalds/linux@8ed936b5671bfb33d89bc60bdcc7cf0470ba52fe was merged).
	oldKernel := kernel.CheckKernelVersion(3, 18, 0)
	if oldKernel {
		t.Logf("NOTE: This test may fail on your <3.18 kernels.")
	}

	// docker run -d --name testA busybox top
	var configA containerConfig
	configA.Config.Image = "busybox"
	configA.Config.Cmd = strslice.StrSlice{"top"}
	if _, err := runDetachedContainer(context.Background(), cli, configA, "testA"); err != nil {
		t.Fatalf("failed to start testA: %v", err)
	}

	// docker run -d --name testB -v /:/rootfs busybox top
	var configB containerConfig
	configB.Config.Image = "busybox"
	configB.Config.Cmd = strslice.StrSlice{"top"}
	configB.HostConfig.Binds = []string{"/:/rootfs"}
	if _, err := runDetachedContainer(context.Background(), cli, configB, "testB"); err != nil {
		t.Fatalf("failed to start testB: %v", err)
	}

	// docker rm -f testA
	if err := rmContainer(context.Background(), cli, "testA", true); err != nil {
		errfn := t.Errorf
		if oldKernel {
			errfn = t.Logf
		}
		errfn("failed to remove container that leaked Docker's mounts: %v", err)
	}
}
