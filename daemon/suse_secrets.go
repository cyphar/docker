/*
 * suse-secrets: patch for Docker to implement SUSE secrets
 * Copyright (C) 2017 SUSE LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package daemon

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"syscall"

	"github.com/Sirupsen/logrus"
	"github.com/docker/docker/container"
	"github.com/docker/docker/pkg/idtools"
	"github.com/opencontainers/go-digest"

	swarmtypes "github.com/docker/docker/api/types/swarm"
	swarmexec "github.com/docker/swarmkit/agent/exec"
	swarmapi "github.com/docker/swarmkit/api"
)

func init() {
	// Output to tell us in logs that SUSE:secrets is enabled.
	logrus.Infof("SUSE:secrets :: enabled")
}

// Creating a fake file.
type SuseFakeFile struct {
	Path string
	Uid  int
	Gid  int
	Mode os.FileMode
	Data []byte
}

func (s SuseFakeFile) id() string {
	return fmt.Sprintf("suse::%s:%s", digest.FromBytes(s.Data), s.Path)
}

func (s SuseFakeFile) toSecret() *swarmapi.Secret {
	return &swarmapi.Secret{
		ID:       s.id(),
		Internal: true,
		Spec: swarmapi.SecretSpec{
			Data: s.Data,
		},
	}
}

func (s SuseFakeFile) toSecretReference(uidMaps, gidMaps []idtools.IDMap) *swarmtypes.SecretReference {
	// Figure out the host-facing {uid,gid} based on the provided maps. Fall
	// back to root if the UID/GID don't match (we are guaranteed that root is
	// mapped).
	hostUid, hostGid, _ := idtools.GetRootUIDGID(uidMaps, gidMaps)
	if uid, err := idtools.ToHost(s.Uid, uidMaps); err == nil {
		hostUid = uid
	}
	if gid, err := idtools.ToHost(s.Gid, gidMaps); err == nil {
		hostGid = gid
	}

	// Return the secret reference as a file target.
	return &swarmtypes.SecretReference{
		SecretID:   s.id(),
		SecretName: s.id(),
		File: &swarmtypes.SecretReferenceFileTarget{
			Name: s.Path,
			UID:  fmt.Sprintf("%d", hostUid),
			GID:  fmt.Sprintf("%d", hostGid),
			Mode: s.Mode,
		},
	}
}

// readDir will recurse into a directory prefix/dir, and return the set of secrets
// in that directory. The Path attribute of each has the prefix stripped. Symlinks
// are evaluated.
func readDir(prefix, dir string) ([]*SuseFakeFile, error) {
	var suseFiles []*SuseFakeFile

	path := filepath.Join(prefix, dir)

	fi, err := os.Stat(path)
	if err != nil {
		// Ignore dangling symlinks.
		if os.IsNotExist(err) {
			logrus.Warnf("SUSE:secrets :: dangling symlink: %s", path)
			return suseFiles, nil
		}
		return nil, err
	}

	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		logrus.Warnf("SUSE:secrets :: failed to cast directory stat_t: defaulting to owned by root:root: %s", path)
	}

	suseFiles = append(suseFiles, &SuseFakeFile{
		Path: dir,
		Uid:  int(stat.Uid),
		Gid:  int(stat.Gid),
		Mode: fi.Mode(),
	})

	files, err := ioutil.ReadDir(path)
	if err != nil {
		return nil, err
	}

	for _, f := range files {
		subpath := filepath.Join(dir, f.Name())

		if f.IsDir() {
			secrets, err := readDir(prefix, subpath)
			if err != nil {
				return nil, err
			}
			suseFiles = append(suseFiles, secrets...)
		} else {
			secrets, err := readFile(prefix, subpath)
			if err != nil {
				return nil, err
			}
			suseFiles = append(suseFiles, secrets...)
		}
	}

	return suseFiles, nil
}

// readFile returns a secret given a file under a given prefix.
func readFile(prefix, file string) ([]*SuseFakeFile, error) {
	var suseFiles []*SuseFakeFile

	path := filepath.Join(prefix, file)
	fi, err := os.Stat(path)
	if err != nil {
		// Ignore dangling symlinks.
		if os.IsNotExist(err) {
			logrus.Warnf("SUSE:secrets :: dangling symlink: %s", path)
			return suseFiles, nil
		}
		return nil, err
	}

	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		logrus.Warnf("SUSE:secrets :: failed to cast file stat_t: defaulting to owned by root:root: %s", path)
	}

	if fi.IsDir() {
		secrets, err := readDir(prefix, file)
		if err != nil {
			return nil, err
		}
		suseFiles = append(suseFiles, secrets...)
	} else {
		bytes, err := ioutil.ReadFile(path)
		if err != nil {
			return nil, err
		}
		suseFiles = append(suseFiles, &SuseFakeFile{
			Path: file,
			Uid:  int(stat.Uid),
			Gid:  int(stat.Gid),
			Mode: fi.Mode(),
			Data: bytes,
		})
	}

	return suseFiles, nil
}

// getHostSuseSecretData returns the list of SuseFakeFiles the need to be added
// as SUSE secrets.
func getHostSuseSecretData() ([]*SuseFakeFile, error) {
	secrets := []*SuseFakeFile{}

	credentials, err := readDir("/etc/zypp", "credentials.d")
	if err != nil {
		if os.IsNotExist(err) {
			credentials = []*SuseFakeFile{}
		} else {
			logrus.Errorf("SUSE:secrets :: error while reading zypp credentials: %s", err)
			return nil, err
		}
	}
	secrets = append(secrets, credentials...)

	suseConnect, err := readFile("/etc", "SUSEConnect")
	if err != nil {
		if os.IsNotExist(err) {
			suseConnect = []*SuseFakeFile{}
		} else {
			logrus.Errorf("SUSE:secrets :: error while reading /etc/SUSEConnect: %s", err)
			return nil, err
		}
	}
	secrets = append(secrets, suseConnect...)

	return secrets, nil
}

// In order to reduce the amount of code touched outside of this file, we
// implement the swarm API for SecretGetter. This asserts that this requirement
// will always be matched.
var _ swarmexec.SecretGetter = &suseSecretGetter{}

type suseSecretGetter struct {
	dfl     swarmexec.SecretGetter
	secrets map[string]*swarmapi.Secret
}

func (s *suseSecretGetter) Get(id string) *swarmapi.Secret {
	logrus.Debugf("SUSE:secrets :: id=%s requested from suseSecretGetter", id)

	secret, ok := s.secrets[id]
	if !ok {
		// fallthrough
		return s.dfl.Get(id)
	}

	return secret
}

func (daemon *Daemon) injectSuseSecretStore(c *container.Container) error {
	newSecretStore := &suseSecretGetter{
		dfl:     c.SecretStore,
		secrets: make(map[string]*swarmapi.Secret),
	}

	secrets, err := getHostSuseSecretData()
	if err != nil {
		return err
	}

	uidMaps, gidMaps := daemon.GetUIDGIDMaps()
	for _, secret := range secrets {
		newSecretStore.secrets[secret.id()] = secret.toSecret()
		c.SecretReferences = append(c.SecretReferences, secret.toSecretReference(uidMaps, gidMaps))
	}

	c.SecretStore = newSecretStore
	return nil
}
