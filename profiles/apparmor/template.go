// +build linux

package apparmor // import "github.com/docker/docker/profiles/apparmor"

// NOTE: This profile is replicated in containerd and libpod. If you make a
//       change to this profile, please make follow-up PRs to those projects so
//       that these rules can be synchronised (because any issue with this
//       profile will likely affect libpod and containerd).
// TODO: Move this to a common project so we can maintain it in one spot.

// baseTemplate defines the default apparmor profile for containers.
const baseTemplate = `
# NOTE: This profile is a Go template, which is necessary for the container
#       runtime to be able to effectively handle different distributions. If
#       you plan to modify and this template, be aware that some of these
#       variable substituions are required in order for it to work across
#       distributions and AppArmor versions.

# If used as a default profile, the following variables will defined by the
# runtime at template execution time:
#
#  .Name
#     The name of the profile. This template MUST contain a profile with this
#     name or containers will be unable to start.
#
#  .Imports
#     List of system import lines to be placed in the global scope.
#
#  .InnerImports
#     List of system import lines to be placed in the profile scope.
#
#  .DaemonProfile
#     Name of the profile (or "unconfined") that the management daemon runs
#     under.
#
#  .Version
#     The version of apparmor_parser available on the system (for an
#     apparmor_parser version XX.YY.ZZZ, this variable will contain the
#     numerical value XXYYZZZ). Note that these semantics may change in a
#     future version, if AppArmor decides to release a version of
#     apparmor_parser which breaks this convention.
#
# While we will make every attempt to not change the semantics of these
# variables, they are an implementation detail and users should make sure that
# they verify their custom profiles with upgrades as it may be necessary for us
# to change these variables and their semantics in the future.

{{range $value := .Imports}}
{{$value}}
{{end}}

profile {{.Name}} flags=(attach_disconnected,mediate_deleted) {
{{range $value := .InnerImports}}
  {{$value}}
{{end}}

  network,
  capability,
  file,
  umount,
{{if ge .Version 208096}}
  # Host (privileged) processes may send signals to container processes.
  signal (receive) peer=unconfined,
  # dockerd may send signals to container processes (for "docker kill").
  signal (receive) peer={{.DaemonProfile}},
  # Container processes may send signals amongst themselves.
  signal (send,receive) peer={{.Name}},
{{end}}

  deny @{PROC}/* w,   # deny write for all files directly in /proc (not in a subdir)
  # deny write to files not in /proc/<number>/** or /proc/sys/**
  deny @{PROC}/{[^1-9],[^1-9][^0-9],[^1-9s][^0-9y][^0-9s],[^1-9][^0-9][^0-9][^0-9]*}/** w,
  deny @{PROC}/sys/[^k]** w,  # deny /proc/sys except /proc/sys/k* (effectively /proc/sys/kernel)
  deny @{PROC}/sys/kernel/{?,??,[^s][^h][^m]**} w,  # deny everything except shm* in /proc/sys/kernel/
  deny @{PROC}/sysrq-trigger rwklx,
  deny @{PROC}/kcore rwklx,

  deny mount,

  deny /sys/[^f]*/** wklx,
  deny /sys/f[^s]*/** wklx,
  deny /sys/fs/[^c]*/** wklx,
  deny /sys/fs/c[^g]*/** wklx,
  deny /sys/fs/cg[^r]*/** wklx,
  deny /sys/firmware/** rwklx,
  deny /sys/kernel/security/** rwklx,

{{if ge .Version 208095}}
  # suppress ptrace denials when using 'docker ps' or using 'ps' inside a container
  ptrace (trace,read,tracedby,readby) peer={{.Name}},
{{end}}
}
`

// BaseTemplate returns the string form of the default AppArmor profile
// template.
func BaseTemplate() string {
	return baseTemplate
}
