# Embedded control

`embedded::EmbeddedRuntime` calls the engine directly. It starts a separate boot
helper to enter the hypervisor; it does not run CLI lifecycle commands. Register
one matching helper, library directory and rootfs bundle before starting machines.
The registry, image cache and rootfs/template discovery use one process-wide data
root. Set that root before starting threads, not around individual launches.

## Published sockets

`MachineSpec::published_sockets` persists host/guest Unix-socket mappings. Both
embedded creation and CLI parsing call `PublishedSocketConfig::validate` before
persisting them. Validation rejects excess mappings, malformed or nonabsolute
paths, oversized socket addresses, missing mount sources and duplicate guest
mount destinations. Launch reconstructs the mappings from the persisted record;
a stopped restart does not discard them. The boot helper refuses missing mount
sockets, existing expose destinations and failed bridge registration. It never
blindly unlinks a destination; a controller must prove exit and ownership before
removing a stale listener. Machine specifications are immutable
for a caller that requires generation-fenced execution.

## Helper environment

`Bundle::boot_env` selects an explicit helper environment. `None` retains the CLI
inheritance behavior. `Some(map)`, including an empty map, clears ambient variables
before adding the map and the engine's intentional per-launch variables. Dynamic
loader paths use only the explicit map and selected bundle in this mode, not the
parent's ambient loader path. The map is process configuration, not a VM record,
and must not contain unrelated credentials. It does not change the host process
environment or make all engine subprocesses use that environment.

## Detached managers

A persisted detached machine survives both loss of its controller and normal
release of its cached handle. The engine detaches the manager after persisting
successful launch identity, and when attaching to that detached record. Explicit
stop still stops it. Operating-system service policy remains independent: a
service configured to kill its entire cgroup can kill detached VMs too.

## Launch admission

The matched helper waits on a private stdin pipe before opening boot configuration
or guest disks. The parent writes the child's PID, start time and Linux boot ID
through an fsynced atomic identity file, then releases that pipe. Controller death
before release closes the pipe and the helper refuses boot. Controller death after
release leaves an inspectable incarnation even if guest readiness never completed.
The early identity record is not rewritten during readiness bookkeeping. For
parent-owned machines, the watchdog uses the launcher PID passed before spawn,
not a replacement parent observed after admission. Watchdog thread creation
failure terminates the helper rather than silently disabling the lifetime rule.

## Resource and exit evidence

Linux delegated-cgroup placement establishes limits before joining the VM leaf.
An error writing required limits or membership refuses launch, rather than
continuing uncapped. A successful stop request alone does not establish whole-tree
exit; controllers must retain exact process incarnation and cgroup identity until
physical exit is established. Neither a missing registry row nor a failed agent
probe proves that an earlier launch cannot still run.
