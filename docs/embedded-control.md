# Embedded control

`embedded::EmbeddedRuntime` calls the engine directly. It starts a separate boot
helper to enter the hypervisor. Machine control is direct; the shared image-seed
builder described below uses the matched helper's internal CLI workflow. Register
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
sockets, existing expose destinations and failed bridge registration. Explicit host
paths remain caller-owned; contained execution cleanup never removes them, including
borrowed mount listeners. Machine specifications are immutable for a caller that requires
generation-fenced execution.

In the Linux subprocess launcher, an expose mapping without a host path requests
an engine-owned endpoint.
The launcher allocates one private directory per execution and persists its device,
inode and guest-to-host mappings in the execution record before admitting the helper.
This requires contained execution. `Execution::sockets` returns those same mappings
after controller replacement; it does not allocate new endpoints or prove readiness.
Applications keep the returned paths bound to that execution, not a movable alias.

Cleanup requires whole-execution exit, the unchanged execution record and the same
directory inode. It removes only the recorded socket names, refuses unexpected file
types or directory contents, and never follows a replaced directory. Thus an admitted
helper that dies before binding needs no invented bind receipt for cleanup. A caller
endpoint inside the machine's data directory blocks directory deletion until its
owner removes it. Allocation interrupted before execution-record publication can
leave an unrecorded directory; automatic collection of those directories is not
implemented.

The owned directory is reserved for serialized trusted engine writers. Mode 0700
excludes other UIDs, not hostile host processes with the same UID. Arbitrary same-UID
host mutation is outside this guest-isolation contract; this does not weaken guest
filesystem confinement or permit removing a replaced directory. Caller-specified
paths retain their separate collision/refusal contract.

## Helper environment

`Bundle::boot_env` selects an explicit helper environment. `None` retains the CLI
inheritance behavior. `Some(map)`, including an empty map, clears ambient variables
before adding the map and the engine's intentional per-launch variables. Dynamic
loader paths use only the explicit map and selected bundle in this mode, not the
parent's ambient loader path. The map is process configuration, not a VM record,
and must not contain unrelated credentials. It does not change the host process
environment or make all engine subprocesses use that environment.

## Explicit image preparation

On Unix, `image_seed::prepare_image(SeedSpec)` prepares the same content-, template-
and storage-size-keyed seed used by lazy first start. It returns a `SeedId`; holding
that value retains the existing shared cache lease so eviction cannot remove the
seed during attachment. No caller-side cache key or separate image registry is
needed. A cache hit does not unpack again. A miss uses the existing matched-helper
builder: a temporary VM with no workload flattens the image, then publishes its
storage through the existing cache lock/publication path. Local archive builders
have networking off. Registry-image preparation retains its existing authorization
and networking behavior. Explicit preparation does not attach a machine's disk.

`image_seed::prepared(SeedSpec)` only inspects existing cache state. It does not
create cache directories or lock files, materialize compressed templates, contact
a registry or start a VM. It returns None when absent or when a mutable reference
cannot be resolved from a fresh cached digest without IO. Pinned archives and
registry digests can be checked directly. This is cache evidence, not registry
pull authorization; normal start retains authorization checks.

`seed_storage` calls the same preparation implementation before attaching its
copy-on-write disk, preserving lazy operation when explicit preparation was not
performed or a cache entry was evicted. Builder subprocesses honor an embedder's
explicit `Bundle::boot_env`; unrelated ambient variables are not copied into them.
Read-only template discovery uses `smolvm_pack::assets::existing_template`, while
ordinary template discovery may still materialize compressed templates.

## Host launch observation

`progress::Observer` receives typed host phase events supplied explicitly to
`data::image_source::resolve_observed` and
`EmbeddedRuntime::start_machine_observed`. The observer has no engine clock,
process-global registration, identifiers, paths, command arguments or payloads.
The caller stamps callbacks with its own attempt clock and decides where to keep
them. Callbacks run synchronously; they must not block or re-enter the lifecycle.
Ordinary entry points use an empty observer and keep their existing behavior.

Archive resolution reports hashing and staging, including an actual cache hit,
hardlink or completed copy. Launch reports the existing image-seed attempt,
opening and formatting disks, helper spawn, retained execution admission, agent
readiness, initialization and the detached-workload launch routine. The seed span
includes selection, possible builder work and attachment; it is not evidence of a
cache hit or a pure lookup duration. A completed best-effort seed attempt does not
assert that a seed was built. A failed phase contains no error text. An interrupted
phase may have a start without a terminal event.

Helper spawn is reported after the host spawn call succeeds. Admission is reported
after the retained identity admission operation returns. Agent readiness is the
host manager's readiness result, not a guest timestamp. A completed workload phase
means the launch routine returned successfully: an image without a command may be
skipped, and a launch acknowledgement is not application readiness. Reconnecting
may still perform and report seed
checks or disk opening, but does not fabricate a helper spawn, new admission or
fresh workload launch. No event claims to observe application imports or
application-specific initialization inside the guest.

## Detached managers

A persisted detached machine survives both loss of its controller and normal
release of its cached handle. The engine detaches the manager after persisting
successful launch identity, and when attaching to that detached record. Explicit
stop still stops it. Operating-system service policy remains independent: a
service configured to kill its entire cgroup can kill detached VMs too.

## Launch admission

The matched helper waits on a private stdin pipe before opening boot configuration
or guest disks. On Linux the parent first places the blocked child in its requested
delegated cgroup or systemd scope. It then writes the child's PID, start time, Linux
boot ID and exact cgroup device/inode through one fsynced atomic identity file,
then releases that pipe. Placement or publication failure kills and reaps only
that unreaped child without admitting it. Controller death
before release closes the pipe and the helper refuses boot. Controller death after
release leaves an inspectable incarnation even if guest readiness never completed.
The early identity record is not rewritten during readiness bookkeeping. For
parent-owned machines, the watchdog uses the launcher PID passed before spawn,
not a replacement parent observed after admission. Watchdog thread creation
failure terminates the helper rather than silently disabling the lifetime rule.

## Trusted initialization

`MachineSpec::init` stores trusted provisioning commands in the existing machine
record. The embedded launcher runs them as guest root on the image's persistent
overlay and configured mounts before starting its workload user. CLI and embedded
launch use the same command construction and failure handling; their output policy
differs (interactive CLI output versus captured embedded output).

A nonzero command exit refuses workload launch. The runtime durably records
`init_completed` only after all commands succeed. Commands must tolerate replay:
a controller can lose the success reply before recording it. Image environment and
working directory apply, but image `USER` never changes provisioning away from
root. Neither initialization nor VM boot proves an application is ready; callers
must probe the application identity. A live VM left before workload startup is not
a ready resource and is not silently admitted as one.

## Resource and exit evidence

Linux delegated-cgroup placement establishes limits before joining the VM leaf.
An error writing required limits or membership refuses launch, rather than
continuing uncapped. The launcher records containment before boot admission; the
helper does not repeat placement after entering the populated leaf.

For a recorded contained execution, stop pins the exact cgroup directory and the
process incarnation before shutdown. Signals use a pidfd, not a re-read numeric
PID. Stop waits for process exit and `cgroup.events` reporting `populated 0`;
remaining descendants receive `cgroup.kill` after the graceful deadline. Timeout,
missing evidence or changed cgroup identity refuses completion and retains the
record. Completed exit is fsynced into that same record before runtime cleanup.
A later controller can inspect the retained evidence without an agent connection.
A different Linux boot ID proves that the recorded execution cannot remain alive.
Legacy or uncapped launches do not provide a whole-instance exit guarantee.
Neither a missing registry row nor a failed agent probe proves exit.

For a retained contained execution whose process and original cgroup have both
been removed, `Execution::exited` reconciles current absence under that record's
serialization lock. It rechecks the unchanged execution identity, refuses a
present/reused numeric PID or any replacement cgroup path, and durably records
`exited=true` with proof `absent` before returning success. Unexpected IO errors
remain errors. This records current containment absence, not a historical claim
that a particular stop command succeeded. The execution record is not unlinked;
owned socket cleanup and a successor start follow the ordinary exited path.
A held cgroup event descriptor reporting ENODEV from either seek or read also
proves removal of that original group, even when kernfs retains nlink=2.
The optional proof field accepts earlier records; readers that reject unknown
fields must be upgraded before reading newly reconciled records.
