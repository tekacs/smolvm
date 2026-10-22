use super::place_in_cgroup;
use std::fs;

const CONTROLS: &[&str] = &[
    "cpu.max",
    "pids.max",
    "memory.high",
    "memory.max",
    "cgroup.procs",
];

fn leaf(root: &std::path::Path) -> std::path::PathBuf {
    let path = root.join(format!("vm-{}", std::process::id()));
    fs::create_dir(&path).unwrap();
    fs::write(path.join("cgroup.events"), "populated 0\n").unwrap();
    for name in CONTROLS {
        fs::write(path.join(name), []).unwrap();
    }
    path
}

#[test]
fn missing_required_control_refuses_membership() {
    for missing in CONTROLS {
        let root = tempfile::tempdir().unwrap();
        let vm = leaf(root.path());
        fs::remove_file(vm.join(missing)).unwrap();
        assert!(
            place_in_cgroup(root.path(), 1, 512, false, false).is_err(),
            "{missing}"
        );
        if *missing != "cgroup.procs" {
            assert!(
                fs::read(vm.join("cgroup.procs")).unwrap().is_empty(),
                "{missing}"
            );
        }
    }
}

#[test]
fn a_populated_descendant_or_missing_evidence_refuses_reuse() {
    for events in ["populated 1\n", "frozen 0\n"] {
        let root = tempfile::tempdir().unwrap();
        let vm = leaf(root.path());
        fs::write(vm.join("cgroup.events"), events).unwrap();
        // The direct procs file is empty; that alone must not authorize reuse.
        assert!(place_in_cgroup(root.path(), 1, 512, false, false).is_err());
        assert!(fs::read(vm.join("cpu.max")).unwrap().is_empty());
        assert!(fs::read(vm.join("cgroup.procs")).unwrap().is_empty());
    }
}

#[test]
fn absent_delegation_never_creates_fake_control_files() {
    let root = tempfile::tempdir().unwrap();
    assert!(place_in_cgroup(root.path(), 1, 512, false, false).is_err());
    let vm = root.path().join(format!("vm-{}", std::process::id()));
    assert!(!vm.join("cpu.max").exists());
    assert!(!vm.join("cgroup.procs").exists());
}
