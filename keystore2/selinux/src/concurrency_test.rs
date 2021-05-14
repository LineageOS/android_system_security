// Copyright 2021, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use keystore2_selinux::{check_access, Context};
use nix::sched::sched_setaffinity;
use nix::sched::CpuSet;
use nix::unistd::getpid;
use std::cmp::min;
use std::thread;
use std::{
    sync::{atomic::AtomicU8, atomic::Ordering, Arc},
    time::Duration,
};

#[derive(Clone, Copy)]
struct CatCount(u8, u8, u8, u8);

impl CatCount {
    fn next(&mut self) -> CatCount {
        let result = *self;
        if self.3 == 255 {
            if self.2 == 254 {
                if self.1 == 253 {
                    if self.0 == 252 {
                        self.0 = 255;
                    }
                    self.0 += 1;
                    self.1 = self.0;
                }
                self.1 += 1;
                self.2 = self.1;
            }
            self.2 += 1;
            self.3 = self.2;
        }
        self.3 += 1;
        result
    }

    fn make_string(&self) -> String {
        format!("c{},c{},c{},c{}", self.0, self.1, self.2, self.3)
    }
}

impl Default for CatCount {
    fn default() -> Self {
        Self(0, 1, 2, 3)
    }
}

/// This test calls selinux_check_access concurrently causing access vector cache misses
/// in libselinux avc. The test then checks if any of the threads fails to report back
/// after a burst of access checks. The purpose of the test is to draw out a specific
/// access vector cache corruption that sends a calling thread into an infinite loop.
/// This was observed when keystore2 used libselinux concurrently in a non thread safe
/// way. See b/184006658.
#[test]
fn test_concurrent_check_access() {
    android_logger::init_once(
        android_logger::Config::default()
            .with_tag("keystore2_selinux_concurrency_test")
            .with_min_level(log::Level::Debug),
    );

    static AVS: &[(&str, &str, &str, &str)] = &[
        ("u:object_r:keystore:s0", "u:r:untrusted_app:s0:c0,c1,c2,c3", "use", "keystore2_key"),
        ("u:object_r:su_key:s0", "u:r:su:s0", "get_info", "keystore2_key"),
        ("u:object_r:shell_key:s0", "u:r:shell:s0", "delete", "keystore2_key"),
        ("u:object_r:keystore:s0", "u:r:system_server:s0", "add_auth", "keystore2"),
        ("u:object_r:keystore:s0", "u:r:su:s0", "change_user", "keystore2"),
        (
            "u:object_r:vold_key:s0",
            "u:r:vold:s0",
            "convert_storage_key_to_ephemeral",
            "keystore2_key",
        ),
    ];

    let cpus = num_cpus::get();

    let turnpike = Arc::new(AtomicU8::new(0));

    let mut threads: Vec<thread::JoinHandle<()>> = Vec::new();

    let goals: Arc<Vec<AtomicU8>> = Arc::new((0..cpus).map(|_| AtomicU8::new(0)).collect());

    let turnpike_clone = turnpike.clone();
    let goals_clone = goals.clone();

    threads.push(thread::spawn(move || {
        let mut cpu_set = CpuSet::new();
        cpu_set.set(0).unwrap();
        sched_setaffinity(getpid(), &cpu_set).unwrap();
        let mut cat_count: CatCount = Default::default();

        log::info!("Thread 0 reached turnpike");
        loop {
            turnpike_clone.fetch_add(1, Ordering::Relaxed);
            loop {
                match turnpike_clone.load(Ordering::Relaxed) {
                    0 => break,
                    255 => {
                        goals_clone[0].store(1, Ordering::Relaxed);
                        return;
                    }
                    _ => {}
                }
            }

            for _ in 0..100 {
                let (tctx, sctx, perm, class) = (
                    Context::new("u:object_r:keystore:s0").unwrap(),
                    Context::new(&format!(
                        "u:r:untrusted_app:s0:{}",
                        cat_count.next().make_string()
                    ))
                    .unwrap(),
                    "use",
                    "keystore2_key",
                );

                check_access(&sctx, &tctx, class, perm).unwrap();
            }

            goals_clone[0].store(1, Ordering::Relaxed);
        }
    }));

    for i in 1..cpus {
        let turnpike_clone = turnpike.clone();
        let goals_clone = goals.clone();

        log::info!("Spawning thread {}", i);
        threads.push(thread::spawn(move || {
            let mut cpu_set = CpuSet::new();
            cpu_set.set(i).unwrap();
            sched_setaffinity(getpid(), &cpu_set).unwrap();

            let (tctx, sctx, perm, class) = AVS[i % min(cpus, AVS.len())];

            let sctx = Context::new(sctx).unwrap();
            let tctx = Context::new(tctx).unwrap();

            log::info!("Thread {} reached turnpike", i);
            loop {
                turnpike_clone.fetch_add(1, Ordering::Relaxed);
                loop {
                    match turnpike_clone.load(Ordering::Relaxed) {
                        0 => break,
                        255 => {
                            goals_clone[i].store(1, Ordering::Relaxed);
                            return;
                        }
                        _ => {}
                    }
                }

                for _ in 0..100 {
                    check_access(&sctx, &tctx, class, perm).unwrap();
                }

                goals_clone[i].store(1, Ordering::Relaxed);
            }
        }));
    }

    let mut i = 0;

    loop {
        thread::sleep(Duration::from_millis(200));

        // Give the threads some time to reach and spin on the turn pike.
        assert_eq!(turnpike.load(Ordering::Relaxed) as usize, cpus, "i = {}", i);
        if i == 100 {
            turnpike.store(255, Ordering::Relaxed);
            break;
        }
        // Now go.
        turnpike.store(0, Ordering::Relaxed);
        i += 1;
    }

    for t in threads {
        t.join().unwrap();
    }
}
