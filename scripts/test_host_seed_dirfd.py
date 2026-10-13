#!/usr/bin/env python3
"""Compile only the production seed functions; test synthetic private temp paths."""

import argparse
from pathlib import Path
import subprocess
import tempfile
import unittest

HARNESS = r'''
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static const char *scenario, *parent_path, *held_path, *attacker_path;
static int parent_fd_seen = -1, swapped, dir_syncs, relative_opens, relative_unlinks;
static int random_interrupt, write_interrupt, read_interrupt;

static void swap_parent(void)
{
    if(swapped) return;
    if(rename(parent_path, held_path) || symlink(attacker_path, parent_path)) exit(99);
    swapped = 1;
}

static int fixture_open(const char *path, int flags, ...)
{
    mode_t mode = 0;
    if(flags & O_CREAT) {
        va_list ap; va_start(ap, flags); mode = (mode_t)va_arg(ap, int); va_end(ap);
    }
    int fd = open(path, flags, mode);
    if(fd >= 0 && (flags & O_DIRECTORY)) parent_fd_seen = fd;
    return fd;
}

static int fixture_fstat(int fd, struct stat *st)
{
    int rc = fstat(fd, st);
    if(rc) return rc;
    if(fd == parent_fd_seen) {
        if(!strcmp(scenario, "parent-owner")) st->st_uid = geteuid() + 1;
        if(!strcmp(scenario, "parent-fstat-fail")) { errno = EIO; return -1; }
        if(!strcmp(scenario, "swap-reuse") || !strcmp(scenario, "swap-create")) swap_parent();
    } else if(!strcmp(scenario, "seed-owner")) st->st_uid = geteuid() + 1;
    return 0;
}

static int fixture_openat(int dirfd, const char *path, int flags, ...)
{
    mode_t mode = 0;
    relative_opens++;
    if(flags & O_CREAT) {
        va_list ap; va_start(ap, flags); mode = (mode_t)va_arg(ap, int); va_end(ap);
        if(!strcmp(scenario, "create-error")) { errno = EACCES; return -1; }
        if(!strcmp(scenario, "create-race")) {
            uint8_t other[32]; memset(other, 0x33, sizeof(other));
            int fd = openat(dirfd, path, flags, mode);
            if(fd < 0 || write(fd, other, sizeof(other)) != 32 || close(fd)) exit(99);
            errno = EEXIST; return -1;
        }
    }
    return openat(dirfd, path, flags, mode);
}

static ssize_t fixture_getrandom(void *data, size_t count, unsigned int flags)
{
    (void)flags;
    if(!strcmp(scenario, "entropy-error")) { errno = EIO; return -1; }
    if(!strcmp(scenario, "interrupts") && !random_interrupt++) { errno = EINTR; return -1; }
    if(count > 7) count = 7;
    memset(data, 0x5a, count);
    return (ssize_t)count;
}

static ssize_t fixture_write(int fd, const void *data, size_t count)
{
    if(!strcmp(scenario, "swap-write-error")) { swap_parent(); errno = EIO; return -1; }
    if(!strcmp(scenario, "write-error")) { errno = EIO; return -1; }
    if(!strcmp(scenario, "zero-write")) return 0;
    if(!strcmp(scenario, "interrupts") && !write_interrupt++) { errno = EINTR; return -1; }
    if(count > 5) count = 5;
    return write(fd, data, count);
}

static ssize_t fixture_read(int fd, void *data, size_t count)
{
    if(!strcmp(scenario, "read-error")) { errno = EIO; return -1; }
    if(!strcmp(scenario, "interrupt-read") && !read_interrupt++) { errno = EINTR; return -1; }
    if(count > 6) count = 6;
    return read(fd, data, count);
}

static int fixture_fsync(int fd)
{
    if(fd == parent_fd_seen) {
        dir_syncs++;
        if(!strcmp(scenario, "directory-sync-error")) { errno = EIO; return -1; }
    } else if(!strcmp(scenario, "file-sync-error")) { errno = EIO; return -1; }
    return fsync(fd);
}

static int fixture_close(int fd)
{
    int rc = close(fd);
    if(fd != parent_fd_seen && !strcmp(scenario, "file-close-error")) { errno = EIO; return -1; }
    return rc;
}

static int fixture_unlinkat(int dirfd, const char *path, int flags)
{
    relative_unlinks++;
    return unlinkat(dirfd, path, flags);
}

#define open fixture_open
#define openat fixture_openat
#define fstat fixture_fstat
#define getrandom fixture_getrandom
#define write fixture_write
#define read fixture_read
#define fsync fixture_fsync
#define close fixture_close
#define unlinkat fixture_unlinkat
PRODUCTION_FUNCTIONS
#undef open
#undef openat
#undef fstat
#undef getrandom
#undef write
#undef read
#undef fsync
#undef close
#undef unlinkat

int main(int argc, char **argv)
{
    uint8_t seed[32], expected[32];
    if(argc != 6) return 99;
    scenario = argv[1]; parent_path = argv[3]; held_path = argv[4]; attacker_path = argv[5];
    memset(seed, 0x7c, sizeof(seed));
    int result = host_seed(argv[2], seed);
    memset(expected, !strcmp(scenario, "create-race") ? 0x33 : 0x5a, sizeof(expected));
    if(result == 0 && memcmp(seed, expected, sizeof(seed))) return 98;
    printf("result=%d relative_opens=%d relative_unlinks=%d dir_syncs=%d swapped=%d\n",
           result, relative_opens, relative_unlinks, dir_syncs, swapped);
    return result == 0 ? 0 : 1;
}
'''


class SeedFixtures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = SOURCE.read_text()
        functions = source[source.index("static int random_seed("):source.index("\nint main(")]
        cls.build = tempfile.TemporaryDirectory(prefix="noxssh-seed-functions-")
        cls.addClassCleanup(cls.build.cleanup)
        path = Path(cls.build.name)
        (path / "fixture.c").write_text(HARNESS.replace("PRODUCTION_FUNCTIONS", functions))
        cls.binary = path / "fixture"
        subprocess.run([CC, "-std=c99", "-Wall", "-Wextra", "-Werror", "-O2",
                        str(path / "fixture.c"), "-o", str(cls.binary)], check=True)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="noxssh-seed-case-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.parent = self.root / "private"
        self.held = self.root / "held"
        self.attack = self.root / "attacker"
        self.parent.mkdir(mode=0o700)
        self.attack.mkdir(mode=0o777)
        self.seed = self.parent / "seed"
        self.other = self.attack / "seed"
        self.other.write_bytes(b"A" * 32)
        self.other.chmod(0o600)

    def existing(self, size=32, mode=0o600):
        self.seed.write_bytes(b"\x5a" * size)
        self.seed.chmod(mode)

    def run_case(self, scenario="normal", success=True, path=None):
        result = subprocess.run([str(self.binary), scenario, str(path or self.seed),
                                 str(self.parent), str(self.held), str(self.attack)],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0 if success else 1, result.stdout + result.stderr)
        self.assertEqual(self.other.read_bytes(), b"A" * 32)
        return result.stdout

    def test_create_and_reuse_exact_private_seed(self):
        first = self.run_case()
        self.assertIn("dir_syncs=1", first)
        self.assertEqual(self.seed.read_bytes(), b"\x5a" * 32)
        self.assertEqual(self.seed.stat().st_mode & 0o777, 0o600)
        self.assertIn("dir_syncs=0", self.run_case())

    def test_existing_read_interrupted_and_short(self):
        self.existing()
        self.run_case("interrupt-read")

    def test_entropy_and_write_interrupted_and_short(self):
        self.run_case("interrupts")

    def test_concurrent_creator_reused(self):
        self.run_case("create-race")
        self.assertEqual(self.seed.read_bytes(), b"\x33" * 32)

    def test_existing_parent_path_swap_uses_validated_directory(self):
        self.existing()
        self.assertIn("swapped=1", self.run_case("swap-reuse"))
        self.assertTrue(self.parent.is_symlink())
        self.assertEqual((self.held / "seed").read_bytes(), b"\x5a" * 32)

    def test_creation_parent_path_swap_uses_validated_directory_and_fsync(self):
        self.assertIn("dir_syncs=1 swapped=1", self.run_case("swap-create"))
        self.assertEqual((self.held / "seed").read_bytes(), b"\x5a" * 32)

    def test_write_failure_cleanup_not_redirected_by_parent_swap(self):
        self.assertIn("relative_unlinks=1", self.run_case("swap-write-error", False))
        self.assertFalse((self.held / "seed").exists())

    def test_symlink_parent_rejected(self):
        self.parent.rmdir()
        self.parent.symlink_to(self.attack, target_is_directory=True)
        self.run_case(success=False)

    def test_writable_parent_rejected(self):
        self.parent.chmod(0o777)
        self.run_case(success=False)

    def test_symlink_parent_with_repeated_separator_rejected(self):
        self.parent.rmdir()
        self.parent.symlink_to(self.attack, target_is_directory=True)
        self.run_case(success=False, path=str(self.parent) + "//seed")

    def test_wrong_parent_owner_rejected(self):
        self.run_case("parent-owner", False)

    def test_parent_fstat_failure_rejected(self):
        self.run_case("parent-fstat-fail", False)

    def test_symlink_seed_rejected(self):
        self.seed.symlink_to(self.other)
        self.run_case(success=False)

    def test_fifo_seed_rejected_without_blocking(self):
        import os
        os.mkfifo(self.seed, 0o600)
        self.run_case(success=False)

    def test_directory_seed_rejected(self):
        self.seed.mkdir(mode=0o700)
        self.run_case(success=False)

    def test_wrong_seed_owner_rejected(self):
        self.existing()
        self.run_case("seed-owner", False)

    def test_exposed_seed_permissions_rejected(self):
        self.existing(mode=0o644)
        self.run_case(success=False)

    def test_wrong_seed_length_rejected(self):
        for size in [0, 31, 33]:
            self.existing(size=size)
            self.run_case(success=False)
            self.assertEqual(self.seed.stat().st_size, size)

    def test_read_failure_preserves_existing_seed(self):
        self.existing()
        self.run_case("read-error", False)
        self.assertEqual(self.seed.read_bytes(), b"\x5a" * 32)

    def test_entropy_failure_does_not_create_seed(self):
        self.run_case("entropy-error", False)
        self.assertFalse(self.seed.exists())

    def test_create_error_does_not_create_seed(self):
        self.run_case("create-error", False)
        self.assertFalse(self.seed.exists())

    def test_failed_write_sync_close_cleanup(self):
        for scenario in ["write-error", "zero-write", "file-sync-error", "file-close-error"]:
            self.run_case(scenario, False)
            self.assertFalse(self.seed.exists())

    def test_directory_sync_failure_preserves_complete_identity(self):
        self.run_case("directory-sync-error", False)
        self.assertEqual(self.seed.read_bytes(), b"\x5a" * 32)
        self.run_case()

    def test_invalid_final_components(self):
        for path in [str(self.parent) + "/", str(self.parent) + "/.", str(self.parent) + "/.."]:
            self.run_case(success=False, path=path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parents[1] / "server/main.c")
    parser.add_argument("--cc", default="cc")
    args, remainder = parser.parse_known_args()
    SOURCE, CC = args.source, args.cc
    unittest.main(argv=[__file__, *remainder], verbosity=2)
