import tarfile
import gzip
import json
import os
import platform
import shutil
import secrets
from contextlib import contextmanager
from subprocess import Popen, PIPE
from functools import lru_cache


SCRIPT_NAME = "YUBIKEY_SETUP"

TMP_DIR = os.path.join("/tmp", f"{SCRIPT_NAME}_{secrets.token_urlsafe(10)}")

SUPPORTED_OS       = "linux".split(" ")
RECOMENDED_DISTROS = "tails".split(" ")

CL_NORM   = "\033[0m"
CL_YELLOW = "\033[93m"
CL_GREEN  = "\033[92m"
CL_RED    = "\033[91m"
CL_GREY   = "\033[90m"

PKGS_NAME          = "Package name"
PKGS_COMMENT       = "Package comment"
PKGS_CHECK         = "Availability check cmd"
PKGS_TAILS_INSTALL = "Tails intalation commands"
PKGS_ISNTALL       = "Instalation commands"
PKGS = (
    {
        PKGS_NAME: "gnupg",
        PKGS_COMMENT: "GNU Privacy Guard",
        PKGS_CHECK: "gpg --version",
        PKGS_ISNTALL: {
            # Should be already installed in Tails
        },
    },
    {
        PKGS_NAME: "argon2",
        PKGS_COMMENT: "memory & CPU hard hash function",
        PKGS_CHECK: ("argon2 -h", 1),
        PKGS_ISNTALL: {
            "tails": "sudo apt -qq install -y argon2",
        },
    },
    {
        PKGS_NAME: "ykman",
        PKGS_COMMENT: "yubikey cli & gui manager",
        PKGS_CHECK: "ykman --help",
        PKGS_ISNTALL: {
            "tails": (
                "# Adding yubico maintaners GPG keys",
                "gpg --quiet --keyserver hkps://keys.openpgp.org --receive-keys 9E885C0302F9BB9167529C2D5CBA11E6ADC7BCD1",
                "gpg --quiet --keyserver hkps://keys.openpgp.org --receive-keys 57a9deed4c6d962a923bb691816f3ed99921835e",
                
                "# Download ykman AppImage",
                f"mkdir -p {TMP_DIR}/ykman",
                f"torsocks wget -c -t 0 --retry-connrefused --quiet --show-progress -O {TMP_DIR}/ykman/yubikey-manager-qt.AppImage https://developers.yubico.com/yubikey-manager-qt/Releases/yubikey-manager-qt-latest-linux.AppImage",
                f"torsocks wget -c -t 0 --retry-connrefused --quiet --show-progress -O {TMP_DIR}/ykman/yubikey-manager-qt.AppImage.sig https://developers.yubico.com/yubikey-manager-qt/Releases/yubikey-manager-qt-latest-linux.AppImage.sig",
                
                "# Verify downloaded image",
                f"gpg --quiet --verify {TMP_DIR}/ykman/yubikey-manager-qt.AppImage.sig",

                "# Make image executable",
                f"chmod +x {TMP_DIR}/ykman/yubikey-manager-qt.AppImage",

                "# Move image to /bin",
                f"sudo mv {TMP_DIR}/ykman/yubikey-manager-qt.AppImage /bin/ykman",
            ),
        },
    },
)

PRE_INSTALL = {
    "tails": "sudo apt -q update -y "
}
# Singleton
PRE_INSTALL_RUNNED = False

YES = "Yes"
NO = "No"
YES_OR_NO = f"'{CL_GREEN}{YES}{CL_NORM}' or '{CL_RED}{NO}{CL_NORM}'"

WRONG_OS_MSG = f"{CL_RED}Srry, your os is not currently supported by script{CL_NORM}"
RECOMMEND_OS_MSG = f"{CL_YELLOW}It is strongly recommended to use hardened OS distros to work with this script.\nSuch as {' or '.join(RECOMENDED_DISTROS)}.{CL_NORM}"
BEGIN_MSG = """
<< TODO BEGIN MSG >>
"""

def ask_continue():
    input(f"Press {CL_GREEN}Enter{CL_NORM} when you are ready: ")

def ask(prompt):
    while True:
        inp = input(prompt+f" ({YES_OR_NO}): ")
        if inp == YES:
            return True
        if inp == NO:
            return False
        print(f"\t{CL_YELLOW}Please type {YES_OR_NO}")

def ask_execute(cmds):
    if cmds is None:
        return True
    if isinstance(cmds, str):
        cmds = (cmds,)
    prompt = "Those commands will be executed:\n"
    for cmd in cmds:
        if cmd.lstrip().startswith("#"):
            prompt += f"\t{CL_GREY}{cmd}{CL_NORM}\n"
            continue
        if cmd.lstrip().startswith("sudo "):
            prompt += f"\t{CL_YELLOW}sudo{CL_NORM} {cmd.replace('sudo ', '', 1)}\n"
            continue
        prompt += f"\t{cmd}\n"
    prompt += "\nDo you want to execute them?"
    return ask(prompt)

# ( <Os type: linux/win/macos/etc >, <Distro name: debian/nixos/win11/etc> )
# ("linux", None) # Unknown linux disro
# ("linux", "whonix")
# ("win", "10")
@lru_cache(maxsize=None)
def get_os_info():
    system = platform.system().lower()
    version = platform.version()
    if system == "linux":
        if "Debian" in version:
            if os.path.isdir('/etc/tails') and os.path.isdir('/etc/amnesia') and os.getlogin() == "amnesia":
                return "linux", "tails"
        version = version.split("-")
        if len(version) < 2:
            return system, version[0]
        version = version[1].split(" ")[0]
    version = version.lower()
    return system, version

# (<status code>, <stdout if not interactive>, <sterr if not interactive>)
def run_cmd(cmd, interactive=True):
    if cmd is None:
        return 0, "", ""
    #cmd = shlex.split(cmd)
    out, err = "", ""
    stdout, stderr = None, None
    if not interactive:
        stdout, stderr = PIPE, PIPE
    with Popen(cmd, shell=True, stdout=stdout, stderr=stderr) as proc:
        code = proc.wait()
        if not interactive:
            out = proc.stdout.read()
            err = proc.stderr.read()
        return code, out, err

# returns status code
# 0 if all commands return 0
def run_cmds(cmds, interactive=True):
    if cmds is None:
        return 0
    if isinstance(cmds, str):
        cmds = (cmds,)
    for cmd in cmds:
        if cmd.strip().startswith("#"):
            continue
        code, _, _ = run_cmd(cmd, interactive)
        if code != 0:
            return code
    return 0

# Try to destroy file/dir using GNU Shred
# If failed for some reason (for example shred does not exist),
#   delete in the usual way.
def fs_del(path):
    if os.path.isdir(path):
        # Dir
        # Calls fs_del for all subentities
        for root, dirs, files in os.walk(path):
            for dr in dirs:
                fs_del(os.path.join(root, dr))
            for file in files:
                fs_del(os.path.join(root, file))
    else:
        # File
        # Try to shred
        run_cmd(f"shred -f -u -z {path}", False)
    # Regualr delete
    try:
        shutil.rmtree(path)
    except FileNotFoundError:
        pass # Already deleted

# In depend of istalled ykman disribution
#  there is may be two variants how to run it in cli:
# 1:
#   $ ykman ykman
#   If there is ykman-qt AppImage istalled
# 2:
#   $ ykman
#   If there is ykman cli installed by itself
# See https://github.com/Yubico/yubikey-manager-qt/pull/293
@lru_cache(maxsize=None)
def get_ykman_cmd():
    if run_cmd("ykman ykman", False) == 0:
        return "ykman ykman"
    return "ykman"

def chek_can_install(deps, distro):
    available, not_available = [], []
    for dep in deps:
        if distro in dep[PKGS_ISNTALL]:
            available.append(dep)
        else:
            not_available.append(dep)
    return available, not_available

def run_pre_install(distro):
    global PRE_INSTALL_RUNNED
    if PRE_INSTALL_RUNNED:
        return True
    PRE_INSTALL_RUNNED = True
    if distro not in PRE_INSTALL:
        return True # Nothing special shoud be done
    if not ask_execute(PRE_INSTALL[distro]):
        return False
    return run_cmds(PRE_INSTALL[distro]) == 0

def install_deps(distro, deps):
    commands = []
    for dep in deps:
        cmd = dep[PKGS_ISNTALL][distro]
        if isinstance(cmd, str):
            commands.append(cmd)
            continue
        commands += cmd
    if not ask_execute(commands):
        return False
    return run_cmds(commands) == 0

def check_deps():
    _, distro = get_os_info()
    recheck = False
    while True:
        to_install = []
        for pkg in PKGS:
            check_cmd, req_code = "", 0
            if isinstance(pkg[PKGS_CHECK], str):
                check_cmd = pkg[PKGS_CHECK]
            else:
                check_cmd = pkg[PKGS_CHECK][0]
                req_code  = pkg[PKGS_CHECK][1]
            code, _, _ = run_cmd(check_cmd, False)
            if code != req_code:
                to_install.append(pkg)
        if len(to_install) == 0:
            return True
        if not recheck:
            print("This script needs to instal those dependencies:")
            for pkg in to_install:
                print(f"\t{CL_GREEN}{pkg[PKGS_NAME]}{CL_NORM} ({pkg[PKGS_COMMENT]})")
            print(f"Press {CL_GREY}Ctrl+c{CL_NORM} to skip packages management {CL_GREY}at your own risk{CL_NORM}")
        recheck = False
        auto, manual = chek_can_install(to_install, distro)
        if len(manual) != 0:
            recheck = True
            if len(auto) == 0:
                print(f"They cannot be install automatically on current system")
            else:
                prompt = f"{CL_YELLOW}{' '.join(map(lambda pkg: pkg[PKGS_NAME], manual))}{CL_NORM}"
                print(f"Those packages cannot be install automatically on current system:\n\t{prompt}")
            print("Please install them manually before continue")
            ask_continue()
            continue
        print("They can be install automatically")
        if not ask("Do you want to install them?"):
            print("Please install them manually before continue")
            ask_continue()
            continue
        failed = False
        if not run_pre_install(distro):
            failed = True
        elif not install_deps(distro, auto):
            failed = True
        if failed:
            print(f"\n{CL_RED}Failed to install script dependencies{CL_NORM}")
            return False

def check_os():
    os, distro = get_os_info()
    if os not in SUPPORTED_OS:
        print(WRONG_OS_MSG)
        print(RECOMMEND_OS_MSG)
        return False
    if distro not in RECOMENDED_DISTROS:
        print(RECOMMEND_OS_MSG)
        return ask("Do your want to continue on current system")
    return True

# Yes, I know about tempfile.TemporaryDirectory
# I use custom analog cause I'm trying to destroy tmp files
#  more securely (using GNU Shred if available) 
@contextmanager
def tmp_dir():
    os.makedirs(TMP_DIR, mode=0o700)
    yield TMP_DIR
    fs_del(TMP_DIR)

def init():
    if not check_os(): return False
    # TODO Check that /tmp is inside tmpfs
    # TODO Check that there is no swaps except zram
    try:
        if not check_deps(): return False
    except KeyboardInterrupt:
        print(f"\n\n{CL_RED}Dependencies cheking interrupted by user{CL_NORM}")
        print(f"{CL_YELLOW}Continue without them. {CL_RED}It may cause problems{CL_NORM}\n")
    return True

def main():
    if not init(): return
    print(BEGIN_MSG)
    # TODO 

if __name__ == "__main__":
    with tmp_dir():
        try:
            main()
        except KeyboardInterrupt:
            print(f"\n{CL_RED}Interrupted by user{CL_NORM}")
    print("\nBye")
