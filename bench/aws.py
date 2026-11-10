#!yeet
"""Run the published benchmarks on AWS EC2 spot instances and put their results in place:
`task bench-aws`.

The benchmarks are split into pieces of 10 to 20 minutes, each on a spot instance of its own, all
at once: the races (`task bench-race`), the HS256 by-size tables (`task bench-docker`), and the
full matrix (`task bench-matrix`) in two halves, 5 libraries each, each library on a core of its
own. The instances are spread over the region's availability zones, so a zone running short of
capacity hits only one piece. When AWS reclaims a piece's instance, only that piece runs again, on
a new one.

Each piece's results come back as soon as it finishes: the results files, and the pages and races
its task makes. The matrix page is made here, from both halves' results. Pages name the instance
type ($BENCH_MACHINE, read by compare.py), not the machine they're made on.

Uses the AWS CLI with the `ryjwt-benchmarks` profile, whose IAM policy allows only this: m9g.2xlarge
spot instances tagged Project=ryjwt, security groups with that tag, and key pairs named
`ryjwt-benchmarks*`. Each run makes its own key pair and security group (SSH from this machine's
IP only), and removes them, with every instance, when it ends, Ctrl-C included.

The instances benchmark a commit on GitHub (`--ref`, main by default), not the local checkout.
"""

import io
import json
import os
import re
import shlex
import shutil
import subprocess
import tarfile
import tempfile
import threading
import time
import urllib.request
from concurrent.futures import Future, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.markup import escape

ROOT = Path(__file__).parent.parent
REPO_URL = "https://github.com/RogerThomas/ryjwt.git"
NAME = "ryjwt-benchmarks"
"""The key pair and security group names' prefix, and the instances' Name tag."""
TAGS = [{"Key": "Project", "Value": "ryjwt"}]
# As .github/workflows/benchmarks.yml.
TASK_VERSION = "3.54.0"
UV_VERSION = "0.13.0"
COMPOSE_VERSION = "2.40.3"
BUILDX_VERSION = "0.29.1"
MATRIX_LIBRARIES = (
    "pyjwt",
    "joserfc",
    "ryjwt",
    "ryjwt-jiter",
    "ryjwt-msgspec",
    "ryjwt-pydantic",
    "jose",
    "fast-jwt",
    "jsonwebtoken",
    "jsonwebtoken-struct",
)
MATRIX_HALVES = (MATRIX_LIBRARIES[:5], MATRIX_LIBRARIES[5:])
RACE_SVGS = ("perf-race.svg", "perf-race-rs256.svg")
MINUTES_PER_PIECE = 25
"""About how long a piece's instance runs, setting up included: for the cost estimate."""
POLL_SECONDS = 30
CAPACITY_ERRORS = (
    "InsufficientInstanceCapacity",
    "MaxSpotInstanceCountExceeded",
    "VcpuLimitExceeded",
)
"""Errors launching an instance that another zone, or a later try, may not get."""
LAUNCH_PATIENCE = 15 * 60
"""Seconds a piece keeps trying to launch an instance."""

SETUP = f"""\
set -euxo pipefail
plugins=/usr/local/lib/docker/cli-plugins
sudo dnf install -y -q docker git gcc
sudo mkdir -p $plugins
sudo curl -fsSL -o $plugins/docker-compose \\
  https://github.com/docker/compose/releases/download/v{COMPOSE_VERSION}/docker-compose-linux-aarch64
sudo curl -fsSL -o $plugins/docker-buildx \\
  https://github.com/docker/buildx/releases/download/v{BUILDX_VERSION}/buildx-v{BUILDX_VERSION}.linux-arm64
sudo chmod +x $plugins/docker-compose $plugins/docker-buildx
# Docker Hub limits anonymous pulls per IP address: pull through Google's mirror of it, as
# benchmarks.yml does.
echo '{{"registry-mirrors": ["https://mirror.gcr.io"]}}' | sudo tee /etc/docker/daemon.json
sudo systemctl enable --now docker
sudo usermod -aG docker ec2-user
curl -LsSf https://astral.sh/uv/{UV_VERSION}/install.sh | sh
curl -fsSL https://taskfile.dev/install.sh | sudo sh -s -- -d -b /usr/local/bin v{TASK_VERSION}
curl -fsSL https://sh.rustup.rs | sh -s -- -y -q --profile minimal --default-toolchain none
export PATH=$HOME/.cargo/bin:$HOME/.local/bin:$PATH
git clone -q {REPO_URL} ryjwt
cd ryjwt
git checkout -q "$1"
rustup toolchain install
# The pages and races are made with `uv run`, which builds ryjwt: built now, not after timing.
uv sync --locked --group bench
"""

console = Console(highlight=False)


class AwsError(Exception):
    pass


class ReclaimedError(Exception):
    """AWS took the instance back (a spot interruption)."""


class StoppedError(Exception):
    """The run is being stopped (Ctrl-C, or another piece failed to start)."""


def _tool(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        raise SystemExit(f"{name} isn't on PATH")
    return path


@dataclass(frozen=True, slots=True)
class Aws:
    profile: str
    region: str
    cli: str = field(default_factory=lambda: _tool("aws"))

    def __call__(self, *args: str) -> Any:  # noqa: ANN401 - the CLI's JSON
        command = [self.cli, "--profile", self.profile, "--region", self.region, "--output", "json"]
        done = subprocess.run([*command, *args], capture_output=True, text=True, check=False)
        if done.returncode != 0:
            raise AwsError(done.stderr.strip())
        return json.loads(done.stdout) if done.stdout.strip() else None


@dataclass(frozen=True, slots=True)
class Piece:
    name: str
    command: str
    """Run on the instance, in the clone."""
    outputs: tuple[str, ...]
    """What it writes that's brought back, relative to the repo's root."""


def _pieces() -> list[Piece]:
    matrix = [
        Piece(
            f"matrix-{i}",
            f"MATRIX_JOBS={len(half)} MATRIX_SERVICES="
            + shlex.quote(" ".join(f"matrix-{library}" for library in half))
            + " task bench-matrix",
            tuple(f"bench/results-matrix/{library}.json" for library in half),
        )
        for i, half in enumerate(MATRIX_HALVES, 1)
    ]
    races = tuple(f"{assets}/{svg}" for assets in ("assets", "docs/assets") for svg in RACE_SVGS)
    return [
        Piece("race", "task bench-race", ("bench/results-race", "bench/results-race.md", *races)),
        Piece("docker", "task bench-docker", ("bench/results-docker", "bench/results-docker.md")),
        *matrix,
    ]


@dataclass(slots=True)
class Run:
    aws: Aws
    instance_type: str
    machine: str
    sha: str
    attempts: int
    workdir: Path
    """Holds the run's SSH key, known hosts and the pieces' logs."""
    image: str = ""
    zones: list[tuple[str, str]] = field(default_factory=list)
    """(zone, default subnet), cheapest first."""
    group: str = ""
    key: str = ""
    launched: set[str] = field(default_factory=set)
    live: set[str] = field(default_factory=set)
    lock: threading.Lock = field(default_factory=threading.Lock)
    stopping: threading.Event = field(default_factory=threading.Event)
    ssh: str = field(default_factory=lambda: _tool("ssh"))

    def say(self, piece: str, message: str) -> None:
        console.print(f"[bold]{piece:>8}[/] {message}")

    # Setting up and tearing down the run's resources.

    def prepare(self, prices: dict[str, float]) -> None:
        stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
        self.key = f"{NAME}-{stamp}"
        key_file = self.workdir / "key"
        keygen = [_tool("ssh-keygen"), "-q", "-t", "ed25519", "-N", "", "-C", self.key]
        subprocess.run([*keygen, "-f", str(key_file)], check=True)
        self.aws(
            "ec2", "import-key-pair", "--key-name", self.key,
            "--public-key-material", f"fileb://{key_file}.pub",
            "--tag-specifications", _tags("key-pair"),
        )  # fmt: skip
        subnets = self.aws(
            "ec2", "describe-subnets", "--filters", "Name=default-for-az,Values=true"
        )
        by_zone = {s["AvailabilityZone"]: s for s in subnets["Subnets"]}
        if not by_zone:
            raise SystemExit(f"{self.aws.region} has no default VPC")
        self.zones = sorted(
            ((zone, s["SubnetId"]) for zone, s in by_zone.items() if zone in prices),
            key=lambda zs: prices[zs[0]],
        )
        vpc = next(iter(by_zone.values()))["VpcId"]
        self.group = self.aws(
            "ec2", "create-security-group", "--group-name", self.key, "--vpc-id", vpc,
            "--description", "ryjwt benchmarks: SSH from the machine running task bench-aws",
            "--tag-specifications", _tags("security-group"),
        )["GroupId"]  # fmt: skip
        with urllib.request.urlopen("https://checkip.amazonaws.com", timeout=10) as response:
            ip = response.read().decode().strip()
        self.aws(
            "ec2", "authorize-security-group-ingress", "--group-id", self.group,
            "--protocol", "tcp", "--port", "22", "--cidr", f"{ip}/32",
        )  # fmt: skip
        self.image = self.aws(
            "ec2", "describe-images", "--owners", "amazon",
            "--filters", "Name=name,Values=al2023-ami-2023.*-kernel-*-arm64",
            "Name=state,Values=available",
            "--query", "sort_by(Images, &CreationDate)[-1].ImageId",
        )  # fmt: skip

    def terminate_live(self) -> None:
        with self.lock:
            live = sorted(self.live)
        if live:
            self.aws("ec2", "terminate-instances", "--instance-ids", *live)

    def tear_down(self) -> None:
        """Terminates every instance the run launched, then removes its security group and key
        pair; says what's left if any of it fails."""
        with self.lock:
            launched = sorted(self.launched)
        try:
            self.terminate_live()
            if launched:
                console.print(f"Waiting for {len(launched)} instances to terminate")
                self.aws("ec2", "wait", "instance-terminated", "--instance-ids", *launched)
            if self.group:
                self.aws("ec2", "delete-security-group", "--group-id", self.group)
            if self.key:
                self.aws("ec2", "delete-key-pair", "--key-name", self.key)
        except AwsError as e:
            console.print(f"[red]Tearing down failed: {escape(str(e))}[/]")
            console.print(f"Check instances {launched}, group {self.group}, key pair {self.key}")
            raise
        console.print("Torn down: no instances, security group or key pair left")

    # A piece, on one instance after another until it isn't reclaimed.

    def run_piece(self, piece: Piece, first_zone: int) -> None:
        for attempt in range(self.attempts):
            instance = self._launch(piece, first_zone + attempt)
            try:
                ip = self._running(instance)
                self._setup(piece, instance, ip)
                self._bench(piece, instance, ip, attempt)
                self._fetch(piece, instance, ip)
            except ReclaimedError:
                self.say(
                    piece.name, "[yellow]reclaimed by AWS: starting again on a new instance[/]"
                )
                continue
            finally:
                self._terminate(instance)
            return
        raise RuntimeError(f"{piece.name}: reclaimed {self.attempts} times; giving up")

    def _launch(self, piece: Piece, first_zone: int) -> str:
        deadline = time.monotonic() + LAUNCH_PATIENCE
        tries = 0
        while True:
            zone, subnet = self.zones[(first_zone + tries) % len(self.zones)]
            tries += 1
            if self.stopping.is_set():
                raise StoppedError
            try:
                instance = self._run_instance(piece, subnet)
            except AwsError as e:
                if not any(code in str(e) for code in CAPACITY_ERRORS):
                    raise
                if time.monotonic() > deadline:
                    raise RuntimeError(f"{piece.name}: no capacity for {LAUNCH_PATIENCE}s") from e
                self.say(piece.name, f"no capacity in {zone}: trying the next zone")
                if tries % len(self.zones) == 0:
                    self.stopping.wait(60)
                continue
            self.say(piece.name, f"launched {instance} in {zone}")
            return instance

    def _running(self, instance: str) -> str:
        """Waits for the instance to be running; its public IP address."""
        try:
            self.aws("ec2", "wait", "instance-running", "--instance-ids", instance)
        except AwsError:
            self._check_running(instance)
            raise
        return self._describe(instance)["PublicIpAddress"]

    def _check_running(self, instance: str) -> None:
        """Raises ReclaimedError if AWS took the instance back, or RuntimeError if it's otherwise
        not running."""
        state = self._describe(instance)
        if state["State"]["Name"] != "running":
            reason = state.get("StateReason", {}).get("Code", "")
            if reason == "Server.SpotInstanceTermination":
                raise ReclaimedError
            raise RuntimeError(f"{instance} is {state['State']['Name']} ({reason})")

    def _run_instance(self, piece: Piece, subnet: str) -> str:
        spot = {"SpotInstanceType": "one-time", "InstanceInterruptionBehavior": "terminate"}
        disk = {"VolumeSize": 30, "VolumeType": "gp3", "DeleteOnTermination": True}
        interface = {
            "DeviceIndex": 0,
            "SubnetId": subnet,
            "Groups": [self.group],
            "AssociatePublicIpAddress": True,
        }
        instance: str = self.aws(
            "ec2", "run-instances", "--image-id", self.image, "--instance-type", self.instance_type,
            "--count", "1", "--key-name", self.key,
            "--instance-market-options", json.dumps({"MarketType": "spot", "SpotOptions": spot}),
            "--network-interfaces", json.dumps([interface]),
            "--block-device-mappings", json.dumps([{"DeviceName": "/dev/xvda", "Ebs": disk}]),
            "--tag-specifications",
            _tags("instance", {"Key": "Name", "Value": f"{NAME}-{piece.name}"}),
            _tags("volume"),
            "--query", "Instances[0].InstanceId",
        )  # fmt: skip
        with self.lock:
            self.launched.add(instance)
            self.live.add(instance)
        return instance

    def _terminate(self, instance: str) -> None:
        with self.lock:
            self.live.discard(instance)
        self.aws("ec2", "terminate-instances", "--instance-ids", instance)

    def _describe(self, instance: str) -> dict[str, Any]:
        found = self.aws("ec2", "describe-instances", "--instance-ids", instance)
        return found["Reservations"][0]["Instances"][0]

    def _remote(
        self, instance: str, ip: str, command: str, *, stdin: str = "", timeout: int = 120
    ) -> subprocess.CompletedProcess[bytes]:
        """Runs `command` on the instance over SSH. If SSH can't reach it, raises ReclaimedError
        when AWS took it back, and returns the failure when it's still running."""
        options = [
            "-i", str(self.workdir / "key"),
            "-o", f"UserKnownHostsFile={self.workdir / f'known_hosts-{instance}'}",
            "-o", "StrictHostKeyChecking=accept-new", "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=15", "-o", "ServerAliveInterval=15", "-o", "LogLevel=ERROR",
        ]  # fmt: skip
        try:
            done = subprocess.run(
                [self.ssh, *options, f"ec2-user@{ip}", command],
                input=stdin.encode(),
                capture_output=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            done = subprocess.CompletedProcess([], 255, b"", b"timed out")
        if done.returncode == 255:  # SSH's own failure
            self._check_running(instance)
        return done

    def _setup(self, piece: Piece, instance: str, ip: str) -> None:
        for _ in range(20):  # sshd takes a little while after the instance is running
            if self._remote(instance, ip, "true").returncode == 0:
                break
            if self.stopping.wait(10):
                raise StoppedError
        self.say(piece.name, "setting up: Docker, uv, Task, Rust, the clone, the bench venv")
        done = self._remote(instance, ip, f"bash -s -- {self.sha}", stdin=SETUP, timeout=20 * 60)
        if done.returncode != 0:
            tail = done.stderr.decode(errors="replace").splitlines()[-20:]
            raise RuntimeError(f"{piece.name}: setup failed:\n" + "\n".join(tail))

    def _bench(self, piece: Piece, instance: str, ip: str, attempt: int) -> None:
        """Starts the piece's task as a systemd unit, so it outlives the SSH session, and follows
        it until it ends."""
        home = "/home/ec2-user"
        # A file, not `bash -c`: systemd would expand the `$` in the unit's command line.
        script = f"{piece.command} > {home}/bench.log 2>&1\necho $? > {home}/bench.exit\n"
        if self._remote(instance, ip, "cat > bench.sh", stdin=script).returncode != 0:
            raise RuntimeError(f"{piece.name}: couldn't write bench.sh")
        unit = [
            "sudo", "systemd-run", "--quiet", "--unit=ryjwt-bench", "--uid=ec2-user",
            f"--working-directory={home}/ryjwt", f"--setenv=HOME={home}",
            f"--setenv=PATH={home}/.cargo/bin:{home}/.local/bin:/usr/local/bin:/usr/bin:/bin",
            f"--setenv=BENCH_MACHINE={self.machine}", "bash", f"{home}/bench.sh",
        ]  # fmt: skip
        if self._remote(instance, ip, shlex.join(unit)).returncode != 0:
            raise RuntimeError(f"{piece.name}: couldn't start the benchmarks")
        self.say(piece.name, f"benchmarking: {piece.command}")
        progress = "grep -a -E '^(──── |task: )' bench.log || true; echo @@; cat bench.exit || true"
        shown, exit_code = 0, ""
        while not self.stopping.wait(POLL_SECONDS):
            done = self._remote(instance, ip, progress)
            if done.returncode != 0:
                continue
            lines, _, exit_code = done.stdout.decode(errors="replace").partition("@@\n")
            for line in lines.splitlines()[shown:]:
                self.say(piece.name, escape(line))
                shown += 1
            if exit_code.strip():
                break
        else:
            raise StoppedError
        log = self.workdir / f"{piece.name}-{attempt + 1}.log"
        log.write_bytes(self._remote(instance, ip, "cat bench.log", timeout=300).stdout)
        if exit_code.strip() != "0":
            raise RuntimeError(f"{piece.name} failed (exit {exit_code.strip()}); log: {log}")

    def _fetch(self, piece: Piece, instance: str, ip: str) -> None:
        paths = shlex.join(piece.outputs)
        done = self._remote(instance, ip, f"tar -C ryjwt -cf - -- {paths}", timeout=300)
        if done.returncode != 0:
            raise RuntimeError(f"{piece.name}: fetching the results failed: {done.stderr!r}")
        with tarfile.open(fileobj=io.BytesIO(done.stdout)) as tar:
            tar.extractall(ROOT, filter="data")
        self.say(piece.name, f"[green]done[/]: {', '.join(piece.outputs)}")


def _tags(resource: str, *extra: dict[str, str]) -> str:
    return json.dumps({"ResourceType": resource, "Tags": [*TAGS, *extra]})


def _commit(ref: str) -> str:
    """The commit `ref` (a branch, tag or SHA) is on GitHub."""
    listed = subprocess.run(
        [_tool("git"), "ls-remote", REPO_URL, ref], capture_output=True, text=True, check=True
    ).stdout.split()
    if listed:
        return listed[0]
    if re.fullmatch(r"[0-9a-f]{40}", ref):
        return ref
    raise SystemExit(f"{ref} isn't a branch or tag on GitHub, or a full commit SHA")


def _spot_prices(aws: Aws, instance_type: str) -> dict[str, float]:
    """The current spot price per zone, in USD an hour."""
    history = aws(
        "ec2", "describe-spot-price-history", "--instance-types", instance_type,
        "--product-descriptions", "Linux/UNIX", "--start-time", datetime.now(UTC).isoformat(),
    )["SpotPriceHistory"]  # fmt: skip
    return {h["AvailabilityZone"]: float(h["SpotPrice"]) for h in history}


def _matrix_page(machine: str) -> None:
    note = (
        "Run in Docker, one container per library, on two instances, up to 5 at once on each, "
        "each limited to 1 CPU (pinned, a core of its own) and 500 MB with no swap; the JWKS "
        "server runs in a container of its own on each, outside that limit. Each case gets 1,000 "
        "untimed decodes, then 10,000 timed."
    )
    subprocess.run(
        [
            _tool("uv"),
            "run",
            "--group",
            "bench",
            "yeet",
            "./compare.py:matrix",
            "results-matrix",
            note,
        ],
        cwd=ROOT / "bench",
        env={**os.environ, "BENCH_MACHINE": machine},
        check=True,
    )


def _run_pieces(run: Run, pieces: list[Piece]) -> list[str]:
    """Runs every piece at once, each starting from a different zone; the pieces that failed."""
    failed: list[str] = []
    with ThreadPoolExecutor(len(pieces)) as pool:
        futures: dict[Future[None], Piece] = {
            pool.submit(run.run_piece, piece, i): piece for i, piece in enumerate(pieces)
        }
        try:
            wait(futures)
        except KeyboardInterrupt:
            console.print("[yellow]Stopping: terminating the instances[/]")
            run.stopping.set()
            run.terminate_live()  # their SSH sessions then fail, and the pieces stop
            wait(futures)
        for future, piece in futures.items():
            if (error := future.exception()) is not None:
                if not isinstance(error, StoppedError):
                    run.say(piece.name, f"[red]failed: {escape(str(error))}[/]")
                failed.append(piece.name)
    return failed


def main(
    *,
    ref: str = "main",
    profile: str = NAME,
    region: str = "eu-west-1",
    instance_type: str = "m9g.2xlarge",
    cpu: str = "Graviton5",
    attempts: int = 3,
    yes: bool = False,
) -> None:
    """Benchmark `ref` on AWS spot instances, a piece on each, and put the results in place.

    `cpu` names the instance type's CPU on the pages (lscpu doesn't); `attempts` is how many
    instances a piece gets before it gives up, when AWS keeps reclaiming them; `yes` launches
    without asking.
    """
    aws = Aws(profile, region)
    sha = _commit(ref)
    pieces = _pieces()
    prices = _spot_prices(aws, instance_type)
    if not prices:
        raise SystemExit(f"No spot price for {instance_type} in {region}")
    console.print(f"Benchmarking {REPO_URL} at {sha} ({ref})")
    console.print(f"{len(pieces)} {instance_type} spot instances in {region}, USD an hour now:")
    for zone, price in sorted(prices.items(), key=lambda zp: zp[1]):
        console.print(f"  {zone}: {price:.4f}")
    estimate = len(pieces) * MINUTES_PER_PIECE / 60 * max(prices.values())
    console.print(
        f"About {MINUTES_PER_PIECE} minutes; at most about ${estimate:.2f} unless reclaimed"
    )
    if not yes and console.input("Launch? [y/N] ").strip().lower() != "y":
        return
    machine = f"AWS {instance_type}, {cpu} (aarch64), Linux"
    workdir = tempfile.mkdtemp(prefix="ryjwt-bench-aws-")
    run = Run(aws, instance_type, machine, sha, attempts, Path(workdir))
    try:
        run.prepare(prices)
        failed = _run_pieces(run, pieces)
    finally:
        run.tear_down()
    console.print(f"Logs: {workdir}")
    if not any(name.startswith("matrix-") for name in failed):
        _matrix_page(machine)
    if failed:
        raise SystemExit(f"Failed: {', '.join(failed)}; the other pieces' results are in place")
