"""Exercise the compiled CLI prompt host with synthetic input on an actual PTY."""

import json
import os
import pty
import select
import subprocess
import sys
import tempfile
import termios
import time
from pathlib import Path
from urllib.parse import unquote, urlparse


def check(scenario, module, directory):
    master, slave = pty.openpty()
    before = termios.tcgetattr(slave)
    script = "import { secretPrompt, cliPromptSession } from " + json.dumps(module) + ";"
    if scenario == "challenge":
        script += "const { answerLoginChallenge } = await import(new URL('./auth-input.js', " + json.dumps(module) + "));"
        script += """
let deliveries = 0;
const answer = await answerLoginChallenge({ providers: [0, 1], requestEmail: async () => { deliveries++; } });
if (deliveries !== 1 || answer.provider !== 1 || answer.token !== '123456') process.exitCode = 1;
process.stdout.write('DONE');
"""
        steps = [(b"Two-factor method", b"2\n", False), (b"Verification code:", b"123456\r", True)]
    elif scenario == "sequential":
        script += """
const visible = await cliPromptSession().ask({ kind: 'input', message: 'Synthetic account:', trim: true });
const first = await secretPrompt('First hidden entry:');
const second = await secretPrompt('Second hidden entry:');
if (visible !== 'account' || first !== '  synthetic-secret  ' || second !== 'second-synthetic-value') process.exitCode = 1;
process.stdout.write('DONE');
"""
        steps = [
            (b"Synthetic account:", b"account\n", False),
            (b"First hidden entry:", b"  synthetic-secrex\x7ft  \r", True),
            (b"Second hidden entry:", b"second-synthetic-value\r", True),
        ]
    else:
        script += """
try {
    const value = await secretPrompt('Hidden entry:');
    if (value !== '  synthetic-secret  ') process.exitCode = 1;
    process.stdout.write('DONE');
} catch (error) {
    process.exitCode = error.exitCode ?? 1;
    process.stdout.write('CANCELLED');
}
"""
        steps = [(b"Hidden entry:", b"\x03" if scenario == "interrupt" else b"  synthetic-secret  \r", True)]
    environment = {"PATH": os.environ["PATH"]}
    command = ["node", "--input-type=module", "-e", script]
    if scenario == "cli_interrupt":
        cli = str(Path(unquote(urlparse(module).path)).with_name("main.js"))
        environment["VW_APPDATA_DIR"] = directory
        configured = subprocess.run(["node", cli, "config", "server", "https://example.com"], env=environment, capture_output=True)
        if configured.returncode != 0:
            raise RuntimeError("Could not configure synthetic cancellation profile")
        command = ["node", cli, "login", "fixture@example.com"]
        steps = [(b"Master password:", b"\x03", True)]
    child = subprocess.Popen(command, stdin=slave, stdout=slave, stderr=slave, env=environment)
    output = b""
    index = 0
    deadline = time.monotonic() + 7
    try:
        while time.monotonic() < deadline and child.poll() is None:
            ready, _, _ = select.select([master], [], [], 0.05)
            if ready:
                try:
                    output += os.read(master, 4096)
                except OSError:
                    break
            if index < len(steps):
                marker, answer, hidden = steps[index]
                echo = bool(termios.tcgetattr(slave)[3] & termios.ECHO)
                if marker in output and (not hidden or not echo):
                    os.write(master, answer)
                    index += 1
        if child.poll() is None:
            raise RuntimeError("Prompt child did not finish")
        if index != len(steps):
            raise RuntimeError("Expected prompt did not become ready")
        if b"synthetic-secret" in output or b"second-synthetic-value" in output or b"123456" in output:
            raise RuntimeError("Secret appeared in terminal output")
        after = termios.tcgetattr(slave)
        mask = termios.ECHO | termios.ICANON
        if before[3] & mask != after[3] & mask:
            raise RuntimeError("Terminal echo/canonical modes were not restored")
        if child.returncode != (130 if scenario in ("interrupt", "cli_interrupt") else 0):
            raise RuntimeError("Unexpected prompt child exit code")
        if scenario == "cli_interrupt":
            status = subprocess.run(["node", cli, "status"], env=environment, capture_output=True, text=True)
            if status.returncode != 0 or json.loads(status.stdout)["status"] != "unauthenticated":
                raise RuntimeError("Cancelled CLI login retained an authenticated account")
        return True
    finally:
        if child.poll() is None:
            child.kill()
            child.wait()
        os.close(master)
        os.close(slave)


with tempfile.TemporaryDirectory(prefix="vw-prompt-cancel-") as directory:
    print(json.dumps({scenario: check(scenario, sys.argv[1], directory) for scenario in ("answer", "interrupt", "sequential", "challenge", "cli_interrupt")}))
