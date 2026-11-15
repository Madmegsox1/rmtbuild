# rmtbuild

`rmtbuild` syncs the git-tracked files in the current repository to a build machine and runs a named command there. The build machine runs `rmtbuild serve`. Output streams back, and selected server ports are forwarded to `127.0.0.1` on your machine for as long as the command runs.

The connection is authenticated with a shared key. It is not encrypted; run it over a VPN or another trusted network.

## Build

Requires Zig 0.16.

```sh
zig build
zig build test
```

The binary is `zig-out/bin/rmtbuild`. `zig build -Dtarget=x86_64-windows` cross-compiles a Windows server or client.

## Commands

```text
rmtbuild keygen [--force]                  create the shared key
rmtbuild serve [--listen ADDR] [--port N]  serve the git repo in the current directory
rmtbuild <command>                         sync, then run <command> from rmtbuild.yaml
rmtbuild help
```

`keygen` writes `$XDG_CONFIG_HOME/rmtbuild/key`, or `~/.config/rmtbuild/key`, or `%APPDATA%\rmtbuild\key`. Copy that file to the same path on the other machine (`chmod 600` on Unix). `RMTBUILD_KEY` (64 hex characters) overrides the file.

`serve` must be started in a git checkout. It only syncs tracked files, so new files need `git add` before they are sent. Untracked build output stays on the server.

## Config

`rmtbuild.yaml` in the repo root (it has to be tracked, the server reads its own synced copy):

```yaml
server:
  address: 192.168.1.20   # client connects here
  port: 8099
  listen: 0.0.0.0         # serve bind address, default 127.0.0.1
  max_payload_mb: 256
commands:
  build:
    run: zig build
  web:
    run: zig build run
    forward: 8080          # or "8080, 3000", or "8081:8080" (local:remote)
```

`run` is a script: `sh -c` on a POSIX server, a `.cmd` batch file on Windows (`%%i` in `for` loops, `exit /b N`). `forward` publishes server localhost ports on the client's localhost while the command runs.

Command names `serve`, `keygen`, and `help` are reserved.

## Debugging .NET Framework

.NET Framework debugging only works when the server is Windows. The debugger that attaches has to run on that machine: the desktop CLR does not speak a remote debug protocol of its own.

`debug` on a command starts that helper and, when it listens on a TCP port, forwards the port the same way `forward` does.

```yaml
commands:
  framework:
    run: |
      msbuild App.csproj /p:Configuration=Debug
      bin\Debug\App.exe
    debug:
      mode: rider          # rider (default integration) | msvsmon | mdbg
      port: 7777           # server port; default 7777 for rider, 4026 for msvsmon
      local: 7777          # client port; default is the same as port
      agent: C:\Tools\jetbrains_debugger_agent.exe
      start: true          # false: something is already listening (OpenSSH)
```

`debug: rider` is the short form of `mode: rider` with the default port.

`run` has to leave the process running (the exe is the foreground of the script). The helper is stopped when the command ends. For `mdbg`, `run` is the build and must exit 0; `program` is what MDbg launches.

While `mode` is `rider` or `msvsmon`, the script is started with `RMTBUILD_DEBUG_WAIT=1`. Wait on it so the process is still at the top of `Main` when the debugger attaches:

```csharp
#if DEBUG
if (Environment.GetEnvironmentVariable("RMTBUILD_DEBUG_WAIT") == "1")
{
    Console.WriteLine("rmtbuild: pid {0} waiting for a debugger",
        System.Diagnostics.Process.GetCurrentProcess().Id);
    while (!System.Diagnostics.Debugger.IsAttached)
        System.Threading.Thread.Sleep(200);
    System.Diagnostics.Debugger.Break();
}
#endif
```

Build the Debug configuration so a PDB is written next to the exe on the server. The debugger reads that PDB on the server. Paths inside it are the server's paths; map them onto the local checkout if breakpoints stay hollow (Rider: the path mapping prompt, or Settings, Build, Execution, Deployment, Debugger).

### rider

This is the mode to use with JetBrains Rider. Rider attaches to a remote .NET Framework process over SSH, then uploads its own debugger and talks to the CLR on the Windows machine. It does not attach to msvsmon, and stock `netcoredbg` does not debug the desktop CLR.

On the server, download the JetBrains SSH debug agent (the build linked from Rider's [SSH remote debugging](https://www.jetbrains.com/help/rider/SSH_Remote_Debugging.html) page) and point `agent` at it, or set `RMTBUILD_RIDER_AGENT`:

```text
https://download.jetbrains.com/rider/ssh-remote-debugging/windows-x64/jetbrains_debugger_agent_20240726.40.0.exe
```

That filename is the one current Rider docs link. A newer Rider may want a newer agent; use the link in the docs for the version you run.

rmtbuild starts it with `-port=<port>`, reads the `Login` / `Password` / `Port` banner, and prints where to point Rider. The first attach uploads Rider's remote debugger tools onto the server; that is Rider, not rmtbuild.

The agent picks its own password and may listen on every interface. Connect through the forwarded `127.0.0.1` port and leave the Windows firewall closed for that port.

`start: false` does not launch an agent. It forwards `port` (for example `22`) to the client so Rider can use the Windows OpenSSH server you already run. Authenticate with that SSH account; there is no generated password.

```yaml
debug:
  mode: rider
  port: 22
  start: false
```

### msvsmon

Visual Studio's remote debugger. Rider cannot connect to it.

`agent` is `msvsmon.exe` from the Visual Studio Remote Tools (or `RMTBUILD_MSVSMON`). rmtbuild starts it as:

```text
msvsmon.exe /noauth /anyuser /nosecuritywarn /silent /hostname 127.0.0.1 /port:<port>
```

`/hostname 127.0.0.1` keeps the unauthenticated listener off the network. The only client is the rmtbuild forward. Do not open the port in the Windows firewall.

In Visual Studio: Debug, Attach to Process, connection type Remote (no authentication), target `127.0.0.1:<local port>`.

### mdbg

Fallback with no IDE. [MDbg](https://learn.microsoft.com/en-us/dotnet/framework/tools/mdbg-exe) is the .NET Framework command-line debugger (`MDbg.exe` on `PATH`, or `debug.agent`, or `RMTBUILD_MDBG`).

```yaml
debug:
  mode: mdbg
  agent: C:\Tools\MDbg.exe
  program: bin\Debug\App.exe
  args: --one "two words"
```

`run` (the build) runs first. If it exits 0, rmtbuild starts `MDbg.exe <program> <args>` and copies your terminal stdin to it. `help`, `break`, `go`, `next`, `out`, `print`, `quit`. Ctrl-D ends the session.

`program` and `args` are only valid for `mdbg`. `args` is split on whitespace, with `'...'` and `"..."` quotes.

## Manual test with Rider

These steps need a Windows machine with .NET Framework build tools and a developer machine with Rider. They were not run in the environment that added this feature (Linux, no Rider, no desktop CLR). What was run there is `zig build test` and `zig build -Dtarget=x86_64-windows`.

1. On the Windows build machine, install the .NET Framework targeting pack / MSBuild, and put `jetbrains_debugger_agent.exe` somewhere stable.
2. `rmtbuild keygen` on one machine, copy the key to the other, `chmod 600` it on Unix.
3. In a git checkout of a small C# console project (the wait snippet above in `Main`, a `Debug` build, a PDB next to the exe):

   ```yaml
   server:
     address: 127.0.0.1
     port: 8099
     listen: 127.0.0.1
   commands:
     framework:
       run: |
         msbuild App.csproj /p:Configuration=Debug
         bin\Debug\App.exe
       debug:
         mode: rider
         port: 7777
         agent: C:\Tools\jetbrains_debugger_agent.exe
   ```

   Use the Windows machine's address in `server.address` when the client is a different computer. Track `rmtbuild.yaml` (`git add`).
4. On Windows, in that checkout: `rmtbuild serve --listen 0.0.0.0 --port 8099`.
5. On the developer machine, in a checkout of the same repo: `rmtbuild framework`.
6. Wait until rmtbuild prints `JetBrains debugger agent is forwarded to 127.0.0.1:7777` with a user and password, and the app prints `rmtbuild: pid N waiting for a debugger`.
7. In Rider, open the same project. Run, Attach to Remote Process. Add an SSH configuration:
   - Host `127.0.0.1`
   - Port `7777` (or whatever `local` you set)
   - Authentication: password, the user and password from the rmtbuild banner
8. Accept the upload of remote debugger tools if Rider asks. Attach to the process with that pid (or the exe name).
9. `Debugger.Break()` should stop in `Main`. Set a breakpoint on the next line, continue, and confirm it binds. If it stays hollow, add a path mapping from the Windows repo path in the PDB to your local checkout.
10. Stop the debug session in Rider (the process keeps running). Stop `rmtbuild framework` with Ctrl-C; the app and the agent should exit with it.
11. Optional: repeat with `mode: msvsmon` and Visual Studio's Attach to Process, and with `mode: mdbg` (`run` is only the build, `program` is the exe) and type `break` / `go` / `quit` in the rmtbuild terminal.
