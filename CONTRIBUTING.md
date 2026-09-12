# Contributing to LinkKeeper

This is a young project, fresh out of a private repo — help testing it on real setups is exactly
as valuable as code right now.

## Try it and tell me what broke

The single most useful thing you can do: run it on your own Windows machine with your own mix of
links (Ethernet, USB tether, Wi-Fi hotspot, Bluetooth) and [open an
issue](../../issues/new/choose) for anything that doesn't behave — a link that isn't detected, a
failover that's too slow/too fast, an Advisor tip that's wrong for your phone, a crash. Include:

- Windows version, Python version (`python --version`)
- What links you have configured and which one misbehaved
- `logs\linkkeeper.log` around the time of the issue (redact anything personal first)

## Ideas / feature requests

Open an issue, or start a [Discussion](../../discussions) if it's more of a "would this fit the
project" question than a concrete ask.

## Code contributions

- Stdlib-only Python — no new third-party dependencies without discussing first (the zero-dependency
  install is a deliberate design choice).
- Run `python -m unittest test_linkkeeper -v` before opening a PR — keep it green.
- Match the existing style: the codebase favors explicit, commented PowerShell/WinAPI calls over
  abstractions, since a lot of the value here is in documented Windows-specific workarounds.
- Small, focused PRs are much easier to review than large ones.

## Security

LinkKeeper changes network routing and Windows power settings on the machine it runs on, and its
dashboard binds to `127.0.0.1` only. If you find a security issue, please open an issue describing
it — there's no dedicated security contact yet, so a public issue is fine for now unless it's
actively exploitable, in which case flag that clearly in the title.

Thanks for even reading this far — every bit of testing on a setup I don't personally have helps.
