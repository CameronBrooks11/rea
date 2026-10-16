import { spawn, type ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { parseConfig } from "../../../../src/config/parseConfig.js";
import { projectAnalysisError } from "../../../../src/domain/analysisErrorProjection.js";
import { elf } from "../../../../src/domain/binaryTarget.fixture.js";
import type { BinaryTarget } from "../../../../src/domain/binaryTargetTypes.js";
import { ok } from "../../../../src/domain/result.js";
import { GhidraClient } from "../../../../src/ghidra/GhidraClient.js";
import type { GhidraInstallationHost } from "../../../../src/ghidra/GhidraInstallation.js";
import type {
  GhidraLaunchSession,
  GhidraLauncher,
} from "../../../../src/ghidra/GhidraLauncher.js";
import { GhidraProvider } from "../../../../src/ghidra/GhidraProvider.js";
import { loopbackTransportLimitations } from "../../../../src/ghidra/GhidraProviderCapabilities.js";
import { silentLogger } from "../../../../src/logger.js";
import { createTestTempDirectory } from "../../../fixtures/temporaryDirectory.js";
import { waitForExit } from "../../../support/process/processFixture.js";

const fixturePath = fileURLToPath(
  new URL("../../../fixtures/fakeGhidra.mjs", import.meta.url),
);

const installationHost: GhidraInstallationHost = {
  platform: "linux",
  architecture: "x64",
  readText: () => "application.version=12.1.4\napplication.java.min=21\n",
  executable: () => true,
  probeJava: () => ({
    osArch: "amd64",
    osName: "Linux",
    version: "21.0.11",
    major: 21,
    home: "/fixture/jdk-21",
    bits: 64,
    runtime: "jdk",
  }),
};

/** Real child and socket; only the Java bridge itself is simulated. */
class FixtureLauncher implements GhidraLauncher {
  readonly endpointPaths: string[] = [];
  readonly processes: ChildProcess[] = [];
  readonly requests: string[] = [];

  async launch(session: GhidraLaunchSession) {
    this.endpointPaths.push(session.endpointPath);
    const projectRoot = join(session.runtimeRoot, "project");
    await mkdir(projectRoot, { recursive: true });
    const child = spawn(process.execPath, [fixturePath], {
      stdio: ["ignore", "pipe", "pipe", "ipc"],
      env: {
        ...process.env,
        REA_GHIDRA_FIXTURE_CONFIG: JSON.stringify({
          endpointPath: session.endpointPath,
          token: session.token,
          runId: session.runId,
          providerVersion: session.providerVersion,
          profileDigest: session.profileDigest,
          targetSha256: session.targetSha256,
          transport: session.transport,
        }),
      },
    });
    child.on("message", (value: unknown) => {
      if (
        typeof value === "object" &&
        value !== null &&
        "method" in value &&
        typeof value.method === "string"
      )
        this.requests.push(value.method);
    });
    this.processes.push(child);
    return ok({
      process: child,
      ownsProcessLifetime: true as const,
      projectRoot,
      ghidraLogPath: join(session.runtimeRoot, "ghidra.log"),
      scriptLogPath: join(session.runtimeRoot, "script.log"),
    });
  }
}

// Only installation discovery and the Java bridge are simulated. The provider
// client, private runtime, endpoint record and loopback socket are production.
describe.skipIf(process.platform === "win32")(
  "Ghidra bridge transport selection on a POSIX host",
  () => {
    it("serves the read-only session over authenticated loopback TCP when selected", async () => {
      const directory = await createTestTempDirectory("rea-ghidra-loopback-");
      const path = join(directory, "target.elf");
      const source = elf(2, 1, 62);
      await writeFile(path, source);
      const target: BinaryTarget = {
        path,
        sha256: createHash("sha256").update(source).digest("hex"),
        kind: "executable",
        format: "elf",
        architecture: "x86_64",
        availableArchitectures: ["x86_64"],
      };
      const config = parseConfig({
        GHIDRA_INSTALL_DIR: "/fixture/ghidra_12.1.4_PUBLIC",
        REA_GHIDRA_BRIDGE_TRANSPORT: "authenticated-loopback-tcp",
      });
      if (!config.ok) throw config.error;
      const launcher = new FixtureLauncher();
      const provider = new GhidraProvider(
        config.value,
        silentLogger,
        {},
        installationHost,
        (options) =>
          new GhidraClient({
            ...options,
            launcher,
            platform: process.platform,
            startupTimeoutMs: 5_000,
          }),
      );
      const resolved = await provider.resolveAnalysisProfile(target);
      if (!resolved.ok || resolved.value.profile === null)
        throw new Error("Expected a bound Ghidra profile");
      const client = provider.createClient(target, resolved.value.profile);
      try {
        const listed = await client.execute("list_procedures", {});
        if (!listed.ok)
          throw new Error(
            JSON.stringify(projectAnalysisError(listed.error), null, 1),
          );
        // The fixture reports read_only over loopback and omits the mutating
        // methods; the production handshake only completes when both match.
        expect(launcher.requests).toContain("list_procedures");
        expect(launcher.endpointPaths).toEqual([
          expect.stringMatching(/bridge-endpoint\.json$/u),
        ]);
        expect(listed.value.limitations).toEqual(
          expect.arrayContaining([...loopbackTransportLimitations]),
        );
      } finally {
        expect((await client.close()).ok).toBe(true);
        for (const child of launcher.processes) {
          if (child.exitCode === null && child.signalCode === null)
            child.kill("SIGTERM");
          expect(await waitForExit(child, 2_000)).toBe(true);
        }
      }
    });
  },
);
