import { randomBytes } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { loadWalletConfig } from './config.mjs';
import { createWalletServer } from './http.mjs';
import { WalletNetwork } from './network.mjs';
import { AgentHandoff } from './agent-handoff.mjs';
import { WalletSession } from './session.mjs';
import { WalletToolchain } from './toolchain.mjs';

// WebAuthn requires a domain RP ID: Chrome refuses registration on 127.0.0.1.
// Listeners still bind only the IPv4 loopback interface.
const ORIGIN = 'http://localhost:3000';
const BACKEND_HOST = '127.0.0.1';
const BACKEND_PORT = 4317;

/** Assemble trusted local components without invoking any network method or executable. */
export async function createWalletRuntime(configPath, { actionsFactory } = {}) {
  const config = loadWalletConfig(configPath);
  const secret = randomBytes(32).toString('hex');
  const session = new WalletSession({ origin: ORIGIN, host: 'localhost:3000', secret });
  const toolchain = new WalletToolchain(config);
  const journalRoot = join(toolchain.sessionRoot, 'journal');
  mkdirSync(journalRoot, { mode: 0o700 });
  const network = new WalletNetwork({ rpcUrl: config.rpcUrl, journalRoot });
  const createActions = actionsFactory ?? (await import('./actions.mjs')).createWalletActions;
  const native = config.nativeExecutable ? Object.freeze({ executable: config.nativeExecutable }) : null;
  const live = config.liveHelper ? Object.freeze({ helper: config.liveHelper }) : null;
  const handoff = new AgentHandoff();
  const actions = createActions({ session, toolchain, network, native, live, handoff });
  const server = createWalletServer({ session, actions, handoff });
  return { server, launchUrl: `${ORIGIN}/policy-builder#session=${secret}` };
}

export async function startWallet(configPath) {
  const runtime = await createWalletRuntime(configPath);
  await new Promise((resolve, reject) => {
    runtime.server.once('error', reject);
    runtime.server.listen(BACKEND_PORT, BACKEND_HOST, () => {
      runtime.server.off('error', reject);
      resolve();
    });
  });
  return runtime;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    if (process.argv.length !== 4 || process.argv[2] !== '--config') throw new Error();
    const { server, launchUrl } = await startWallet(process.argv[3]);
    process.stdout.write(`${launchUrl}\n`);
    const stop = () => server.close();
    process.once('SIGINT', stop);
    process.once('SIGTERM', stop);
    server.on('close', () => {
      process.off('SIGINT', stop);
      process.off('SIGTERM', stop);
    });
    server.on('error', () => {
      process.stderr.write('Wallet listener failed; inspect retained local state before restarting.\n');
      server.close();
      process.exitCode = 1;
    });
  } catch {
    process.stderr.write('Wallet startup refused. Check the operator configuration and local ports.\n');
    process.exitCode = 1;
  }
}
