#!/usr/bin/env node
import {
  resolveActiveSessionId,
  loadSessionData,
  registerProcess,
  registerResource,
  validateSessionRoot,
  getBrokerSocketPath
} from '../core/registry.mjs';
import { verifyProcessOwnership } from '../core/verifier.mjs';
import { verifyResourceSafety } from '../core/resource-verifier.mjs';
import { planSessionCleanup } from '../core/planner.mjs';
import { checkProcessAlive } from '../core/identity.mjs';
import { sendBrokerRequest } from '../core/ipc.mjs';
import { SupervisorBroker } from '../core/broker.mjs';
import { PHASE_V0_1_CONFIG } from '../core/config.mjs';

function parseArgs(args) {
  const options = {
    command: args[0] || 'status',
    sessionId: null,
    dryRun: true,
    execute: false,
    pid: null,
    role: 'unspecified',
    path: null,
    type: 'unix_socket',
    json: false
  };

  for (let i = 1; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--session' && args[i + 1]) {
      options.sessionId = args[++i];
    } else if (arg === '--dry-run') {
      options.dryRun = true;
    } else if (arg === '--execute') {
      options.execute = true;
      options.dryRun = false;
    } else if (arg === '--pid' && args[i + 1]) {
      options.pid = parseInt(args[++i], 10);
    } else if (arg === '--role' && args[i + 1]) {
      options.role = args[++i];
    } else if (arg === '--path' && args[i + 1]) {
      options.path = args[++i];
    } else if (arg === '--type' && args[i + 1]) {
      options.type = args[++i];
    } else if (arg === '--json') {
      options.json = true;
    }
  }

  return options;
}

export async function runCli(argv = process.argv.slice(2)) {
  const opts = parseArgs(argv);
  const sessionId = resolveActiveSessionId(opts.sessionId);

  switch (opts.command) {
    case 'status': {
      const data = loadSessionData(sessionId);
      const socketPath = getBrokerSocketPath(sessionId);
      const ping = await sendBrokerRequest(socketPath, { action: 'PING', sessionId }, 1000);

      if (opts.json) {
        console.log(JSON.stringify({ ...data, broker: ping }, null, 2));
        return 0;
      }

      console.log(`=======================================================`);
      console.log(` ANTIGRAVITY PROCESS SUPERVISOR (Session Status)       `);
      console.log(` Phase: ${PHASE_V0_1_CONFIG.phase} | Version: ${PHASE_V0_1_CONFIG.version} `);
      console.log(`=======================================================`);
      console.log(`Session ID    : ${data.session.sessionId}`);
      console.log(`Session Nonce : ${data.session.sessionNonce || 'none'}`);
      console.log(`Started At    : ${data.session.startedAt}`);
      console.log(`Root PID      : ${data.session.root_pid} (${data.session.root_executable || 'unknown'})`);
      console.log(`Directory     : ${data.sessionDir}`);
      console.log(`Broker IPC    : ${ping.success ? 'ONLINE (PID ' + ping.brokerPid + ')' : 'OFFLINE (Audit-Only / Fallback)'}\n`);

      console.log(`[Registered Processes: ${data.processes.length}]`);
      if (data.processes.length === 0) {
        console.log(`  (None registered)`);
      } else {
        data.processes.forEach((p, idx) => {
          const alive = checkProcessAlive(p.pid);
          console.log(`  ${idx + 1}. PID ${p.pid} [${p.role}]`);
          console.log(`     Source   : ${p.registration_source || 'UNKNOWN'} | Ownership: ${p.ownership || 'UNTRUSTED'}`);
          console.log(`     Alive    : ${alive} | SafeToKill: ${p.safe_to_kill}`);
          console.log(`     Command  : ${p.command.substring(0, 80)}...`);
          console.log(`     Started  : ${p.lstart}`);
          if (p.never_kill_reason) {
            console.log(`     BlockReason: ${p.never_kill_reason}`);
          }
        });
      }

      console.log(`\n[Registered Resources: ${data.resources.length}]`);
      if (data.resources.length === 0) {
        console.log(`  (None registered)`);
      } else {
        data.resources.forEach((r, idx) => {
          console.log(`  ${idx + 1}. [${r.type}] ${r.path}`);
          console.log(`     Owning PID: ${r.owning_pid} | Safe Path: ${r.is_approved_temp_path}`);
        });
      }
      return 0;
    }

    case 'verify': {
      const data = loadSessionData(sessionId);
      const rootCheck = validateSessionRoot(sessionId);
      const socketPath = getBrokerSocketPath(sessionId);
      const ping = await sendBrokerRequest(socketPath, { action: 'PING', sessionId }, 1000);

      console.log(`=======================================================`);
      console.log(` 8-FACTOR PROVENANCE & OWNERSHIP VERIFICATION          `);
      console.log(` Session: ${sessionId}                                 `);
      console.log(` Broker IPC: ${ping.success ? 'ONLINE' : 'OFFLINE (Fail-Closed: Observe Only)'}`);
      console.log(` Root Integrity: ${rootCheck.valid ? 'VALID (PASS)' : 'INVALID (' + rootCheck.reason + ')'}`);
      console.log(`=======================================================`);

      let totalPass = 0;
      let totalBlocked = 0;

      for (let idx = 0; idx < data.processes.length; idx++) {
        const p = data.processes[idx];
        const v = await verifyProcessOwnership(p, sessionId);
        console.log(`\n[Process ${idx + 1}] PID ${p.pid} (${p.role})`);
        console.log(`  Source : ${p.registration_source || 'UNKNOWN'} | Ownership: ${p.ownership || 'UNTRUSTED'}`);
        console.log(`  Verdict: ${v.status} (CanTerminate: ${v.canTerminate})`);
        console.log(`  Reason : ${v.reason}`);
        if (v.ancestry && v.ancestry.length > 0) {
          console.log(`  Ancestry: ${v.ancestry.join(' -> ')}`);
        }
        console.log(`  Factors:`);
        console.log(`    - F1 (Alive)              : ${v.factors.f1_exists ? 'PASS' : 'FAIL'}`);
        console.log(`    - F2 (Start Identity)     : ${v.factors.f2_startTimeMatch ? 'PASS' : 'FAIL'}`);
        console.log(`    - F3 (Executable Match)   : ${v.factors.f3_executableMatch ? 'PASS' : 'FAIL'}`);
        console.log(`    - F4 (Command Match)      : ${v.factors.f4_commandMatch ? 'PASS' : 'FAIL'}`);
        console.log(`    - F5 (Session Match)      : ${v.factors.f5_sessionMatch ? 'PASS' : 'FAIL'}`);
        console.log(`    - F6 (Provenance Attested): ${v.factors.f6_provenanceAttested ? 'PASS' : 'FAIL'}`);
        console.log(`    - F7 (Never-Kill Exempt)  : ${v.factors.f7_neverKillExempt ? 'PASS' : 'FAIL (BLOCKED)'}`);
        console.log(`    - F8 (Source Trust)       : ${v.factors.f8_sourceTrusted ? 'PASS' : 'FAIL (UNTRUSTED)'}`);

        if (v.canTerminate) totalPass++;
        else totalBlocked++;
      }

      console.log(`\n-------------------------------------------------------`);
      console.log(`Processes: ${totalPass} VERIFIED_OWNED | ${totalBlocked} BLOCKED/UNTRUSTED`);

      let totalResPass = 0;
      let totalResBlocked = 0;
      for (let idx = 0; idx < data.resources.length; idx++) {
        const r = data.resources[idx];
        const rv = await verifyResourceSafety(r, sessionId);
        console.log(`\n[Resource ${idx + 1}] [${r.type}] ${r.path}`);
        console.log(`  Verdict: ${rv.status} (CanDelete: ${rv.canDelete})`);
        console.log(`  Reason : ${rv.reason}`);
        if (rv.canDelete) totalResPass++;
        else totalResBlocked++;
      }

      console.log(`-------------------------------------------------------`);
      console.log(`Resources: ${totalResPass} DELETABLE | ${totalResBlocked} BLOCKED/REMOVED\n`);
      return 0;
    }

    case 'cleanup': {
      if (opts.execute) {
        console.error(`\n[ERROR: FAIL CLOSED GATE ENFORCED]`);
        console.error(`--execute is strictly locked in Phase ${PHASE_V0_1_CONFIG.phase}!`);
        console.error(`Reason: ${PHASE_V0_1_CONFIG.lockReason}`);
        console.error(`In accordance with Antigravity Phase S1.3 safety rules, no POSIX kill`);
        console.error(`signals or unlinks may be executed on this machine.\n`);
        return 1;
      }

      console.log(`=======================================================`);
      console.log(` AGY-SUPERVISOR CLEANUP (DRY-RUN ONLY)                  `);
      console.log(` Session: ${sessionId}                                 `);
      console.log(` Mode: STRICT DRY-RUN (Zero Signal, Zero Unlink)        `);
      console.log(`=======================================================`);

      const plan = await planSessionCleanup(sessionId, { dryRun: true });
      if (opts.json) {
        console.log(JSON.stringify(plan, null, 2));
        return 0;
      }

      console.log(`Summary:`);
      console.log(`  Processes Total            : ${plan.summary.totalProcesses}`);
      console.log(`  - Would Terminate          : ${plan.summary.processesWouldTerminate}`);
      console.log(`  - Blocked by Policy/Trust  : ${plan.summary.processesBlocked}`);
      console.log(`  - Already Dead (Noop)      : ${plan.summary.processesAlreadyDead}`);
      console.log(`  Resources Total            : ${plan.summary.totalResources}`);
      console.log(`  - Would Delete             : ${plan.summary.resourcesWouldDelete}`);
      console.log(`  - Blocked / In Use         : ${plan.summary.resourcesBlocked}`);
      console.log(`  - Already Removed (Noop)   : ${plan.summary.resourcesAlreadyRemoved}\n`);

      if (plan.processes.length > 0) {
        console.log(`Processes Planned Actions:`);
        plan.processes.forEach(p => {
          console.log(`  - PID ${p.pid} [${p.role}]: ${p.action} (${p.status} - ${p.reason}) [PGID: ${p.pgid_safety}]`);
        });
        console.log('');
      }

      if (plan.resources.length > 0) {
        console.log(`Resources Planned Actions:`);
        plan.resources.forEach(r => {
          console.log(`  - [${r.type}] ${r.path}: ${r.action} (${r.status} - ${r.reason})`);
        });
        console.log('');
      }

      console.log(`[DRY-RUN AUDIT COMPLETE: 0 processes killed, 0 files deleted]`);
      return 0;
    }

    case 'register-process': {
      if (!opts.pid) {
        console.error(`Error: --pid is required`);
        return 1;
      }
      const res = registerProcess(sessionId, {
        pid: opts.pid,
        role: opts.role
      });
      if (!res.success) {
        console.error(`Registration failed: ${res.error}`);
        return 1;
      }
      console.log(`[MANUAL_TEST] Registered PID ${opts.pid} in session ${sessionId}`);
      console.log(`  Source    : ${res.record.registration_source}`);
      console.log(`  Ownership : ${res.record.ownership}`);
      console.log(`  SafeToKill: ${res.record.safe_to_kill} (CANNOT BE TERMINATED)`);
      return 0;
    }

    case 'register-resource': {
      if (!opts.path) {
        console.error(`Error: --path is required`);
        return 1;
      }
      const res = await registerResource(sessionId, {
        path: opts.path,
        type: opts.type,
        owningPid: opts.pid
      });
      if (!res.success) {
        console.error(`Registration failed: ${res.error}`);
        return 1;
      }
      console.log(`Successfully registered resource ${opts.path} in session ${sessionId}`);
      return 0;
    }

    case 'start-broker': {
      const broker = new SupervisorBroker(sessionId);
      await broker.start();
      console.log(`Supervisor Broker started successfully.`);
      console.log(`Session: ${broker.sessionId}`);
      console.log(`Socket : ${broker.socketPath}`);
      console.log(`PID    : ${process.pid}`);
      // Keep process alive if run directly
      return new Promise(() => {});
    }

    default: {
      console.log(`Usage: agy-supervisor <command> [options]`);
      console.log(`Commands:`);
      console.log(`  status                 Show session status and broker state`);
      console.log(`  verify                 Run 8-factor provenance & ancestry verification`);
      console.log(`  cleanup --dry-run      Generate and display cleanup plan without executing`);
      console.log(`  register-process       Manual test register (--pid <pid>) -> UNTRUSTED_TEST`);
      console.log(`  register-resource      Register socket/token resource (--path <path>)`);
      console.log(`  start-broker           Start session privileged broker daemon`);
      return 0;
    }
  }
}

if (process.argv[1] && process.argv[1].endsWith('cli.mjs')) {
  runCli().catch(err => {
    console.error(`Fatal CLI Error:`, err);
    process.exit(1);
  });
}
