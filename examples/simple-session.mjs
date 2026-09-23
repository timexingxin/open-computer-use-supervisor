import { SupervisorBroker } from '../src/core/broker.mjs';

async function main() {
  const sessionId = `example-session-${Date.now()}`;
  console.log(`Starting supervisor session: ${sessionId}`);

  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  console.log(`Broker running on socket: ${broker.socketPath}`);
  console.log(`Broker launcher capability token generated (length: ${broker.launcherCapabilityToken?.length || 0})`);

  // Issue single-use launch ticket
  const ticket = broker.issueLaunchTicket({
    role: 'playwright-worker',
    expectedLauncherPid: process.pid
  });

  console.log(`Issued launch ticket ID: ${ticket.ticket_id}`);
  console.log(`Ticket expires at: ${new Date(ticket.expires_at).toISOString()}`);

  // Shutdown broker
  await broker.stop();
  console.log(`Session ${sessionId} cleanly terminated.`);
}

main().catch(console.error);
