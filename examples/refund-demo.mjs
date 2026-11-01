// P7 demo CLI (product-value-assessment-2026-10-23.md §12.12): run the refund scenario
// against a live control plane.
//
//   node examples/refund-demo.mjs [baseUrl] [adminToken]
//
// With the app running locally (app: `npm run dev` in app/), in another shell:
//   node app/agent-sdk/examples/refund-demo.mjs http://localhost:3000 <admin-token>
// Against your organization on the bench:
//   node app/agent-sdk/examples/refund-demo.mjs https://app.provantix.tech <your-admin-token>
//
// Then open:
//   <base>/runs/<approved-trace>     the approved run as one chain, approval on the record
//   <base>/findings                  sensitive_action_without_approval from the unapproved run
// and export the approved run from its page to verify it offline (examples/verify-export.mjs).

import { runRefundDemo } from './refund-scenario.mjs';

const base = (process.argv[2] ?? 'http://localhost:3000').replace(/\/$/, '');
const token = process.argv[3] ?? process.env.LEDGER_ADMIN_TOKEN;
if (!token) {
  console.error('admin token required: pass it as argv[3] or set LEDGER_ADMIN_TOKEN');
  process.exit(1);
}

const log = (line) => console.log(`  ${line}`);
console.log('Refund demo — "refund above threshold" (P7)\n');
const result = await runRefundDemo({ base, token, spoolDir: '.refund-demo-spool', log });

console.log('\nWhat the platform shows:');
console.log(`  run view (approved):  ${base}/runs/${result.approved_trace}`);
console.log(`    — request from the human, approval ${'apr_refund_1042'} on the refund record,`);
console.log('      the payments destination record beside it, and no sensitive-action finding.');
console.log(`  run view (unapproved): ${base}/runs/${result.unapproved_trace}`);
console.log(`  finding:              ${base}/findings — sensitive_action_without_approval`);
console.log('\nVerify the export yourself: open the approved run, click "Export run", unzip, then');
console.log('  node examples/verify-export.mjs <unzipped-dir>');
