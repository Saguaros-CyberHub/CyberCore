/**
 * ============================================================================
 * INCIDENT ENGINE — 'synthetic'
 * ============================================================================
 * The engine that exists today: a baked Rocky sensor running cc-emit.js, driven
 * by a cc-attack.sh wrapper staged per dispatch over the Proxmox guest agent.
 * It fabricates ND-JSON that Filebeat ships into the lane's Elasticsearch.
 *
 * WHAT THIS FILE IS, AND WHAT IT IS NOT
 * ----------------------------------------------------------------------------
 * It is the ADAPTER — the thin surface that src/incident/engines/index.js
 * registers and that a future Caldera adapter has to match. The implementation
 * lives where it already lives: runner.js (command construction, dispatch,
 * abort, finalize) and target.js (which VM in a lane to attack). Nothing was
 * reimplemented here, and nothing should be.
 *
 * The orchestration methods are deliberately NOT wired yet. E1 is a pure
 * relocation, so runner.js still writes cle_attack_run through the CLE pool;
 * E2 is what re-points it at cybercore_incident_run and gives these methods a
 * caller to be shaped against. Wiring them now would mean guessing at signatures
 * and rewriting them next session.
 *
 * They throw rather than no-op, and that distinction matters: a no-op
 * dispatchTarget() returns "dispatched" for a lane where nothing was started,
 * and the worker then waits out the full run duration before reporting a
 * failure that happened instantly. A throw fails the target at dispatch, which
 * is where the operator is still looking.
 * ============================================================================
 */

'use strict';

/**
 * Lazily required, and the reason is not style.
 *
 * runner.js pulls in src/utils/site-config at module scope, which reads
 * config/site.json — gitignored, and absent in a plain checkout. Requiring it
 * from here at load time would make engines/index.js unimportable outside a
 * deployed environment, and index.js is required by anything that wants to know
 * which engines exist. Deferring costs one property lookup per call.
 */
let _runner = null;
function runner() {
  if (!_runner) _runner = require('../runner');
  return _runner;
}

/** Not-yet-wired orchestration. See the header for why this throws. */
function notWiredYet(method) {
  return () => {
    throw new Error(
      `incident engine 'synthetic': ${method}() is not wired to the shared tables yet (E2). `
      + 'Until then the CLE routes drive src/incident/runner.js directly.'
    );
  };
}

module.exports = {
  key: 'synthetic',

  /**
   * Every mode the run table declares EXCEPT 'scenario'.
   *
   * 'scenario' is the CiAB arm and the wrapper already supports its mechanics —
   * buildDispatchCommand derives wrapperMode='playbook' from args.playbookJson
   * — but the COMPILER that turns a client profile's threat scenarios into a
   * playbook does not exist until E4. Claiming support before then would let a
   * route write a 'scenario' run that dispatches an empty playbook: a lane that
   * reports 'completed' having generated nothing, which is the worst outcome
   * available because it looks like a working exercise.
   */
  supportsMode(mode) {
    return mode === 'technique' || mode === 'tactic' || mode === 'chain';
  },

  /**
   * Validates a run row's mode-specific columns and returns what the wrapper is
   * dispatched with. Throws on anything it cannot validate — these values reach
   * a root shell inside a student's VM, so it never sanitizes.
   */
  resolveSelection(runRow) {
    return runner().resolveSelection(runRow);
  },

  /**
   * STAFF-ONLY grading key.
   *
   * Empty for now, and honestly so: E5's projection is what defines the key's
   * shape, and a guessed key is worse than none — it would grade a student
   * against findings the run never produced. The synthetic engine CAN produce a
   * real key (it authored the playbook, so it knows every host, IOC and
   * timestamp it emitted), which is exactly why this is a stub and not a
   * permanent {}.
   */
  compileAnswerKey() {
    return {};
  },

  prepare: notWiredYet('prepare'),
  dispatchTarget: notWiredYet('dispatchTarget'),
  readTargetState: notWiredYet('readTargetState'),
  abortTarget: notWiredYet('abortTarget'),
  abortRun: notWiredYet('abortRun'),
  finalize: notWiredYet('finalize'),
};
