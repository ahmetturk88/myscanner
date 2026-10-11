// MyScannerTasks waits for queued jobs; never performs a real request.
const assert = require('node:assert/strict');
const states = [];
global.fetch = async url => { assert(url.startsWith('/api/task-status/')); const next = states.shift(); return {ok: next.ok !== false, json: async () => next.body}; };
const tasks = require('../static/task_poll.js');
(async () => {
  states.push({body: {state: 'PENDING'}}, {body: {state: 'SUCCESS', result: {status: 'completed', result: {verdict: 'unknown'}}}});
  assert.deepEqual(await tasks.wait('a', {interval: 1}), {verdict: 'unknown'});
  states.push({body: {state: 'FAILURE', error: 'Target DNS is temporarily unavailable; please retry'}});
  await assert.rejects(tasks.wait('b', {interval: 1}), /Target DNS/);
  states.push({ok: false, body: {error: 'Task not found'}});
  await assert.rejects(tasks.wait('c', {interval: 1}), /Task not found/);
  states.push({body: {state: 'SUCCESS', result: {status: 'completed'}}});
  await assert.rejects(tasks.wait('d', {interval: 1}), /no report/);
  const direct = await tasks.resolve({status: 200, json: async () => ({verdict: 'x'})});
  assert.equal(direct.data.verdict, 'x');
  states.push({body: {state: 'SUCCESS', result: {status: 'completed', result: {verdict: 'queued'}}}});
  const queued = await tasks.resolve({status: 202, json: async () => ({task_id: 'e'})}, {interval: 1});
  assert.equal(queued.response.ok, true); assert.equal(queued.data.verdict, 'queued');
  await assert.rejects(tasks.resolve({status: 202, json: async () => ({})}), /could not be started/);
  console.log('PASS: queued jobs resolve to reports; failures and missing reports surface as errors.');
})().catch(error => { console.error(error); process.exit(1); });
