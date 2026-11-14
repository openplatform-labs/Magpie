import '@angular/compiler';
import { strict as assert } from 'node:assert';
import { ChangeDetectorRef, Injector, runInInjectionContext } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Subject } from 'rxjs';
import { AppComponent } from '../src/app/app.component';
import { SessionLifecycle } from '../src/app/session-lifecycle';

let requests = 0;
let result = new Subject<unknown>();
const ids: string[] = [];
const http = { post: (_url: string, _body: unknown, options: {headers: Record<string, string>}) => { requests++; ids.push(options.headers['Idempotency-Key']); return result.asObservable(); } };
const injector = Injector.create({ providers: [
  SessionLifecycle,
  {provide: HttpClient, useValue:http},
  {provide: ChangeDetectorRef, useValue:{markForCheck() {}}},
] });
const component = runInInjectionContext(injector, () => new AppComponent());
let refreshes = 0;
component.refreshKeys = () => { refreshes++; };
component.refreshObservability = () => {};
(globalThis as any).requestAnimationFrame = () => 0;
component.keyName = 'test';
component.modelIds = [1];
component.issueKey();
component.issueKey();
assert.equal(requests, 1);
assert(component.issuingKey);
result.next({id:1, key:'test-key'});
result.complete();
assert.equal(component.issuedKey, 'test-key');
assert(!component.issuingKey);
result = new Subject<unknown>();
component.issueKey();
assert.equal(requests, 2);
result.error(new Error('offline'));
assert(!component.issuingKey);
assert.equal(component.issuedKey, 'test-key');
assert.match(component.error, /키 목록/);
assert(component.keyIssueUncertain);
assert.equal(refreshes, 2); // Once after success, once after uncertain failure.
result = new Subject<unknown>();
component.issueKey();
assert.equal(ids[1], ids[2]);
result.error(new Error('offline'));
result = new Subject<unknown>();
(globalThis as any).confirm = () => false;
component.resetKeyIssueRequest();
assert(component.keyIssueUncertain);
component.issueKey();
assert.equal(ids[2], ids[3]);
result.error(new Error('offline'));
(globalThis as any).confirm = () => true;
component.resetKeyIssueRequest();
assert(!component.keyIssueUncertain);
result = new Subject<unknown>();
component.issueKey();
assert.notEqual(ids[3], ids[4]);
result.error(new Error('offline'));
result = new Subject<unknown>();
component.keyName = 'different';
component.issueKey();
assert.notEqual(ids[4], ids[5]);
result.complete();
console.log('Key issuance prevents duplicate submissions and keeps prior key visible on uncertain failure.');

async function timeoutKeepsIdempotencyKey(): Promise<void> {
  (component as any).managementTimeoutMs = 10;
  result = new Subject<unknown>(); component.keyName = 'timeout'; component.issueKey();
  const requestId = ids.at(-1);
  await new Promise(resolve => setTimeout(resolve, 40));
  assert(!component.issuingKey);
  assert(component.keyIssueUncertain);
  result = new Subject<unknown>(); component.issueKey();
  assert.equal(ids.at(-1), requestId);
  result.complete();
  console.log('Timed-out issuance releases the drawer and retains the idempotency key.');
}
timeoutKeepsIdempotencyKey().catch(error => { console.error(error); process.exitCode = 1; });
