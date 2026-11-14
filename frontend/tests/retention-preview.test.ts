import '@angular/compiler';
import { strict as assert } from 'node:assert';
import { ChangeDetectorRef, Injector, runInInjectionContext } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Subject } from 'rxjs';
import { AppComponent } from '../src/app/app.component';
import { SessionLifecycle } from '../src/app/session-lifecycle';

const requests: {url: string; body: any; result: Subject<any>}[] = [];
const http = { post: (url: string, body: any) => {
  const result = new Subject<any>(); requests.push({url, body, result}); return result.asObservable();
} };
const injector = Injector.create({ providers: [SessionLifecycle, {provide: HttpClient, useValue: http},
  {provide: ChangeDetectorRef, useValue: {markForCheck() {}}}] });
const component = runInInjectionContext(injector, () => new AppComponent());
component.refreshObservability = () => {};
(globalThis as any).confirm = () => true;
const preview = {usage_records: 7, audit_records: 4, usage_cutoff:'2026-01-01', audit_cutoff:'2025-01-01'};

component.previewRetention();
component.usageRetention = 30;
component.invalidateRetentionPreview();
requests[0].result.next(preview);
assert.equal(component.retentionPreview, null);
component.applyRetention();
assert.equal(requests.length, 1);

component.previewRetention();
requests[1].result.next(preview);
component.auditRetention = 10; // Even if an input event is missed, mismatched settings cannot be applied.
component.applyRetention();
assert.equal(requests.length, 2);
component.invalidateRetentionPreview();
component.previewRetention();
requests[2].result.next(preview);
component.applyRetention();
component.applyRetention();
assert.equal(requests.length, 4);
assert.equal(requests[3].url, '/admin/retention/apply');
assert.deepEqual(requests[3].body, {usage_days:30, audit_days:10});
requests[3].result.error(new Error('response lost'));
assert.equal(component.retentionPreview, null);
assert(!component.retentionApplying);
component.applyRetention();
assert.equal(requests.length, 4);
console.log('Retention deletion requires the current preview and ignores stale responses or duplicate submissions.');
