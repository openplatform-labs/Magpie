import '@angular/compiler';
import { strict as assert } from 'node:assert';
import { ChangeDetectorRef, Injector, runInInjectionContext } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Subject } from 'rxjs';
import { AppComponent } from '../src/app/app.component';
import { SessionLifecycle } from '../src/app/session-lifecycle';

const gets: Subject<any>[] = [];
const puts: Subject<any>[] = [];
const http = {
  get: () => { const result = new Subject<any>(); gets.push(result); return result.asObservable(); },
  put: () => { const result = new Subject<any>(); puts.push(result); return result.asObservable(); },
};
const injector = Injector.create({ providers: [SessionLifecycle, {provide: HttpClient, useValue: http},
  {provide: ChangeDetectorRef, useValue: {markForCheck() {}}}] });
const component = runInInjectionContext(injector, () => new AppComponent());
(globalThis as any).requestAnimationFrame = () => 0;
component.refreshModels = () => {};
component.refreshObservability = () => {};
const first = {id:1, alias:'first', verification_version:1} as any;
const second = {id:2, alias:'second', verification_version:1} as any;
const capability = {operation:'decision', verification_status:'unverified'} as any;

component.selectVerification(first, capability);
component.saveVerification();
component.selectVerification(second, capability);
gets[1].next([{id:2, note:'second model'}]);
gets[0].next([{id:1, note:'first model'}]);
assert.equal(component.verificationModel?.id, 2);
assert.equal(component.verificationHistory[0].note, 'second model');
puts[0].next({});
assert.equal(component.verificationModel?.id, 2);

component.selectVerification(first, capability);
component.closeVerification();
gets[2].error(new Error('late failure'));
assert.equal(component.verificationModel, null);
assert.equal(component.error, '');
assert.deepEqual(component.verificationHistory, []);
console.log('Out-of-order verification responses do not replace or close another model selection.');
