import '@angular/compiler';
import { strict as assert } from 'node:assert';
import { ChangeDetectorRef, Injector, runInInjectionContext } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Subject } from 'rxjs';
import { AppComponent } from '../src/app/app.component';
import { SessionLifecycle } from '../src/app/session-lifecycle';

const requests: {result: Subject<any>}[] = [];
const request = () => { const result = new Subject<any>(); requests.push({result}); return result.asObservable(); };
const injector = Injector.create({providers: [SessionLifecycle, {provide: HttpClient, useValue: {post: request, put: request}}, {provide: ChangeDetectorRef, useValue: {markForCheck() {}}}]});
const component = runInInjectionContext(injector, () => new AppComponent());
component.login = () => {};
component.openDrawer('provider'); component.providerName = 'Example'; component.addProvider(); component.addProvider();
assert.equal(requests.length, 1);
component.closeDrawer(); assert.equal(component.drawer, 'provider');
requests[0].result.error({status: 409}); assert.equal(component.providerSaving, false); assert.equal(component.drawer, 'provider');
component.addProvider(); requests[1].result.next({id:1, name:'Example', provider_type:'openai', model_group:'general', configured:false});
assert.equal(component.drawer, null);
component.openDrawer('providerKey'); component.rotateId = 1; component.rotateSecret = 'fake'; component.rotateProvider(); component.rotateProvider();
assert.equal(requests.length, 3); component.closeDrawer(); assert.equal(component.drawer, 'providerKey');
requests[2].result.next({}); assert.equal(component.drawer, null); assert.equal(component.rotateSecret, '');
console.log('Provider drawer prevents duplicate submissions and stays open while saving.');

async function timeoutReleasesDrawer(): Promise<void> {
  (component as any).managementTimeoutMs = 10;
  component.openDrawer('provider'); component.providerName = 'Slow'; component.addProvider();
  await new Promise(resolve => setTimeout(resolve, 40));
  assert.equal(component.providerSaving, false);
  assert(component.error.includes('결과를 확인하지 못했습니다'));
  component.closeDrawer(); assert.equal(component.drawer, null);
  component.openDrawer('providerKey'); component.rotateProvider();
  await new Promise(resolve => setTimeout(resolve, 40));
  assert.equal(component.providerKeySaving, false);
  assert(component.error.includes('감사 이력'));
  component.closeDrawer(); assert.equal(component.drawer, null);
  console.log('Timed-out provider writes release the drawer and report an uncertain outcome.');
}
timeoutReleasesDrawer().catch(error => { console.error(error); process.exitCode = 1; });
