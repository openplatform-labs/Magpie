import '@angular/compiler';
import { strict as assert } from 'node:assert';
import { ChangeDetectorRef, Injector, runInInjectionContext } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Subject } from 'rxjs';
import { AppComponent } from '../src/app/app.component';
import { SessionLifecycle } from '../src/app/session-lifecycle';

const requests: {url:string; body:any; result:Subject<any>}[] = [];
const http = {put: (url:string, body:any) => {const result = new Subject<any>(); requests.push({url, body, result}); return result.asObservable();}};
const injector = Injector.create({providers:[SessionLifecycle, {provide:HttpClient, useValue:http}, {provide:ChangeDetectorRef, useValue:{markForCheck(){}}}]});
const component = runInInjectionContext(injector, () => new AppComponent());
(globalThis as any).requestAnimationFrame = () => 0;
let refreshes = 0; component.login = () => { refreshes++; };
const provider = {id:1, name:'EXAONE', provider_type:'exaone', model_group:'general' as const, active:true, configured:true};
component.editProviderName(provider); component.editProviderNameDraft = '새 이름';
component.saveProviderName(); component.saveProviderName(); component.closeDrawer();
assert.equal(requests.length, 1); assert.equal(component.drawer, 'providerName');
assert.equal(requests[0].url, '/admin/providers/1/name'); assert.deepEqual(requests[0].body, {name:'새 이름'});
requests[0].result.error({status:409}); assert(component.error.includes('이미 사용 중')); assert.equal(component.drawer, 'providerName');
component.saveProviderName(); requests[1].result.next({id:1,name:'새 이름'});
assert.equal(component.drawer, null); assert.equal(refreshes, 1);
component.editProviderName(provider); component.saveProviderName(); component.logout();
requests[2].result.next({id:1,name:'EXAONE'}); assert.equal(refreshes, 1);
console.log('Provider name edits handle duplicate submissions, conflicts and stale sessions.');

async function timeoutReleasesNameDrawer(): Promise<void> {
  (component as any).managementTimeoutMs = 10;
  component.editProviderName(provider); component.editProviderNameDraft = '시간 초과';
  component.saveProviderName();
  await new Promise(resolve => setTimeout(resolve, 40));
  assert.equal(component.providerNameSaving, false);
  assert(component.error.includes('변경 결과를 확인하지 못했습니다'));
  component.closeDrawer(); assert.equal(component.drawer, null);
  console.log('Timed-out provider name changes release the drawer and report an uncertain outcome.');
}
timeoutReleasesNameDrawer().catch(error => { console.error(error); process.exitCode = 1; });
