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
let refreshes = 0;
component.login = () => {refreshes++;};
const provider = {id:1, name:'OpenAI', provider_type:'openai', model_group:'general' as const, active:true, configured:true};
component.editProviderGroup(provider);
component.groupDraft = 'embedding'; component.saveProviderGroup(); component.saveProviderGroup();
assert.equal(requests.length, 1);
assert.equal(requests[0].url, '/admin/providers/1/model-group');
assert.deepEqual(requests[0].body, {model_group:'embedding'});
requests[0].result.error({status:409});
assert(component.groupError.includes('다른 용도의 모델'));
assert.equal(component.groupEditing?.id, 1);
component.saveProviderGroup();
requests[1].result.next({id:1, model_group:'embedding'});
assert.equal(component.groupEditing, null);
assert.equal(refreshes, 1);
component.editProviderGroup(provider); component.saveProviderGroup(); component.logout();
requests[2].result.next({id:1, model_group:'general'});
assert.equal(refreshes, 1);
assert.equal(component.groupEditing, null);
console.log('Provider group edits handle conflicts, duplicate submissions and stale sessions.');

async function timeoutReleasesGroupDrawer(): Promise<void> {
  (component as any).managementTimeoutMs = 10;
  component.editProviderGroup(provider); component.saveProviderGroup();
  await new Promise(resolve => setTimeout(resolve, 40));
  assert.equal(component.groupSaving, false);
  assert(component.groupError.includes('결과를 확인하지 못했습니다'));
  component.closeDrawer(); assert.equal(component.drawer, null);
  console.log('Timed-out group changes release the drawer and report an uncertain outcome.');
}
timeoutReleasesGroupDrawer().catch(error => { console.error(error); process.exitCode = 1; });
