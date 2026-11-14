import '@angular/compiler';
import { strict as assert } from 'node:assert';
import { ChangeDetectorRef, Injector, runInInjectionContext } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Subject } from 'rxjs';
import { AppComponent } from '../src/app/app.component';
import { SessionLifecycle } from '../src/app/session-lifecycle';

const requests: {url: string; body: any; result: Subject<any>}[] = [];
const http = { put: (url: string, body: any) => {
  const result = new Subject<any>(); requests.push({url, body, result}); return result.asObservable();
} };
const injector = Injector.create({ providers: [SessionLifecycle, {provide: HttpClient, useValue: http},
  {provide: ChangeDetectorRef, useValue: {markForCheck() {}}}] });
const component = runInInjectionContext(injector, () => new AppComponent());
(globalThis as any).requestAnimationFrame = () => 0;
component.refreshModels = () => {};
component.refreshKeys = () => {};
component.refreshObservability = () => {};
const model = (id: number) => ({id, alias:`model-${id}`, provider_id:1, upstream_model:'mock', operations:['generation'],
  description:null, max_input_tokens:null, embedding_dimensions:null, embedding_space:null, supports_embedding_batch:null,
  embedding_max_batch_size:null, supports_streaming:null, supports_tools:null, supports_reasoning:null}) as any;
const a = model(1), b = model(2);
component.models = [a,b];
component.editModel(a); component.addModel(); component.editModel(b);
requests[0].result.next({});
assert.equal(component.editingModel?.id, 2);
assert.equal(component.alias, 'model-2');
const key = (id: number) => ({id, name:`key-${id}`, model_ids:[id], requests_per_minute:null, expires_at:null}) as any;
component.editKey(key(1)); component.saveKey();
component.editModelIds.push(2);
assert.deepEqual(requests[1].body.model_ids, [1]);
component.editKey(key(2)); requests[1].result.next({});
assert.equal(component.editingKey?.id, 2);
assert.equal(component.editKeyName, 'key-2');
component.addModel(); component.modelDescription = 'new unsaved description'; requests[2].result.next({});
assert.equal(component.editingModel?.id, 2);
assert.equal(component.modelDescription, 'new unsaved description');
component.saveKey(); component.editKeyName = 'new unsaved name'; requests[3].result.next({});
assert.equal(component.editingKey?.id, 2);
assert.equal(component.editKeyName, 'new unsaved name');
console.log('A completed model or key save does not close another selection.');

const originalExpiry = '2026-11-01T06:30:42.123Z';
component.editKey({...key(3), expires_at:originalExpiry});
component.toggleTimePicker('editExpiry'); const beforePickerSave = requests.length;
component.saveKey(); assert.equal(requests.length, beforePickerSave); component.pickerField = null;
component.editKeyName = 'renamed'; component.saveKey();
assert.equal(requests.at(-1)?.body.expires_at, originalExpiry);
requests.at(-1)!.result.next({}); requests.at(-1)!.result.complete();
component.editKey({...key(3), expires_at:originalExpiry});
component.editExpiry = '2030-12-31:2359'; component.saveKey();
assert.equal(requests.at(-1)?.body.expires_at, new Date(2030, 11, 31, 23, 59).toISOString());
requests.at(-1)!.result.next({}); requests.at(-1)!.result.complete();
console.log('Unchanged expiry preserves the original instant; an edited expiry uses local time.');

async function savesDoNotOverlap(): Promise<void> {
  (component as any).managementTimeoutMs = 10;
  component.editModel(a); component.addModel(); const modelRequest = requests.length;
  component.addModel(); assert.equal(requests.length, modelRequest);
  assert(component.modelSaving); component.closeDrawer(); assert.equal(component.drawer, 'model');
  await new Promise(resolve => setTimeout(resolve, 40));
  assert(!component.modelSaving); assert(component.error.includes('결과를 확인하지 못했습니다'));
  component.closeDrawer(); assert.equal(component.drawer, null);
  component.editKey(key(1)); component.saveKey(); const keyRequest = requests.length;
  component.saveKey(); assert.equal(requests.length, keyRequest);
  assert(component.keySaving); component.closeDrawer(); assert.equal(component.drawer, 'editKey');
  await new Promise(resolve => setTimeout(resolve, 40));
  assert(!component.keySaving); assert(component.error.includes('결과를 확인하지 못했습니다'));
  component.closeDrawer(); assert.equal(component.drawer, null);
  console.log('Model and key drawers prevent overlapping saves and report timeouts.');
}
savesDoNotOverlap().catch(error => { console.error(error); process.exitCode = 1; });
