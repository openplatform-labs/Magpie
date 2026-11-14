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
component.refreshRoutes = () => {};
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

const route = (id: number) => ({id, alias:`route-${id}`, operation:'generation', retry_on_failure:false,
  targets:[{model_id:id, priority:0, weight:1}]}) as any;
component.editRoute(route(1)); component.saveRoute();
component.routeTargets[0].weight = 9;
assert.equal(requests[1].body.targets[0].weight, 1);
component.editRoute(route(2)); requests[1].result.next({});
assert.equal(component.editingRoute?.id, 2);
assert.equal(component.routeAlias, 'route-2');

const key = (id: number) => ({id, name:`key-${id}`, model_ids:[id], requests_per_minute:null, expires_at:null}) as any;
component.editKey(key(1)); component.saveKey();
component.editModelIds.push(2);
assert.deepEqual(requests[2].body.model_ids, [1]);
component.editKey(key(2)); requests[2].result.next({});
assert.equal(component.editingKey?.id, 2);
assert.equal(component.editKeyName, 'key-2');
component.addModel(); component.modelDescription = 'new unsaved description'; requests[3].result.next({});
assert.equal(component.editingModel?.id, 2);
assert.equal(component.modelDescription, 'new unsaved description');
component.saveRoute(); component.routeTargets[0].weight = 7; requests[4].result.next({});
assert.equal(component.editingRoute?.id, 2);
assert.equal(component.routeTargets[0].weight, 7);
component.saveKey(); component.editKeyName = 'new unsaved name'; requests[5].result.next({});
assert.equal(component.editingKey?.id, 2);
assert.equal(component.editKeyName, 'new unsaved name');
console.log('A completed model, route, or key save does not close another selection.');
