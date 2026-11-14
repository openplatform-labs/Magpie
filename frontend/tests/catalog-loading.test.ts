import '@angular/compiler';
import { strict as assert } from 'node:assert';
import { ChangeDetectorRef, Injector, runInInjectionContext } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Subject } from 'rxjs';
import { AppComponent } from '../src/app/app.component';
import { SessionLifecycle } from '../src/app/session-lifecycle';

const requests: Subject<unknown>[] = [];
const http = {get: (url: string) => {
  assert.equal(url, '/api/catalog');
  const response = new Subject<unknown>(); requests.push(response); return response.asObservable();
}};
const injector = Injector.create({providers: [SessionLifecycle, {provide: HttpClient, useValue: http},
  {provide: ChangeDetectorRef, useValue: {markForCheck() {}}}]});
const component = runInInjectionContext(injector, () => new AppComponent());
component.loadCatalog();
component.loadCatalog();
assert.equal(requests.length, 1);
assert(component.catalogLoading);
requests[0].error(new Error('offline'));
assert(component.catalogError);
assert(!component.catalogLoading);
component.loadCatalog();
assert.equal(requests.length, 2);
assert(!component.catalogError);
requests[1].next({providers:[{id:'exaone', name:'EXAONE', adapter:'openai-compatible', base_url:null}], operations:['generation']});
assert(!component.catalogLoading);
assert(!component.catalogError);
assert.equal(component.selectedProvider?.name, 'EXAONE');
console.log('Provider catalog failure can be retried without duplicate concurrent requests.');
