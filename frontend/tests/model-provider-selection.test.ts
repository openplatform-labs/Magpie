import '@angular/compiler';
import { strict as assert } from 'node:assert';
import { ChangeDetectorRef, Injector, runInInjectionContext } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { AppComponent } from '../src/app/app.component';
import { SessionLifecycle } from '../src/app/session-lifecycle';

const injector = Injector.create({providers: [SessionLifecycle, {provide: HttpClient, useValue:{}},
  {provide: ChangeDetectorRef, useValue: {markForCheck() {}}}]});
const component = runInInjectionContext(injector, () => new AppComponent());
component.connections = [
  {id:1, name:'Jev', provider_type:'typesafe', active:true, configured:false},
  {id:2, name:'EXAONE', provider_type:'exaone', active:true, configured:false},
  {id:3, name:'OpenAI', provider_type:'openai', active:true, configured:false},
  {id:4, name:'Coding', provider_type:'zai_coding', active:true, configured:false},
];
component.embedding = true;
component.providerId = 1; component.modelProviderChanged();
assert.deepEqual([component.generation, component.embedding, component.decision], [false, false, true]);
component.providerId = 2; component.modelProviderChanged();
assert.deepEqual([component.generation, component.embedding, component.decision], [true, false, false]);
component.embedding = true;
component.providerId = 3; component.modelProviderChanged();
assert.deepEqual([component.generation, component.embedding, component.decision], [true, true, false]);
component.decision = true;
component.providerId = 4; component.modelProviderChanged();
assert.deepEqual([component.generation, component.embedding, component.decision], [true, false, false]);
console.log('Provider changes keep only supported model operations.');
