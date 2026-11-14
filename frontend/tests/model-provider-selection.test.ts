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
  {id:1, name:'Jev', provider_type:'typesafe', model_group:'decision' as const, active:true, configured:false},
  {id:2, name:'EXAONE', provider_type:'exaone', model_group:'general' as const, active:true, configured:false},
  {id:3, name:'OpenAI', provider_type:'openai', model_group:'general' as const, active:true, configured:false},
  {id:4, name:'Coding', provider_type:'zai_coding', model_group:'general' as const, active:true, configured:false},
];
component.embedding = true;
component.providerId = 1; component.modelProviderChanged();
assert.deepEqual([component.generation, component.embedding, component.decision], [false, false, true]);
component.providerId = 2; component.modelProviderChanged();
assert.deepEqual([component.generation, component.embedding, component.decision], [false, false, false]);
component.embedding = true;
component.providerId = 3; component.modelProviderChanged();
assert.deepEqual([component.generation, component.embedding, component.decision], [false, false, false]);
component.decision = true;
component.providerId = 4; component.modelProviderChanged();
assert.deepEqual([component.generation, component.embedding, component.decision], [true, false, false]);
console.log('Provider changes keep only supported model operations.');
component.providerType = 'typesafe'; component.providerTypeChanged();
assert.equal(component.providerGroup, 'decision');
component.providerType = 'exaone'; component.providerTypeChanged();
assert.equal(component.providerGroup, 'general');
component.connections.push({id:5, name:'Embeddings', provider_type:'openai', model_group:'embedding', active:true, configured:false});
component.providerId = 5; component.modelProviderChanged();
assert.deepEqual([component.generation, component.embedding, component.decision], [false, true, false]);
component.selectModelOperation('generation', true);
assert.deepEqual([component.generation, component.embedding, component.decision], [true, false, false]);
