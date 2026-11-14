import '@angular/compiler';
import { strict as assert } from 'node:assert';
import { ChangeDetectorRef, Injector, runInInjectionContext } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { of } from 'rxjs';
import { AppComponent } from '../src/app/app.component';
import { SessionLifecycle } from '../src/app/session-lifecycle';

const requests: {url: string; params?: HttpParams}[] = [];
const http = {get: (url:string, options:{params?:HttpParams}) => { requests.push({url, params:options.params}); return of(url === '/admin/metrics' ? {} : []); }};
const injector = Injector.create({providers: [SessionLifecycle, {provide:HttpClient,useValue:http}, {provide:ChangeDetectorRef,useValue:{markForCheck(){}}}]});
const component = runInInjectionContext(injector, () => new AppComponent());
component.usageStart = '2026-11-14:0905'; component.usageEnd = '2026-11-14:1030'; component.refreshObservability();
const start = new Date(2026, 10, 14, 9, 5).toISOString(), end = new Date(2026, 10, 14, 10, 30).toISOString();
for (const url of ['/admin/metrics', '/admin/usage', '/admin/usage/requests']) {
  const params = requests.find(request => request.url === url)?.params;
  assert(params); assert.equal(params.get('start'), start); assert.equal(params.get('end'), end);
}
const previousCount = requests.length;
component.toggleTimePicker('usageStart'); component.submitUsageFilters(); assert.equal(requests.length, previousCount); component.pickerField = null;
component.usageStart = '2026-02-29:1200'; component.refreshObservability(); assert.equal(requests.length, previousCount);
component.usageStart = '2026-11-14:1030'; component.refreshObservability(); assert.equal(requests.length, previousCount); assert(component.error.includes('늦어야'));
component.usageStart = '2026-11-14:0905'; component.refreshObservability(); assert.equal(component.error, ''); assert.equal(requests.length, previousCount + 4);
console.log('Usage filters send local time as UTC and reject invalid or empty ranges.');
