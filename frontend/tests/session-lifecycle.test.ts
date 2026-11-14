import '@angular/compiler';
import { strict as assert } from 'node:assert';
import { Injector, runInInjectionContext } from '@angular/core';
import { HttpErrorResponse, HttpRequest, HttpResponse, HttpEvent } from '@angular/common/http';
import { NEVER, Subject, of, throwError } from 'rxjs';
import { SessionLifecycle, revokeSession, sessionCancellationInterceptor } from '../src/app/session-lifecycle';

const injector = Injector.create({ providers: [SessionLifecycle] });
const lifecycle = injector.get(SessionLifecycle);
function request(url: string) {
  const source = new Subject<HttpEvent<unknown>>();
  const values: unknown[] = [];
  let completed = false;
  const result = runInInjectionContext(injector, () => sessionCancellationInterceptor(
    new HttpRequest('GET', url), () => source.asObservable()));
  result.subscribe({ next: value => values.push(value), complete: () => completed = true });
  return { source, values, isComplete: () => completed };
}

const oldModels = request('/admin/models');
const oldLogin = request('/auth/oidc/callback');
const publicCatalog = request('/api/catalog');
const publicSsoConfig = request('/auth/oidc/config');
const revocation = request('/admin/sessions/current');
lifecycle.end();
assert(oldModels.isComplete() && oldLogin.isComplete());
oldModels.source.next(new HttpResponse({ body: 'old models' }));
oldLogin.source.next(new HttpResponse({ body: 'old login' }));
assert.equal(oldModels.values.length, 0);
assert.equal(oldLogin.values.length, 0);
assert(!publicCatalog.isComplete() && !publicSsoConfig.isComplete() && !revocation.isComplete());
publicSsoConfig.source.next(new HttpResponse({ body: {enabled:true} }));
assert.equal(publicSsoConfig.values.length, 1);
revocation.source.next(new HttpResponse({ status: 204 }));
assert.equal(revocation.values.length, 1);

const newModels = request('/admin/models');
newModels.source.next(new HttpResponse({ body: 'new models' }));
assert.equal(newModels.values.length, 1);
lifecycle.end();
assert(newModels.isComplete());
console.log('Session transitions cancel stale admin and login responses without cancelling revocation or public SSO configuration.');

let warnings = 0;
const warn = () => warnings++;
revokeSession(of(null), warn);
assert.equal(warnings, 0);
revokeSession(throwError(() => new HttpErrorResponse({status:401})), warn);
assert.equal(warnings, 1);
revokeSession(throwError(() => new HttpErrorResponse({status:503})), warn);
assert.equal(warnings, 2);
revokeSession(NEVER, warn, 10);
setTimeout(() => {
  assert.equal(warnings, 3);
  console.log('Failed and timed-out session revocations are reported; success is accepted.');
}, 50);
