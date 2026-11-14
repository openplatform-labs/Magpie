import { Injectable, inject } from '@angular/core';
import { HttpInterceptorFn } from '@angular/common/http';
import { Observable, Subject, takeUntil, timeout } from 'rxjs';

@Injectable({ providedIn: 'root' })
export class SessionLifecycle {
  private readonly ended = new Subject<void>();
  readonly ended$ = this.ended.asObservable();
  end(): void { this.ended.next(); }
}

// Do not cancel the server-side session revocation itself on a later login.
export const sessionCancellationInterceptor: HttpInterceptorFn = (request, next) => {
  const protectedRequest = request.url.startsWith('/admin/');
  if (!protectedRequest || request.url === '/admin/sessions/current') return next(request);
  return next(request).pipe(takeUntil(inject(SessionLifecycle).ended$));
};

export function revokeSession(request: Observable<unknown>, onUncertain: () => void, timeoutMs = 5000): void {
  request.pipe(timeout({first: timeoutMs})).subscribe({error: () => onUncertain()});
}
