import '@angular/compiler';
import { strict as assert } from 'node:assert';
import { ChangeDetectorRef, Injector, runInInjectionContext } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Subject } from 'rxjs';
import { AppComponent } from '../src/app/app.component';
import { SessionLifecycle } from '../src/app/session-lifecycle';

const posts: {url:string; body:any; result:Subject<any>}[] = [];
const http = {post: (url:string, body:any) => {const result = new Subject<any>(); posts.push({url,body,result}); return result.asObservable();}};
const injector = Injector.create({ providers: [SessionLifecycle, {provide:HttpClient, useValue:http},
  {provide:ChangeDetectorRef, useValue:{markForCheck(){}}}] });
const component = runInInjectionContext(injector, () => new AppComponent());
(globalThis as any).requestAnimationFrame = () => 0;
(globalThis as any).confirm = () => true;
component.refreshBudgets = () => {};
component.refreshObservability = () => {};

component.selectReservation({request_id:'a', request_status:'error'} as any);
component.settledAmount = '1'; component.reconcileNote = 'receipt';
component.reconcileBudget(); component.reconcileBudget();
assert.equal(posts.length, 1);
component.selectReservation({request_id:'b', request_status:'error'} as any);
component.settledAmount = '2'; component.reconcileNote = 'new note';
posts[0].result.next({}); posts[0].result.complete();
assert.equal(component.selectedReservation?.request_id, 'b');
assert.equal(component.settledAmount, '2');
assert(!component.reconcileSubmitting);

component.adjustmentHistory = {request_id:'a', settled_amount:'1'} as any;
component.adjustmentRequest = 'a'; component.adjustmentId = 'id-a'; component.adjustmentAmount = '2'; component.adjustmentNote = 'receipt';
component.adjustBudget(); component.adjustBudget();
assert.equal(posts.length, 2);
component.clearAdjustment();
component.adjustmentHistory = {request_id:'b', settled_amount:'3'} as any;
component.adjustmentRequest = 'b'; component.adjustmentId = 'id-b'; component.adjustmentAmount = '4'; component.adjustmentNote = 'new receipt';
posts[1].result.next({}); posts[1].result.complete();
assert.equal(component.adjustmentHistory?.request_id, 'b');
assert.equal(component.adjustmentAmount, '4');
assert.equal(component.adjustmentNote, 'new receipt');
assert(!component.adjustmentSubmitting && !component.adjustmentNeedsRefresh);

component.adjustBudget();
component.adjustmentAmount = '5';
posts[2].result.next({}); posts[2].result.complete();
assert(component.adjustmentNeedsRefresh);
assert.equal(component.adjustmentAmount, '5');
component.adjustBudget();
assert.equal(posts.length, 3);
console.log('Budget submissions do not close or overwrite a newer selection, and changed adjustments require refresh.');
