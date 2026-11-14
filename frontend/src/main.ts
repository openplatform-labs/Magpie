import { provideZoneChangeDetection } from '@angular/core';
import { bootstrapApplication } from '@angular/platform-browser';
import { provideHttpClient, withInterceptors } from '@angular/common/http';
import { AppComponent } from './app/app.component';
import { sessionCancellationInterceptor } from './app/session-lifecycle';

bootstrapApplication(AppComponent, { providers: [provideHttpClient(withInterceptors([sessionCancellationInterceptor])), provideZoneChangeDetection()] }).catch(console.error);
