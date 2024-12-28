import { HttpClient as AngularHttpClient, HttpXhrBackend, HttpHandler } from '@angular/common/http';
import { MnHttpInterceptor } from 'mn.http.interceptor';

// Create the backend handler
const backend = new HttpXhrBackend({ build: () => new XMLHttpRequest() });

// Create a custom handler that uses your interceptor
class InterceptorHandler extends HttpHandler {
  constructor(next, interceptor) {
    super();
    this.next = next;
    this.interceptor = interceptor;
  }
  handle(req) {
    return this.interceptor.intercept(req, this.next);
  }
}

// Create the handler chain
const handler = new InterceptorHandler(backend, MnHttpInterceptor);

// Create the HTTP client with your handler
const HttpClient = new AngularHttpClient(handler);

export { HttpClient };