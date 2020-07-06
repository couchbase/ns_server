import { BehaviorSubject } from "/ui/web_modules/rxjs.js";
import { shareReplay } from '/ui/web_modules/rxjs/operators.js';
import { Injectable } from "/ui/web_modules/@angular/core.js";

export { MnTasksService }

class MnTasksService {
  static get annotations() { return [
    new Injectable()
  ]}

  static get parameters() { return [
  ]}

  constructor() {
    this.stream = {};
    this.stream.tasksXDCRPlug = new BehaviorSubject();
    this.stream.tasksXDCR = this.stream.tasksXDCRPlug
      .pipe(shareReplay({refCount: true, bufferSize: 1}));
  }
}
