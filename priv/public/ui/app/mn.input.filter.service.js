import {Injectable} from "/ui/web_modules/@angular/core.js";
import {FormBuilder} from "/ui/web_modules/@angular/forms.js";
import {shareReplay, debounceTime, startWith, map} from '/ui/web_modules/rxjs/operators.js';

import {combineLatest} from "/ui/web_modules/rxjs.js";

export {MnInputFilterService}

class MnInputFilterService {
  static get annotations() { return [
    new Injectable()
  ]}

  static get parameters() { return [
    FormBuilder
  ]}

  constructor(formBuilder) {
    this.formBuilder = formBuilder;
  }

  create(listAsStream) {
    var filterInput = this.formBuilder.group({value: ""});

    var filterFunction = ([list, filterValue]) =>
        list ? list.filter(item => item.name.includes(filterValue)) : [];

    var filterInputValues =
        filterInput.get("value").valueChanges.pipe(debounceTime(200),
                                                   startWith(""));

    var filteredList =
        combineLatest(listAsStream, filterInputValues)
        .pipe(map(filterFunction),
              shareReplay({refCount: true, bufferSize: 1}));

    return {result: filteredList, group: filterInput};
  }

}
