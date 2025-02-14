Follow these instructions to convert Angular components to React Class Components.

## 1. Your Role

You are expert in converting Angular components to React Class Components.
You will be provided with examples specific to this project on how conversion
must be done in addition to your knowledge.

You will be provided with examples right after "For example:" words. Consider them
as example patterns, the actual code can be different and it depends on particular file.

Important! Apply them only when you actually encounter similar pattern in the code.

## 1. Leave Class extension in place Do not change anything here React Class should extend MnLifeCycleHooksToStream.

For example:

```javascript
// Instead of
  ...
  class MnWizardComponent extends MnLifeCycleHooksToStream {
  ...
// Do
  ...
  class MnWizardComponent extends MnLifeCycleHooksToStream {
  ...
```

## 2. Remove Angular annotations and parameters props

For example:

```javascript
// Instead of
  ...
  static get annotations() { return [
    ...
  ]}
  ...
  static get parameters() { return [
    ...
  ]}
// Do
  ...
```

## 3. Place code from constructor to componentDidMount function almost as is. Only change what is required in further instructions.

For example:

```javascript
// Instead of
  ...
  constructor(...props) {
    super();
    //code to copy over
  }
  ...
// Do
  ...
  constructor(props) {
    super(props);
    this.state = {
      ...
    };
  }
  componentDidMount() {
    super.componentDidMount();
    //code to paste
  }
  ...
```

## 4. Angular services and DI must be converted to simple React singletons import

Any service must be imported as a singletons instance. Angualr service ends with Service postfix
MnAuthService, MnFormService, MnAdminService. React Functional Components doesn't have 'annotations'
and 'parameters' properties and 'constructor'. therefor we import them directly

Example of conversion

```javascript
// Instead of
  import {MnFormService} from './mn.form.service.js';
  ...
  static get parameters() { return [
    MnFormService,
    ...
  ...
  constructor(mnFormService, ....
  ...
  mnFormService.create(this)
  ...
// Do
  import {MnFormService} from './mn.form.service.js';
  ...
  MnFormService.create(this)
  ...
```

## 5. Replacement of @uirouter/angular with @uirouter/react

You must familiarise yourself with

- useObservable @uirouter/angular implementation.
- MnHttpRequest @uirouter/react implementation.
- UIRouter defenition ns_server/priv/public/ui/app/mn.react.router.js

You will see imports of UIRouter in Angualr. They must replaced like

Example of convertsion

```javascript
// Instead of
import { UIRouter } from '@uirouter/angular';
// Do
import { UIRouter } from 'mn.react.router';
```

And then use it directly

```javascript
// Instead of
  uiRouter.stateService.go('app.authCh.....
// Do
  UIRouter.stateService.go('app.authCh.....
```

## 6. Convert Angular inputs to React props

For example:

```javascript
// Instead of
  ...
  inputs: [
    service,
    ...
  ]
  ...
  this.service...
// Do
  ...
  constructor(props) {
    ...
  }
  ...
  const {service, ...} = this.props;
```

## 7. If there is code in ngOnInit method in Angular combine it with Insturction ## 3.

Place the code to componentDidMount from ngOnInit

## 8. Convert all values read by async pipe to react states

For example:

```
// Instead of
...
this.indexesHttp = mnWizardService.stream.indexesHttp;
this.totalRAMMegs = MnWizardService.stream.totalRAMMegs;
...
<div
    class="error error-field"
    [hidden]="!(indexesHttp.error | async)?.errors?.storageMode">
  {{(indexesHttp.error | async)?.errors?.storageMode | mnFormatStorageModeError}}
</div>
// Do
this.state = {
  indexesHttpError: null,
  totalRAMMegs: null
}
...
// we extract error and value from the HTTP streams
this.indexesHttpError = mnWizardService.stream.indexesHttp.error;
MnHelperReactService.async(this, 'indexesHttpError');

this.totalRAMMegs = MnWizardService.stream.totalRAMMegs;
MnHelperReactService.async(this, 'totalRAMMegs');
...
<div
    className="error error-field"
    hidden={!this.state.indexesHttpError}>
  {mnFormatStorageModeError(this.state.indexesHttpError?.errors?.storageMode)}}
</div>
```

## 9. Convert react-reactive-form valueChanges to streams

```javascript
// Instead of
...
this.indexFlag.valueChanges.pipe(takeUntil(this.mnOnDestroy))...
...
// and if you see statusChanges
...
this.indexFlag.statusChanges.pipe(takeUntil(this.mnOnDestroy))...
...
//Do
...
MnHelperReactService.valueChanges(this, this.props.indexFlag.valueChanges).pipe(takeUntil(this.mnOnDestroy))...
...
// and if you see statusChanges
...
MnHelperReactService.valueChanges(this, this.props.indexFlag.statusChanges).pipe(takeUntil(this.mnOnDestroy))...
```

## 10. Conversion of Angular reactive forms to their analogue in React.

You must familiarise yourself with

- react-reactive-form. https://github.com/bietkul/react-reactive-form
- ns_server/priv/public/ui/app/mn.form.service.js

When you see pattern like 'this.form = mnFormService.create(this)...' follwed by medthods like
setFormGroup, setPackPipe, setPostRequest, error, success. This means you have faced our custom
form helper. you must familiarise yourself with its implementation, see #mn.form.service.js based
on Angualr reactive forms. React has similar library called react-reactive-form.
You must convert them to React analogue like this:

Here is example of convertsion

```javascript
// Instead of
  this.certAuth = mnFormService.create(this)
    ...
// Do
  this.certAuth = MnFormService.create(this)
    .setFormGroup({})
    ...
```

## 10.1 the elements with ngSubmit and formGroup must be converted like this:

Here is example of convertsion

// Instead of

```html
....
<form
  (ngSubmit)="form.submit.next()"
  [formGroup]="form.group"
  class="forms"
  novalidate
>
  ...
</form>
```

// Do

```jsx
<FieldGroup
    control={form.group}
    render={({ get, invalid }) => (
      <form onSubmit={form.submit.next()} novalidate className="forms">
        ...
```

## 10.2 the form elements with formControlName attributes must be converted like this:

Here is example of convertsion

// Instead of

```html
<div class="formrow">
  <input
    autocorrect="off"
    spellcheck="false"
    autocapitalize="off"
    type="text"
    id="auth-username-input"
    name="username"
    placeholder="Username"
    formControlName="user"
    [mnFocus]="focusFieldSubject"
  />
  <div [hidden]="!form.group.get('user').dirty" class="error error-field">
    <div [hidden]="!form.group.get('user').errors?.required">
      Username is required.
    </div>
  </div>
</div>
```

// Do

```jsx
 <FieldControl
    name="user"
    strict={false}
    render={({ handler, touched, hasError, meta }) => (
      <div  className="formrow">
        <input
          autocorrect="off"
          spellcheck="false"
          autocapitalize="off"
          type="text"
          id="auth-username-input"
          name="username"
          placeholder="Username"
          // fieldType: '' | 'checkbox' | 'radio' | 'switch'
          // for normal text/number inputs use ''
          autoFocus {...handler(fieldType)}/>
        <div hidden={!touched}
             class="error error-field">
          <div [hidden]="!hasError("required")">Username is required.</div>
        </div>
      </div>
    )}
    meta={{ label: "Username" }}
  />
```

## 10.3 the submit button must rely on render arguments when necessary

Example:

in this case we take invalid from FieldGroup, eg.

<FieldGroup
control={form.group}
strict={false}
render={({ get, invalid }) => (

// Instead of

````html
<div class="panel-footer flex-end">
  <button [disabled]="form.group.invalid" type="submit">Sign In</button>
</div>
//Do ```jsx
<div className="panel-footer flex-end">
  <button disabled="{invalid}" type="submit">Sign In</button>
</div>
````

## 10.4 when using MnInputFilter add the focus functionality by adding mnFocus and mnName props; mnFocus should be a Subject

initially emitting the value of mnName prop.Example:
in constructor:

```jsx
this.doFocusFilter = new Subject();
```

in componentDidMount:

```jsx
this.doFocusFilter.next('filter');
```

in render:

```jsx
<MnInputFilter
  group={this.filter.group}
  mnFocus={this.doFocusFilter}
  mnName="filter"
  mnPlaceholder="filter logs..."
  mnClearDisabled={false}
/>
```

## 11. don't change anything else. The component logic and code should stay as much as possible to original.

## 12. save the result into separate file
