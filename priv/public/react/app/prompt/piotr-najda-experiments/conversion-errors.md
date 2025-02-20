# conversion-errors

Beyond the items here, see if executing [ng2.component-conversion-cleanup.prompt](ng2.component-conversion-cleanup.prompt.md) can help you.

## I can't type in my input

See [ng2.component-conversion-cleanup.prompt](ng2.component-conversion-cleanup.prompt.md)

## 'split' is not a function

If your `FieldControl` uses a numeric id, you will need to `.toString()` the `FieldControl`'s `name` property, or else a cryptic `.split` error will appear.

```js
<FieldControl
  name={desc.id.toString()}
  // ...
/>
```

## Not all data is passed from a subcomponent to the `prepareFormForSend` function

Change `this.form.group.value` to `this.form.group.getRawValue()` in preparing form data.

## "Maximum call stack size exceeded"

Check if AI didn't forget to pass in `distinctUntilChanged` to the `pipe` function, or if it forgot to use a previously defined variable and instead used the `valueChanges` helper (without `distinctUntilChanged`).
