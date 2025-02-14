# Conversion Errors Guide

## I can't type in my input

See point 9 in [Conversion Cleanup](./conversion-errors-cleanup.md).

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
