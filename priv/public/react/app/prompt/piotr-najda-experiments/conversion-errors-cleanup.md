# Conversion Cleanup

[Conversion Errors Guide](./conversion-errors-guide.md)

## Instructions

You have just convereted an Angular component to React. Evaluate if any of the fixes below need to be applied.

1. Fix `ajs.upgraded.providers` import,
2. Constructor should be used for initializing state only and not for subscriptions,
3. Make sure `form.group.get` calls that use `.pipe` are wrapped with `MnHelperReactService.valueChanges`,
4. Make sure that values read by async pipe are converted to React State, are observed with MnReactHelperService.async and destructured in `render` function,
5. Replace `mn-main-spinner` with `MnSpinner`,
6. Comment out unconverted Angular HTML code in the `render` function
7. Make sure to destructure props & state,
8. `strict={false}` should be added to all `FieldControl` and `FieldGroup` elements,
9. Make sure form's `onSubmit` is not `onSubmit={form.submit.next()}`, use an arrow function instead,
10. Make sure proper `handler` type is passed to input fields,
11. Replace `mn-select` with MnSelect and pass in `onSelect={({ selectedOption })}` and `mnDisabled`,

For reference, see [ng2.component.prompt.md](../ng2.component.prompt.md).
