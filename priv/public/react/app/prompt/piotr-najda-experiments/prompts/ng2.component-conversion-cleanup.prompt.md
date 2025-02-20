# ng2.component-conversion-cleanup.prompt

You have just convereted an Angular component to React. Evaluate if any of the fixes below need to be applied.

1. Constructor should be used for initializing state only and not for subscriptions,
2. Make sure `form.group.get` calls that use `.pipe` are wrapped with `MnHelperReactService.valueChanges`,

## componentDidMount / componentWillMount

1. Make sure that values read by async pipe are converted to React State, are observed with MnReactHelperService.async

## Fix imports

1. `ajs.upgraded.providers` -> `import mnPermissions from 'components/mn_permissions',
2. `import { MnSpinner } from './components/directives/mn_spinner.jsx';`

## Render function

1. Replace `mn-main-spinner` with `MnSpinner`,
2. . Make sure that values observed by `async` pipe are converted to React State and used properly in `render` function
3. Comment out unconverted Angular HTML code in the `render` function
4. `strict={false}` should be added to all `FieldControl` and `FieldGroup` elements,
5. Make sure form's `onSubmit` is not `onSubmit={form.submit.next()}`, use an arrow function instead,
6. Replace `mn-select` with MnSelect and pass in `onSelect={({ selectedOption })}` and `mnDisabled`,
