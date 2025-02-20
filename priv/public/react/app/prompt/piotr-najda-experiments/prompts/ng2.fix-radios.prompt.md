# ng2.fix-radios.prompt

Where applicable, refactor all input `type="radio"` radio buttons to this pattern:

```jsx
<FieldControl
  strict={false}
  name="spBaseURLType"
  render={({ handler }) => {
    // (1) - The field is destructured
    const field = handler('switch');
    return (
      <>
        <input
          type="radio"
          id="for-base-url-node"
          value="node"
          checked={field.value === 'node'}
          {...field}
        />
        // ...
        <input
          type="radio"
          id="for-base-url-alternate"
          value="alternate"
          // (2) - Has checked prop
          checked={field.value === 'alternate'}
          // (3) - Has {...field}
          {...field}
        />
        // ...
        <input
          type="radio"
          id="for-base-url-custom"
          value="custom"
          checked={field.value === 'custom'}
          {...field}
        />
        // ...
      </>
    );
  }}
/>
```

Check if applicable and refactor radio button by radio button in the file, to not lose context.
