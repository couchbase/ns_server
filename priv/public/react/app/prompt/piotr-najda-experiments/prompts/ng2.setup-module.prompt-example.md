# ng2.setup-module.prompt-example

This is just the setup for actual component conversion - the actual conversion will be done later, don't worry about it.

## Example

### Input

#### State Declaration - `ui/app/mn.security.saml.module.js`

```js
// Imports...

let samlState = {
  url: '/saml',
  name: 'app.admin.security.saml',
  data: {
    permissions:
      'cluster.admin.security.external.read || cluster.admin.users.external.read',
    enterprise: true,
    compat: 'atLeast76',
  },
  component: MnSecuritySamlComponent,
};

export { MnSecuritySamlModule };

// class MnSecuritySamlModule ...
```

#### Import - `ui/app/mn.app.imports.js`

```js
let samlState = {
  name: 'app.admin.security.saml.**',
  url: '/saml',
  lazyLoad: mnLoadNgModule(
    () => import('./mn.security.saml.module.js'),
    'MnSecuritySamlModule'
  ),
};
```

## Output

### `main.jsx`

```jsx
let samlState = {
  name: 'app.admin.security.saml.**',
  url: '/saml',
  lazyLoad: () => import('./mn.security.saml.states.js'),
};

// ...

router.stateRegistry.register(samlState);
```

### Create a State Declaration - `react/app/mn.security.saml.states.js`

- The URL should be equivalent to that in the original Angular 2 module.
- `.module.js` has become `states.js`

```jsx
import { MnSecuritySamlComponent } from './mn.security.saml.component.jsx';

let samlState = {
  url: '/saml',
  name: 'app.admin.security.saml',
  data: {
    permissions: ({ cluster }) =>
      cluster.admin.security.external.read || cluster.admin.users.external.read,
    enterprise: true,
    compat: 'atLeast76',
  },
  component: MnSecuritySamlComponent,
};

export const states = [samlState];
```

### Create a Component Template - `react/app/mn.security.saml.component.jsx`

```jsx
import React from 'react';
import { MnLifeCycleHooksToStream } from 'mn.core';

export class MnSecuritySamlComponent extends MnLifeCycleHooksToStream {
  constructor(props) {
    super(props);
    this.state = {};
  }

  componentDidMount() {}

  render() {
    return <>mn.security.saml.html conversion goes here</>;
  }
}
```
