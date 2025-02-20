# subcomponent-conversion

## 1. Replace Angular subcomponent rendering with React subcomponent

```diff
-  <mn-security-audit-user-activity-role
-    group={form.group.get('userActivity')}
-    roleDescriptors={userActivityUIRoles}
-    moduleName={name}
-  />
+  <MnSecurityAuditUserActivityRoleComponent
+    group={form.group.get('userActivity')}
+    roleDescriptors={this.userActivityUIRoles}
+    moduleName={name}
+  />
```

## 2. Add empty component template

`mn.security.audit.item.component.jsx`:

```jsx
import React from 'react';
import { MnLifeCycleHooksToStream } from 'mn.core';

export class MnSecurityAuditItemComponent extends MnLifeCycleHooksToStream {
  constructor(props) {
    super(props);
    this.state = {};
  }

  componentDidMount() {}

  render() {
    return <>mn.security.audit.item.html conversion goes here</>;
  }
}
```

## 3. Prompt

```text
Following tips from @ng2.component.prompt.md, succesfully convert @mn.security.audit.user.activity.role.component.js and it's template @mn.security.audit.user.activity.role.html into @mn.security.audit.component.jsx, trying to follow the established patterns.

The end goal is meant to be a fully working converted component that integrates well with the main @mn.security.audit.component.jsx component.
```

### Code context

- add lines from [1. Replace Angular subcomponent rendering with React subcomponent](#1-replace-angular-subcomponent-rendering-with-react-subcomponent)

## 4. Cleanup

See [conversion errors guide](../conversion-errors-guide.md).

## Tips

### Subcomponent props

When passing props down to a subcomponent, if a stream inside the subcomponent depends on the prop, pass in the stream, not a primitive object.

`main.component.jsx`:

```jsx
// componentDidMount()
this.userActivityUIGroups = combineLatest(
  this.getUIUserGroups,
  this.getUserActivity
).pipe(
  map(this.getUIUserGroupsMap.bind(this)),
  shareReplay({ refCount: true, bufferSize: 1 })
);
// MnHelperReactService.async(this, 'userActivityUIGroups')

// ...

// render()
<MnSecurityAuditUserActivityGroupsComponent
  group={form.group.get('userActivity')}
  // We're passing in a stream instead of this.state.userActivityUIGroups
  groupDescriptors={this.userActivityUIGroups}
/>;
```

`angular.subcomponent.js`:

```js
this.groupDescriptors
  .pipe(takeUntil(this.mnOnDestroy))
  .subscribe(this.generateForm.bind(this));
```

`subcomponent.component.jsx` (conversion):

```jsx
// componentDidMount()
// Conversion as-is from angular, except we split the .pipe and .subscribe operations into separate lines to make MnHelperReactService.async() work
this.groupDescriptors = this.props.groupDescriptors.pipe(
  takeUntil(this.mnOnDestroy)
);
this.groupDescriptors.subscribe(this.generateForm.bind(this));
MnHelperReactService.async(this, 'groupDescriptors');
```

Since we're initializing our subscriptions in `componentDidMount()`, and a prop is not an observable, we would not receive fresh prop changes to `this.generateForm`.
