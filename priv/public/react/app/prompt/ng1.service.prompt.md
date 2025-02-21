Follow these instructions to convert Angular components to React

## 1. Your Role

You are expert in converting AngularJS (Angular 1+) to React Service (Simple Objects).
You will be provided with examples specific to this project on how conversion
must be done in addition to your knowledge.

You will be provided with examples right after "For example:" words. Consider them
as example patterns, the actual code can be different and it depends on particular file.

Important! Apply them only when you actually encounter similar pattern in the code.

Important! Do not miss a single line of the input code during conversion.

## 2. AngularJS service's module and factory should be removed

For example:

```javascript
// Instead of
...
angular
  .module('mnPools', [])
  .factory('mnPools', ["$http", "$cacheFactory", mnPoolsFactory]);

  function mnPoolsFactory($http, $cacheFactory) {
    var mnPools = {
      get: get,
      clearCache: clearCache,
      getFresh: getFresh,
      export: {}
    };
...
// Do
  var mnPools = {
      get: get,
      clearCache: clearCache,
      getFresh: getFresh,
      export: {}
    };
```

## 2. Replace this Service 'export' prop with BehaviorSubject from rxjs only in case exported

service has 'export' property

For example:

```javascript
// Instead of
var mnPools = {
  ...
  export: {}
  ...
};
// Do
var mnPools = {
  ...
  export: new BehaviorSubject({})
  ...
};
```

and then use the following pattern in case we update value in service methods:

```javascript
// Instead of
  ...
  Object.assign(mnPools.export, pools);
  ...
// Do
  ...
  mnPools.export.next(Object.assign(structuredClone(mnPools.export.getValue()), pools));
  ...
```

## 3. Imported service 'export' prop is now BehaviorSubject therefore you must do:

```javascript
// Instead of
  ...
  mnPoolDefault.export.compat ....
  ...
// Do
  ...
  mnPoolDefault.export.getValue().compat ....
  ...
```

## 4. Use axios from 'axios' istead of AngularJS $http service. Pay attention that the

following example uses properties as an example the axios props must be equivalent to
the actual one in the code

You must familiarise yourself with

- axios https://github.com/axios/axios

For example:

```javascript
// Instead of
  ...
  $http({
    ...
    method: 'GET',
    url: '/pools',
    cache: true,
    mnHttp: mnHttpParams,
    ...
  })
  ...
// Do
  ...
  axios.get('/pools', {
    ...
    mnHttp: mnHttpParams
    ...
  })
  ...
```

## 5. Convert cache: true to just variable that keeps cache

For example:

```javascript
// Instead of
  ...
  $http({
    ...
    cache: true,
    ...
  })
  ...
// Do
  ...
  var cache;
  ..
  if (cache) {
    return Promise.resolve(cache);
  }
  ...
  cache = pools;
  ...
  cache = null;
```

## 6. Export result service like this:

Example:

```javascript
export { Service };
```

## 7. Convert $uibModal to our uibModal analogue using useModal context.

For example:

// Instead of

```javascript
...
  var scope = $rootScope.$new();
  scope.partitioned = row.partitioned;
  $uibModal.open({
    windowClass: "z-index-10001",
    backdrop: 'static',
    template: mnGsiDropConfirmDialogTemplate,
    scope: scope,
    resolve: {
      indexSettings: async () => {
        return await settingsClusterService.getIndexSettings();
      },
      firstTimeAddedServices: () => {
        return firstTimeAddedServices; // Synchronous resolver
      }
    },
  }).result.then(function () {
    //on success
  }, function () {
    //on error
  });
...
```

// Do

```jsx
  import { useModal } from 'uib/template/modal/window.and.backdrop'
  ...
  const { openModal } = useModal();

  ...
  // Using a promise wrapper
  openModal({
    windowClass: "z-index-10001",
    backdrop: 'static',
    component: MnGsiDropConfirmDialogComponent,
    props: scope, // or props: {partitioned: row.partitioned},
    resolve: {
      indexSettings: async () => {
        return await settingsClusterService.getIndexSettings();
      },
      firstTimeAddedServices: () => {
        return firstTimeAddedServices; // Synchronous resolver
      }
    }
  }).then(function () {
    //on success
  }, function () {
    //on error
  });
...
```

## 7. replace angularJS helpers with lodash ones:

For example:

- replace "angular.isFunction(..." with "\_.isFunction(...)"
- replace "$parse(path).assign(rv, value);" with "\_.set(rv, path, value);"
