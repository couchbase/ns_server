import { useState, useEffect, useCallback, useContext } from 'react';
import mitt from 'mitt';

const useRootScope = () => {
  return useContext(RootScopeContext);
};

const useScope = (initialValues = {}, parentScope = null) => {
  const rootScope = useRootScope();
  parentScope = parentScope || rootScope;
  const [state, setState] = useState(initialValues);
  const emitter = mitt();
  const childScopes = [];
  const eventHandlers = [];

  const set = useCallback((property, value) => {
    setState(prevState => ({ ...prevState, [property]: value }));
  }, []);

  const del = useCallback((property) => {
    setState(prevState => {
      const newState = { ...prevState };
      delete newState[property];
      return newState;
    });
  }, []);

  const on = useCallback((type, handler) => {
    emitter.on(type, handler);
    eventHandlers.push({ type, handler });
    return () => {
      emitter.off(type, handler);
      const index = eventHandlers.findIndex(h => h.type === type && h.handler === handler);
      if (index !== -1) {
        eventHandlers.splice(index, 1);
      }
    };
  }, [emitter, eventHandlers]);

  const broadcast = useCallback((type, event) => {
    emitter.emit(type, event);
    childScopes.forEach(childScope => childScope.$broadcast(type, event));
  }, [emitter, childScopes]);

  const registerChildScope = useCallback((childScope) => {
    childScopes.push(childScope);
  }, [childScopes]);

  if (parentScope) {
    parentScope.registerChildScope({ $broadcast: broadcast });
  }

  useEffect(() => {
    return () => {
      emitter.emit('$destroy');
      eventHandlers.forEach(({ type, handler }) => {
        emitter.off(type, handler);
      });
    };
  }, [emitter, eventHandlers]);

  return {
    ...state,
    $set: set,
    $delete: del,
    $on: on,
    $broadcast: broadcast,
    registerChildScope,
  };
};

export { RootScopeProvider, useRootScope, useScope };

// Usage example
// const MyComponent = () => {
//   const rootScope = useRootScope();
//   const scope = useScope({ initProperty: 'initialValue' });

//   useEffect(() => {
//     const handler = (event) => {
//       console.log('Event received:', event);
//     };
//     const unsubscribe = scope.$on('myEvent', handler);

//     return () => {
//       unsubscribe();
//     };
//   }, [scope]);

//   const handleClick = () => {
//     scope.set('newProperty', 'newValue');
//     rootScope.$broadcast('myEvent', { data: 'someData' });
//   };

//   return (
//     <div>
//       <button onClick={handleClick}>Click me</button>
//     </div>
//   );
// };

// export { RootScopeProvider, useRootScope, useScope };