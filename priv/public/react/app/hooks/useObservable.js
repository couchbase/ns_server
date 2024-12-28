import { useEffect, useState } from 'react';

/**
 * Custom React hook to extract value from an RxJS observable.
 * @param {Observable} observable - The RxJS observable to subscribe to.
 * @param {any} initialValue - The initial value to set before the observable emits.
 * @returns {any} - The latest value emitted by the observable.
 */
function useObservable(observable, initialValue) {
  const [value, setValue] = useState(initialValue);

  useEffect(() => {
    const subscription = observable.subscribe(setValue);
    return () => subscription.unsubscribe();
  }, [observable]);

  return value;
}

export {useObservable};
