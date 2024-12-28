import { useEffect, useMemo } from 'react';
import { Subject, BehaviorSubject } from 'rxjs';

function useLifeCycleHooksToStream(observable, initialValue) {
  const rv = useMemo(() => ({
    mnOnDestroy: new Subject(),
    mnOnChanges: new BehaviorSubject()
  }), []);

  useEffect(() => {
    return () => {
      rv.mnOnDestroy.next();
      rv.mnOnDestroy.complete();
    }
  }, [rv]);

  return rv;
}

export {useLifeCycleHooksToStream};
