export { U as UIRouterRx, a as UIRouterRxPlugin } from '../common/ui-router-rx-c01ce02c.js';
import { O as Observable } from '../common/mergeMap-7bf40e31.js';
import { o as of } from '../common/filter-9cc11002.js';
import { s as shareReplay, f as first } from '../common/shareReplay-7455a2cc.js';
import '../common/ReplaySubject-e07a4c19.js';
import '../common/tslib.es6-89c1b43d.js';
import '../common/Notification-58af84b8.js';
import '../common/EmptyError-a9e17542.js';
import '../common/take-f711bbe2.js';
import '../common/ArgumentOutOfRangeError-91c779f5.js';

/**
 * Determines the unwrapping behavior of asynchronous resolve values.
 *
 *   - When an Observable is returned from the resolveFn, wait until the Observable emits at least one item.
 *     If any other value will be converted to an Observable that emits such value.
 *   - The Observable item will not be unwrapped.
 *   - The Observable stream itself will be provided when the resolve is injected or bound elsewhere.
 *
 * #### Example:
 *
 * The `Transition` will wait for the `main.home` resolve observables to emit their first value.
 * Promises will be unwrapped and returned as observables before being provided to components.
 * ```js
 * var mainState = {
 *   name: 'main',
 *   resolve: mainResolves, // defined elsewhere
 *   resolvePolicy: { async: RXWAIT },
 * }
 * ```
 */
function RXWAIT(resolveFnValue) {
    if (!(resolveFnValue instanceof Observable)) {
        resolveFnValue = of(resolveFnValue);
    }
    var data$ = resolveFnValue.pipe(shareReplay(1));
    return data$
        .pipe(first())
        .toPromise()
        .then(function () {
        return data$;
    });
}

export { RXWAIT };
