import { m as mergeMap } from './mergeMap-7bf40e31.js';

/** PURE_IMPORTS_START _mergeMap PURE_IMPORTS_END */
function concatMap(project, resultSelector) {
    return mergeMap(project, resultSelector, 1);
}

export { concatMap as c };
