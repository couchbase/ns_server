/*
Copyright 2019-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/
import mnHelper from './mn_helper.js';
import { BehaviorSubject } from 'rxjs';

function mnStoreServiceFactory(mnHelper) {
  var db = {};
  var stores = {};
  var storeService = {
    createStore: createStore,
    store: store,
  };

  Store.prototype.get = get;
  Store.prototype.add = add;
  Store.prototype.put = put;
  Store.prototype.delete = _delete;
  Store.prototype.deleteItem = deleteItem;
  Store.prototype.getByIncludes = getByIncludes;
  Store.prototype.share = share;
  Store.prototype.shareSubject = shareSubject;
  Store.prototype.copy = copy;
  Store.prototype.last = last;
  Store.prototype.clear = clear;

  return storeService;

  function store(name) {
    return stores[name];
  }

  function createStore(name, options) {
    stores[name] = new Store(name, options);
  }

  function Store(name, options) {
    this.keyPath = options.keyPath;
    this.name = name;
    if (options.fill) {
      if (db[this.name]) {
        const currentValue = [];
        Array.prototype.push.apply(currentValue, options.fill);
        db[this.name].next(currentValue);
      } else {
        db[this.name] = new BehaviorSubject(options.fill);
      }
    } else {
      db[this.name] = new BehaviorSubject([]);
    }
  }

  function last() {
    return db[this.name].getValue()[db[this.name].getValue().length - 1];
  }

  function clear() {
    db[this.name].next([]);
  }

  function share() {
    return db[this.name].getValue();
  }

  function shareSubject() {
    return db[this.name];
  }

  function copy() {
    return db[this.name].getValue().slice();
  }

  function put(item) {
    var copyTo = this.get(item[this.keyPath]);
    var updatedItem = Object.assign({}, copyTo, item); // Create a new object with updated values
    var currentItems = db[this.name].getValue();
    var index = currentItems.findIndex(
      (i) => i[this.keyPath] === item[this.keyPath]
    );

    if (index !== -1) {
      currentItems[index] = updatedItem; // Update the copied item in the array
    }

    db[this.name].next(currentItems); // Emit the updated array
  }

  function add(item) {
    item = Object.assign({}, item);
    item[this.keyPath] = mnHelper.generateID();
    db[this.name].next(db[this.name].getValue().concat(item));
    return item;
  }

  function _delete(value) {
    db[this.name].next(
      db[this.name].getValue().filter((item) => item[this.keyPath] !== value)
    );
  }

  function deleteItem(item) {
    db[this.name].next(
      db[this.name]
        .getValue()
        .filter((item1) => item1[this.keyPath] !== item[this.keyPath])
    );
  }

  function get(value) {
    return db[this.name].getValue().find(
      function (item) {
        return item[this.keyPath] == value;
      }.bind(this)
    );
  }

  function getByIncludes(value, row) {
    return db[this.name].getValue().find(
      function (item) {
        return item[row].includes(value);
      }.bind(this)
    );
  }
}

const mnStoreService = mnStoreServiceFactory(mnHelper);
export default mnStoreService;
