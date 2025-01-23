/*
Copyright 2020-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

// import {Pipe} from '@angular/core';
// import {DecimalPipe} from '@angular/common';
// import {is} from 'ramda';
// import {map} from 'rxjs/operators';

// import {MnHelperService} from './mn.helper.service.js';
// import {MnAdminService} from './mn.admin.service.js';
// import {servicesEnterprise} from './constants/constants.js';

export {
  MnParseVersion,
  // MnMBtoBytes,
  // MnBytesToMB,
  // MnObjectKeys,
  MnPrettyVersion,
  // MnFormatProgressMessage,
  // MnFormatStorageModeError,
  // MnPrepareQuantity,
  // MnFormatUptime,
  // MnFormatQuantity,
  // MnFormatWarmupMessage,
  // MnBucketsType,
  // MnConflictResolutionType,
  // MnTruncate,
  // MnTruncateTo3Digits,
  // MnFormatServices,
  // MnOrderServices,
  // MnStripPortHTML
}

// class MnTruncate {
//   static get annotations() { return [
//     new Pipe({name: "mnTruncate"})
//   ]}

//   transform(value, limit, trail, isLeft) {
//     trail = trail != undefined ? trail : "...";
//     limit = limit || 15;
//     if (value.length > limit) {
//       if (isLeft) {
//         return trail + value.substring(value.length - limit, value.length);
//       } else {
//         return value.substring(0, limit) + trail;
//       }
//     } else {
//       return value;
//     }
//   }
// }

// class MnTruncateTo3Digits {
//   static get annotations() { return [
//     new Pipe({name: "mnTruncateTo3Digits"})
//   ]}

//   transform(value, minScale, roundMethod) {
//     if (!value) {
//       return 0;
//     }

//     let scale = [100, 10, 1, 0.1, 0.01, 0.001].find(v => value >= v) || 0.0001;
//     if (minScale != undefined && minScale > scale) {
//       scale = minScale;
//     }
//     scale = 100 / scale;
//     return Math[roundMethod || "round"](value * scale)/scale;
//   }
// }

class MnParseVersionClass {
  transform(str) {
    if (!str) {
      return;
    }
    // Expected string format:
    //   {release version}-{build #}-{Release type or SHA}-{enterprise / community}
    // Example: "1.8.0-9-ga083a1e-enterprise"
    var a = str.split(/[-_]/);
    if (a.length === 3) {
      // Example: "1.8.0-9-enterprise"
      //   {release version}-{build #}-{enterprise / community}
      a.splice(2, 0, undefined);
    }
    a[0] = (a[0].match(/[0-9]+\.[0-9]+\.[0-9]+/) || ["0.0.0"])[0];
    a[1] = a[1] || "0";
    // a[2] = a[2] || "unknown";
    // We append the build # to the release version when we display in the UI so that
    // customers think of the build # as a descriptive piece of the version they're
    // running (which in the case of maintenance packs and one-off's, it is.)
    a[3] = (a[3] && (a[3].substr(0, 1).toUpperCase() + a[3].substr(1))) || "DEV";
    return a; // Example result: ["1.8.0-9", "9", "ga083a1e", "Enterprise"]
  }
}

const MnParseVersion = new MnParseVersionClass();


// class MnMBtoBytes {
//   static get annotations() { return [
//     new Pipe({name: "mnMBtoBytes"})
//   ]}

//   static get parameters() { return [
//     MnHelperService
//   ]}

//   constructor(mnHelperService) {
//     this.IEC = mnHelperService.IEC;
//   }

//   transform(MB) {
//     return MB * this.IEC.Mi;
//   }
// }


// class MnBytesToMB {
//   static get annotations() { return [
//     new Pipe({name: "mnBytesToMB"})
//   ]}

//   static get parameters() { return [
//     MnHelperService
//   ]}

//   constructor(mnHelperService) {
//     this.IEC = mnHelperService.IEC;
//   }

//   transform(bytes) {
//     return Math.floor(bytes / this.IEC.Mi);
//   }
// }


// class MnObjectKeys {
//   static get annotations() { return [
//     new Pipe({name: "mnObjectKeys"})
//   ]}

//   transform(object) {
//     if (object) {
//       return Object.keys(object);
//     } else {
//       return [];
//     }
//   }
// }


class MnPrettyVersionClass {
  constructor(mnParseVersion) {
    this.mnParseVersion = mnParseVersion;
  }

  transform(str, full) {
    if (!str) {
      return;
    }
    var a = this.mnParseVersion.transform(str);
    // Example default result: "Enterprise Edition 1.8.0-7  build 7"
    // Example full result: "Enterprise Edition 1.8.0-7  build 7-g35c9cdd"
    var suffix = "";
    if (full && a[2]) {
      suffix = '-' + a[2];
    }
    return [a[3], "Edition", a[0], "build",  a[1] + suffix].join(' ');
  }
}

const MnPrettyVersion = new MnPrettyVersionClass(MnParseVersion);


// class MnFormatProgressMessage {
//   static get annotations() { return [
//     new Pipe({name: "mnFormatProgressMessage"})
//   ]}

//   addNodeCount(perNode) {
//     var serversCount = Object.keys(perNode || {}).length;
//     return serversCount + " " + (serversCount === 1 ? 'node' : 'nodes');
//   }

//   transform(task) {
//     switch (task.type) {
//     case "indexer":
//       return "building view index " + task.bucket + "/" + task.designDocument;
//     case "global_indexes":
//       return "building index " + task.index  + " on bucket " + task.bucket;
//     case "view_compaction":
//       return "compacting view index " + task.bucket + "/" + task.designDocument;
//     case "bucket_compaction":
//       return "compacting bucket " + task.bucket;
//     case "loadingSampleBucket":
//       return "loading sample: " + task.bucket;
//     case "orphanBucket":
//       return "orphan bucket: " + task.bucket;
//     case "clusterLogsCollection":
//       return "collecting logs from " + this.addNodeCount(task.perNode);
//     case "rebalance":
//       return (task.subtype == 'gracefulFailover') ?
//         "failing over 1 node" :
//         ("rebalancing " + this.addNodeCount(task.perNode));
//     }
//   }
// }


// class MnFormatStorageModeError {
//   static get annotations() { return [
//     new Pipe({name: "mnFormatStorageModeError"})
//   ]}

//   transform(error) {
//     if (!error) {
//       return;
//     }
//     var errorCode =
//         error.indexOf("Storage mode cannot be set to") > -1 ? 1 :
//         error.indexOf("storageMode must be one of") > -1 ? 2 :
//         0;
//     switch (errorCode) {
//     case 1:
//       return "please choose another index storage mode";
//     case 2:
//       return "please choose an index storage mode";
//     default:
//       return error;
//     }
//   }
// }



// class MnPrepareQuantity {
//   static get annotations() { return [
//     new Pipe({name: "mnPrepareQuantity"})
//   ]}

//   transform(value, K) {
//     K = K || 1024;

//     var M = K*K;
//     var G = M*K;
//     var T = G*K;

//     if (K !== 1024 && K !== 1000) {
//       throw new Error("Unknown number system");
//     }

//     var t = ([[T,'T'],[G,'G'],[M,'M'],[K,'K']]).find(function (t) {
//       return value >= t[0];
//     }) || [1, ''];

//     if (K === 1024) {
//       t[1] += t[1] ? 'iB' : 'B';
//     }

//     return t;
//   }
// }



// class MnFormatUptime {
//   static get annotations() { return [
//     new Pipe({name: "mnFormatUptime"})
//   ]}

//   transform(seconds, precision) {
//     precision = precision || 8;

//     var arr = [[86400, "days", "day"],
//                [3600, "hours", "hour"],
//                [60, "minutes", "minute"],
//                [1, "seconds", "second"]];

//     var rv = [];

//     arr.forEach(function (item) {
//       var period = item[0];
//       var value = (seconds / period) >> 0;
//       seconds -= value * period;
//       if (value) {
//         rv.push(String(value) + ' ' + (value > 1 ? item[1] : item[2]));
//       }
//       return !!--precision;
//     });
//     return rv.join(', ');
//   }
// }



// class MnFormatQuantity {
//   static get annotations() { return [
//     new Pipe({name: "mnFormatQuantity"})
//   ]}

//   static get parameters() { return [
//     MnPrepareQuantity,
//     DecimalPipe,
//     MnTruncateTo3Digits
//   ]}

//   constructor(mnPrepareQuantity, decimalPipe, mnTruncateTo3Digits) {
//     this.mnPrepareQuantity = mnPrepareQuantity;
//     this.decimalPipe = decimalPipe;
//     this.mnTruncateTo3Digits = mnTruncateTo3Digits;
//   }

//   transform(value, numberSystem, spacing) {
//     if (!value && !is(Number, value)) {
//       return value;
//     }
//     if (!spacing) {
//       spacing = '';
//     }
//     if (numberSystem === 1000 && value <= 1100 && value % 1 === 0) { // MB-11784
//       return value;
//     }

//     var t = this.mnPrepareQuantity.transform(value, numberSystem);
//     return [this.mnTruncateTo3Digits.transform(value/t[0], undefined, 'floor'), spacing, t[1]].join('');
//   }
// }

// class MnFormatWarmupMessage {
//   static get annotations() { return [
//     new Pipe({name: "mnFormatWarmupMessage"})
//   ]}

//   transform(task) {
//     var message = task.stats.ep_warmup_state;
//     switch (message) {
//     case "loading keys":
//       return message + " (" + task.stats.ep_warmup_key_count + " / " + task.stats.ep_warmup_estimated_key_count + ")";
//     case "loading data":
//       return message + " (" + task.stats.ep_warmup_value_count + " / " + task.stats.ep_warmup_estimated_value_count + ")";
//     default:
//       return message;
//     }
//   }
// }



// class MnBucketsType {
//   static get annotations() { return [
//     new Pipe({name: "mnBucketsType"})
//   ]}

//   transform(type) {
//     switch (type) {
//     case "membase":
//       return "Couchbase";
//     case "ephemeral":
//     case "memcached": // TODO: remove once backend no longer supports memcached buckets
//       return type.charAt(0).toUpperCase() + type.slice(1);
//     }
//   }
// }

// class MnConflictResolutionType {
//   static get annotations() { return [
//     new Pipe({name: "mnConflictResolutionType"})
//   ]}

//   transform(type) {
//     switch (type) {
//       case 'lww':
//         return 'Timestamp';
//       case "seqno":
//         return 'Sequence Number';
//       case "custom":
//         return 'Custom';
//     }
//   }
// }


// class MnFormatServices {
//   static get annotations() { return [
//     new Pipe({name: "mnFormatServices"})
//   ]}

//   transform(service) {
//     switch (service) {
//       case 'kv': return 'Data';
//       case 'query':
//       case 'n1ql': return 'Query';
//       case 'index': return 'Index';
//       case 'fts': return 'Search';
//       case 'eventing': return 'Eventing';
//       case 'cbas': return 'Analytics';
//       case 'backup': return 'Backup';
//       default: return service;
//     }
//   }
// }

// class MnOrderServices {
//   static get annotations() { return [
//     new Pipe({name: "mnOrderServices"})
//   ]}

//   transform(services) {
//     return services.slice().sort((a, b) =>
//       servicesEnterprise.indexOf(a) - servicesEnterprise.indexOf(b));
//   }
// }

// class MnStripPortHTML {
//   static get annotations() { return [
//     new Pipe({name: "mnStripPortHTML"})
//   ]}

//   static get parameters() { return [
//     MnAdminService
//   ]}

//   constructor(mnAdminService) {
//     this.mnAdminService = mnAdminService;
//   }

//   transform(hostname) {
//     return this.mnAdminService.stream.isStrippingPort
//       .pipe(map((v) => v ? hostname.replace(/:8091$/, '') : hostname));
//   }
// }
