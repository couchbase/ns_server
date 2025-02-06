import axios from 'axios';
import _ from 'lodash';
import { BehaviorSubject } from 'rxjs';
import mnBucketsService from '../mn_admin/mn_buckets_service.js';

const bucketSpecificPermissions = [
  function (name, buckets) {
    var basePermissions = [
      'cluster.bucket[' + name + '].settings!write',
      'cluster.bucket[' + name + '].settings!read',
      'cluster.bucket[' + name + '].recovery!write',
      'cluster.bucket[' + name + '].recovery!read',
      'cluster.bucket[' + name + '].stats!read',
      'cluster.bucket[' + name + ']!flush',
      'cluster.bucket[' + name + ']!delete',
      'cluster.bucket[' + name + ']!compact',
      'cluster.bucket[' + name + '].xdcr!read',
      'cluster.bucket[' + name + '].xdcr!write',
      'cluster.bucket[' + name + '].xdcr!execute',
      'cluster.bucket[' + name + '].n1ql.select!execute',
      'cluster.bucket[' + name + '].n1ql.index!read',
      'cluster.bucket[' + name + '].n1ql.index!write',
      'cluster.bucket[' + name + '].collections!read',
      'cluster.bucket[' + name + '].collections!write',
      'cluster.collection[' + name + ':.:.].stats!read',
      'cluster.collection[' + name + ':.:.].collections!read',
      'cluster.collection[' + name + ':.:.].collections!write',
    ];
    if (name === '.' || buckets.byName[name].isMembase) {
      basePermissions = basePermissions.concat([
        'cluster.bucket[' + name + '].views!read',
        'cluster.bucket[' + name + '].views!write',
        'cluster.bucket[' + name + '].views!compact',
      ]);
    }
    if (name === '.' || !buckets.byName[name].isMemcached) {
      basePermissions = basePermissions.concat([
        'cluster.bucket[' + name + '].data!write',
        'cluster.bucket[' + name + '].data!read',
        'cluster.bucket[' + name + '].data.docs!read',
        'cluster.bucket[' + name + '].data.docs!write',
        'cluster.bucket[' + name + '].data.docs!upsert',
        'cluster.bucket[' + name + '].n1ql.index!read',
        'cluster.collection[' + name + ':.:.].data.docs!read',
        'cluster.collection[' + name + ':.:.].data.docs!write',
        'cluster.collection[' + name + ':.:.].data.docs!upsert',
        'cluster.collection[' + name + ':.:.].n1ql.index!read',
        'cluster.collection[' + name + ':.:.].n1ql.index!write',
        'cluster.collection[' + name + ':.:.].n1ql.select!execute',
      ]);
    }

    return basePermissions;
  },
];

const interestingPermissions = [
  'cluster.buckets!create',
  'cluster.backup!read',
  'cluster.nodes!write',
  'cluster.pools!read',
  'cluster.server_groups!read',
  'cluster.server_groups!write',
  'cluster.settings!read',
  'cluster.settings!write',
  'cluster.settings.metrics!read',
  'cluster.settings.metrics!write',
  'cluster.stats!read',
  'cluster.tasks!read',
  'cluster.settings.indexes!read',
  'cluster.admin.internal!all',
  'cluster.xdcr.settings!read',
  'cluster.xdcr.settings!write',
  'cluster.xdcr.remote_clusters!read',
  'cluster.xdcr.remote_clusters!write',
  'cluster.admin.security!read',
  'cluster.admin.logs!read',
  'cluster.admin.settings!read',
  'cluster.admin.settings!write',
  'cluster.logs!read',
  'cluster.pools!write',
  'cluster.settings.indexes!write',
  'cluster.admin.security!write',
  'cluster.admin.security.admin!write',
  'cluster.admin.security.admin!read',
  'cluster.admin.security.external!write',
  'cluster.admin.security.external!read',
  'cluster.admin.security.local!read',
  'cluster.admin.security.local!write',
  'cluster.samples!read',
  'cluster.nodes!read',
  'cluster.admin.memcached!read',
  'cluster.admin.memcached!write',
  'cluster.eventing.functions!manage',
  'cluster.settings.autocompaction!read',
  'cluster.settings.autocompaction!write',
];

function getAll() {
  return _.clone(interestingPermissions);
}

function set(permission) {
  if (!_.includes(interestingPermissions, permission)) {
    interestingPermissions.push(permission);
  }
  return this;
}

function remove(permission) {
  let index = interestingPermissions.indexOf(permission);
  if (index > 0) {
    interestingPermissions.splice(index, 1);
  }
  return this;
}

function setBucketSpecific(func) {
  if (_.isFunction(func)) {
    bucketSpecificPermissions.push(func);
  }
  return this;
}

function generateBucketPermissions(bucketName, buckets) {
  return bucketSpecificPermissions.reduce(function (acc, getChunk) {
    return acc.concat(getChunk(bucketName, buckets));
  }, []);
}

const mnPermissions = {
  clear,
  get: doCheck,
  check,
  setBucketSpecific,
  set,
  stream: new BehaviorSubject(),
  remove,
  throttledCheck: _.debounce(getFresh, 200),
  getFresh,
  getBucketPermissions,
  getPerScopePermissions,
  getPerCollectionPermissions,
  export: new BehaviorSubject({
    data: {},
    cluster: {},
    default: {
      all: undefined,
      membase: undefined,
    },
  }),
};

let cache;

interestingPermissions.push(generateBucketPermissions('.'));

function getPerScopePermissions(bucketName, scopeName) {
  let any = bucketName + ':' + scopeName + ':.';
  let all = bucketName + ':' + scopeName + ':*';
  return [
    'cluster.collection[' + any + '].data.docs!read',
    'cluster.collection[' + all + '].collections!write',
    'cluster.collection[' + any + '].n1ql.select!execute',
  ];
}
function getPerCollectionPermissions(bucketName, scopeName, collectionName) {
  let params = bucketName + ':' + scopeName + ':' + collectionName;
  return [
    'cluster.collection[' + params + '].data.docs!read',
    'cluster.collection[' + params + '].n1ql.select!execute',
  ];
}

function clear() {
  // TODO: check whether we need to clear rbac
  // delete mnPermissions.export.getValue().rbac;
  mnPermissions.export.next({
    ...mnPermissions.export.getValue(),
    cluster: {},
    data: {},
  });
  clearCache();
}

function clearCache() {
  cache = null;
}

function getFresh() {
  clearCache();
  return mnPermissions.check();
}

function getBucketPermissions(bucketName) {
  return mnBucketsService.getBucketsByType().then(function (bucketsDetails) {
    return generateBucketPermissions(bucketName, bucketsDetails);
  });
}

function check() {
  if (cache) {
    return Promise.resolve(mnPermissions.export.getValue());
  }

  return doCheck(['cluster.bucket[.].settings!read'])
    .then(function (resp) {
      let permissions = getAll();
      if (resp.data['cluster.bucket[.].settings!read']) {
        return mnBucketsService
          .getBucketsByType()
          .then(function (bucketsDetails) {
            if (bucketsDetails.length) {
              bucketsDetails.forEach(function (bucket) {
                permissions = permissions.concat(
                  generateBucketPermissions(bucket.name, bucketsDetails)
                );
              });
            }
            return doCheck(permissions).then(function (resp) {
              let bucketNamesByPermission = {};
              let bucketCollectionsNames = {};
              let permissions = resp.data;
              bucketsDetails.forEach(function (bucket) {
                let interesting = generateBucketPermissions(
                  bucket.name,
                  bucketsDetails
                );
                interesting.forEach(function (permission) {
                  let bucketPermission = permission.split(
                    '[' + bucket.name + ']'
                  )[1];
                  let collectionPermission = permission.split(
                    '[' + bucket.name + ':.:.]'
                  )[1];

                  bucketNamesByPermission[bucketPermission] =
                    bucketNamesByPermission[bucketPermission] || [];

                  bucketCollectionsNames[collectionPermission] =
                    bucketCollectionsNames[collectionPermission] || [];

                  if (bucketPermission && permissions[permission]) {
                    bucketNamesByPermission[bucketPermission].push(bucket.name);
                  }

                  if (collectionPermission && permissions[permission]) {
                    bucketCollectionsNames[collectionPermission].push(
                      bucket.name
                    );
                  }
                });
              });
              resp.bucketNames = bucketNamesByPermission;
              resp.bucketCollectionsNames = bucketCollectionsNames;
              return resp;
            });
          });
      } else {
        return doCheck(permissions);
      }
    })
    .then(function (resp) {
      cache = convertIntoTree(resp.data);

      mnPermissions.export.next({
        ...mnPermissions.export.getValue(),
        data: resp.data,
        cluster: cache.cluster,
        bucketNames: resp.bucketNames || {},
        bucketCollectionsNames: resp.bucketCollectionsNames || {},
      });

      return mnPermissions.export.getValue();
    });
}

function convertIntoTree(permissions) {
  let rv = {};
  _.forEach(permissions, function (value, key) {
    let levels = key.split(/[[\]]+/);
    let regex = /[.:!]+/;
    if (levels[1]) {
      levels = _.compact(
        levels[0]
          .split(regex)
          .concat([levels[1]])
          .concat(levels[2].split(regex))
      );
    } else {
      levels = levels[0].split(regex);
    }
    let path = levels.shift() + "['" + levels.join("']['") + "']"; //in order to properly handle bucket names
    _.set(rv, path, value);
  });
  return rv;
}

function doCheck(interestingPermissions) {
  return axios.post(
    '/pools/default/checkPermissions',
    interestingPermissions.join(',')
  );
}

export default mnPermissions;
