/*
Copyright 2020-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/
import React from 'react';
import { UIView } from '@uirouter/react';
import { first, combineLatest } from 'rxjs/operators';
import { FormGroup, FormControl } from 'react-reactive-form';

import { MnWizardService } from './mn.wizard.service.js';
import { MnLifeCycleHooksToStream } from './mn.core.js';
import { MnPoolsService } from './mn.pools.service.js';
import { MnAdminService } from './mn.admin.service.js';

export class MnWizardComponent extends MnLifeCycleHooksToStream {
  constructor(props) {
    super(props);
  }

  componentDidMount() {
    var newClusterConfig = MnWizardService.wizardForm.newClusterConfig;
    var joinCluster = MnWizardService.wizardForm.joinCluster;

    MnAdminService.stream.implementationVersion
      .pipe(first())
      .subscribe(function (implementationVersion) {
        MnWizardService.initialValues.implementationVersion =
          implementationVersion;
      });

    MnWizardService.stream.getSelfConfig
      .pipe(first())
      .subscribe((v) => MnWizardService.setSelfConfig(v));

    function servicesToGroup(services, value) {
      return new FormGroup(
        services.reduce(function (acc, name) {
          acc[name] = new FormControl(value);
          return acc;
        }, {})
      );
    }

    MnPoolsService.stream.mnServices
      .pipe(first())
      .subscribe(function (services) {
        newClusterConfig
          .get('services')
          .addControl('flag', servicesToGroup(services, true));
        joinCluster
          .get('services')
          .addControl('flag', servicesToGroup(services, true));
        newClusterConfig.get('services.flag.kv').disable({ onlySelf: true });
      });

    MnPoolsService.stream.quotaServices
      .pipe(first())
      .subscribe(function (services) {
        newClusterConfig
          .get('services')
          .addControl('field', servicesToGroup(services, ''));
      });

    let isEnterpriseStream = MnPoolsService.stream.isEnterprise.pipe(first());

    isEnterpriseStream.subscribe(function (isEnterprise) {
      var storageMode = isEnterprise ? 'plasma' : 'forestdb';
      newClusterConfig.get('storageMode').setValue(storageMode);

      if (!isEnterprise) {
        joinCluster
          .get('clusterStorage.storage.cbas_path')
          .disable({ onlySelf: true });
        newClusterConfig
          .get('clusterStorage.storage.cbas_path')
          .disable({ onlySelf: true });
      }

      MnWizardService.initialValues.storageMode = storageMode;
    });

    MnWizardService.stream.initHddStorage
      .pipe(first(), combineLatest(isEnterpriseStream))
      .subscribe(function ([initHdd, isEnterprise]) {
        setStorageConfigValues(newClusterConfig, initHdd, isEnterprise);
        setStorageConfigValues(joinCluster, initHdd, isEnterprise);

        MnWizardService.initialValues.clusterStorage = initHdd;
      });

    function setStorageConfigValues(config, initHdd, isEnterprise) {
      if (isEnterprise) {
        initHdd.cbas_path.forEach((dir, index) => {
          config
            .get('clusterStorage.storage.cbas_path')
            .setControl(index, new FormControl(null), {
              emitEvent: false,
            });
        });
      }
      if (config === newClusterConfig && isEnterprise) {
        newClusterConfig.get('javaPath').setValue(initHdd.java_home);
      }
      config.get('clusterStorage.storage').patchValue(initHdd);
    }
  }

  render() {
    return (
      <>
        <div className="sign-in-background"></div>
        <div className="page-wrap">
          <div className="row items-center padding-bottom-6">
            <UIView />
          </div>
        </div>
        <footer className="footer-wizard">
          Copyright © 2024
          <a
            href="https://www.couchbase.com/"
            target="_blank"
            rel="noopener noreferrer"
          >
            Couchbase, Inc.
          </a>
          All rights reserved.
        </footer>
      </>
    );
  }
}
