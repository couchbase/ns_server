import {MnWizardService} from './mn.wizard.service.js';
import {MnLifeCycleHooksToStream} from './mn.core.js';
import {MnPoolsService} from './mn.pools.service.js';
import {MnAdminService} from "./mn.admin.service.js";
import {first} from '/ui/web_modules/rxjs/operators.js';
import {FormGroup, FormControl} from '/ui/web_modules/@angular/forms.js';
import {Component, ChangeDetectionStrategy} from '/ui/web_modules/@angular/core.js';

export {MnWizardComponent};

class MnWizardComponent extends MnLifeCycleHooksToStream {

  static get annotations() { return [
    new Component({
      templateUrl: '/ui/app/mn.wizard.html',
      changeDetection: ChangeDetectionStrategy.OnPush
    })
  ]}

  static get parameters() { return [
    MnWizardService,
    MnPoolsService,
    MnAdminService
  ]}

  constructor(mnWizardService, mnPoolsService, mnAdminService) {
    super();
    var newClusterConfig = mnWizardService.wizardForm.newClusterConfig;
    var joinCluster = mnWizardService.wizardForm.joinCluster;
    //MnExceptionHandlerService.stream.appException.subscribe(MnExceptionHandlerService.send);

    mnAdminService.stream.implementationVersion
      .pipe(first())
      .subscribe(function (implementationVersion) {
        mnWizardService.initialValues.implementationVersion = implementationVersion;
      });

    mnWizardService.stream.getSelfConfigFirst
      .subscribe(function (selfConfig) {
        var hostname = selfConfig['otpNode'].split('@')[1] || '127.0.0.1';
        if (hostname == "cb.local") {
          hostname = "127.0.0.1";
        }
        newClusterConfig.get("clusterStorage.hostname").setValue(hostname);
        joinCluster.get("clusterStorage.hostname").setValue(hostname);
        newClusterConfig.get("clusterStorage.hostConfig").patchValue({
          afamily: selfConfig.addressFamily == "inet6",
          nodeEncryption: selfConfig.nodeEncryption
        });
        mnWizardService.initialValues.hostname = hostname;
      });

    function servicesToGroup(services, value) {
      return new FormGroup(services.reduce(function (acc, name) {
        acc[name] = new FormControl(value);
        return acc;
      }, {}));
    }

    mnPoolsService.stream.mnServices.pipe(first())
      .subscribe(function (services) {
        newClusterConfig.get("services").addControl("flag", servicesToGroup(services, true));
        joinCluster.get("services").addControl("flag", servicesToGroup(services, true));
        newClusterConfig.get("services.flag.kv").disable({onlySelf: true});
      });

    mnPoolsService.stream.quotaServices.pipe(first())
      .subscribe(function (services) {
        newClusterConfig.get("services").addControl("field", servicesToGroup(services, null));
      });

    mnPoolsService.stream.isEnterprise.pipe(first())
      .subscribe(function (isEnterprise) {
        var storageMode = isEnterprise ? "plasma" : "forestdb";
        newClusterConfig.get("storageMode").setValue(storageMode);

        if (!isEnterprise) {
          joinCluster.get("clusterStorage.storage.cbas_path").disable({onlySelf: true});
          newClusterConfig.get("clusterStorage.storage.cbas_path").disable({onlySelf: true});
        }

        mnWizardService.initialValues.storageMode = storageMode;
      });

    mnWizardService.stream.initHddStorage.pipe(first())
      .subscribe(function (initHdd) {
        newClusterConfig.get("clusterStorage.storage").patchValue(initHdd);
        joinCluster.get("clusterStorage.storage").patchValue(initHdd);

        mnWizardService.initialValues.clusterStorage = initHdd;
      });
  }
}
