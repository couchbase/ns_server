import {UIRouter} from '/ui/web_modules/@uirouter/angular.js';
import {MnLifeCycleHooksToStream} from './mn.core.js';
import {Component, ChangeDetectionStrategy} from '/ui/web_modules/@angular/core.js';
import {takeUntil, filter, map,
        tap, withLatestFrom, first} from '/ui/web_modules/rxjs/operators.js';
import {BehaviorSubject, pipe} from '/ui/web_modules/rxjs.js';
import {MnWizardService} from './mn.wizard.service.js';
import {MnPoolsService} from './mn.pools.service.js';
import {MnFormService} from "./mn.form.service.js";
import {MnAuthService} from "./mn.auth.service.js";
import {MnAdminService} from "./mn.admin.service.js";
import {MnHttpGroupRequest} from "./mn.http.request.js";
import {MnPools, $rootScope} from "./ajs.upgraded.providers.js";

export {MnWizardNewClusterConfigComponent};

class MnWizardNewClusterConfigComponent extends MnLifeCycleHooksToStream {

  static get annotations() { return [
    new Component({
      templateUrl: "/ui/app/mn.wizard.new.cluster.config.html",
      changeDetection: ChangeDetectionStrategy.OnPush
    })
  ]}

  static get parameters() { return [
    MnFormService,
    MnWizardService,
    MnAdminService,
    MnPoolsService,
    // MnAppService,
    MnAuthService,
    UIRouter,
    MnPools,
    $rootScope
  ]}

  constructor(mnFormService, mnWizardService, mnAdminService, mnPoolsService, mnAuthService, uiRouter, mnPools, $rootScope) {
    super();

    this.wizardForm = mnWizardService.wizardForm;
    this.newClusterConfigForm = mnWizardService.wizardForm.newClusterConfig;
    this.getServicesValues = mnWizardService.getServicesValues.bind(mnWizardService);

    this.totalRAMMegs = mnWizardService.stream.totalRAMMegs;
    this.maxRAMMegs = mnWizardService.stream.maxRAMMegs;
    this.memoryQuotasFirst = mnWizardService.stream.memoryQuotasFirst;

    this.servicesHttp = mnWizardService.stream.servicesHttp;
    this.groupHttp = mnWizardService.stream.groupHttp;

    this.isEnterprise = mnPoolsService.stream.isEnterprise;

    this.isButtonDisabled =
      mnAdminService.stream.postPoolsDefault.error
      .pipe(map((error) => error && !!Object.keys(error.errors).length));

    mnWizardService.stream.getSelfConfig
      .pipe(first())
      .subscribe(v => mnWizardService.setSelfConfig(v));

    this.form = mnFormService.create(this);

    this.form
      .setPackPipe(pipe(
        withLatestFrom(mnPoolsService.stream.isEnterprise),
        map(this.getHostConfigValues.bind(this)),
      ))
      .setPostRequest(new MnHttpGroupRequest({
        diskStorageHttp: mnWizardService.stream.diskStorageHttp,
        postPoolsDefault: mnAdminService.stream.postPoolsDefault,
        enableExternalListenerHttp: mnWizardService.stream.enableExternalListenerHttp
      }).addSuccess().addError())
      .setPackPipe(pipe(
        withLatestFrom(mnPoolsService.stream.isEnterprise),
        map(this.getWizardValues.bind(this))
      ))
      .setPostRequest(new MnHttpGroupRequest({
        setupNetConfigHttp: mnWizardService.stream.setupNetConfigHttp,
        statsHttp: mnWizardService.stream.statsHttp,
        servicesHttp: mnWizardService.stream.servicesHttp
      }).addSuccess().addError())
      .setPostRequest(mnWizardService.stream.disableUnusedExternalListenersHttp)
      .setPackPipe(map(() =>
                       this.wizardForm.newClusterConfig.get("clusterStorage.hostname").value))
      .setPostRequest(mnWizardService.stream.hostnameHttp)
      .setPackPipe(map(this.getFinalConfig.bind(this)))
      .setPostRequest(new MnHttpGroupRequest({
        indexesHttp: mnWizardService.stream.indexesHttp,
        authHttp: mnWizardService.stream.authHttp
      }).addSuccess().addError())
      .setPackPipe(map(mnWizardService.getUserCreds.bind(mnWizardService)))
      .setPostRequest(mnAuthService.stream.postUILogin)
      .clearErrors()
      .showGlobalSpinner()
      .success(() => {
        $rootScope.mnGlobalSpinnerFlag = true;
        mnPools.clearCache();
        uiRouter.urlRouter.sync();
      });
  }

  getFinalConfig(isEnterprise) {
    var rv = new Map();
    rv.set("authHttp", [this.wizardForm.newCluster.value.user, false]);

    if (this.wizardForm.newClusterConfig.get("services.flag").value.index) {
      rv.set("indexesHttp", {
        storageMode: this.wizardForm.newClusterConfig.get("storageMode").value
      });
    }
    return rv;
  }

  getHostConfig() {
    var clusterStor = this.wizardForm.newClusterConfig.get("clusterStorage");
    return {
      afamily: clusterStor.get("hostConfig.afamily").value ? "ipv6" : "ipv4",
      nodeEncryption: clusterStor.get("hostConfig.nodeEncryption").value ? 'on' : 'off'
    }
  }

  getHostConfigValues(isEnterprise) {
    var clusterStor = this.wizardForm.newClusterConfig.get("clusterStorage");
    var rv = new Map();

    rv.set("diskStorageHttp", clusterStor.get("storage").value);
    rv.set("postPoolsDefault", [this.getPoolsDefaultValues.bind(this)(isEnterprise[1]), false]);

    if (isEnterprise[1]) {
      rv.set("enableExternalListenerHttp", this.getHostConfig());
    }

    return rv;
  }

  getWizardValues(isEnterprise) {
    let rv = {
      statsHttp: this.wizardForm.termsAndConditions.get("enableStats").value,
      servicesHttp: {
        services: this.getServicesValues(this.wizardForm
                                         .newClusterConfig.get("services.flag")).join(",")
      }
    };
    if (isEnterprise[1]) {
      rv.setupNetConfigHttp = this.getHostConfig();
    }
    return rv;
  }

  getPoolsDefaultValues(isEnterprise) {
    var services = [
      ["memoryQuota", "kv"],
      ["indexMemoryQuota", "index"],
      ["ftsMemoryQuota", "fts"]
    ];
    if (isEnterprise) {
      services.push(["eventingMemoryQuota", "eventing"]);
      services.push(["cbasMemoryQuota", "cbas"]);
    }
    return services.reduce(this.getPoolsDefaultValue.bind(this), {
      clusterName: this.wizardForm.newCluster.get("clusterName").value
    });
  }

  getPoolsDefaultValue(result, names) {
    var service = this.wizardForm.newClusterConfig.get("services.flag." + names[1]);
    if (service && service.value) {
      result[names[0]] =
        this.wizardForm.newClusterConfig.get("services.field." + names[1]).value;
    }
    return result;
  }
}
