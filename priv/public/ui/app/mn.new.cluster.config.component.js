import {UIRouter} from '/ui/web_modules/@uirouter/angular.js';
import {MnLifeCycleHooksToStream} from './mn.core.js';
import {Component, ChangeDetectionStrategy} from '/ui/web_modules/@angular/core.js';
import {takeUntil, filter, map, tap, withLatestFrom} from '/ui/web_modules/rxjs/operators.js';
import {BehaviorSubject, pipe} from '/ui/web_modules/rxjs.js';
import {MnWizardService} from './mn.wizard.service.js';
import {MnPoolsService} from './mn.pools.service.js';
import {MnFormService} from "./mn.form.service.js";
import {MnAuthService} from "./mn.auth.service.js";
import {MnAdminService} from "./mn.admin.service.js";
import {MnHttpGroupRequest} from "./mn.http.request.js";
import {MnPools} from "./ajs.upgraded.providers.js";

export {MnNewClusterConfigComponent};

class MnNewClusterConfigComponent extends MnLifeCycleHooksToStream {

  static get annotations() { return [
    new Component({
      templateUrl: "/ui/app/mn.new.cluster.config.html",
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
    MnPools
  ]}

  constructor(mnFormService, mnWizardService, mnAdminService, mnPoolsService, mnAuthService, uiRouter, mnPools) {
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

    this.form = mnFormService.create(this);

    this.form
      .setPackPipe(pipe(
        withLatestFrom(mnPoolsService.stream.isEnterprise),
        map(this.getHostConfigValues.bind(this)),
      ))
      .setPostRequest(new MnHttpGroupRequest({
        diskStorageHttp: mnWizardService.stream.diskStorageHttp,
        setupNetConfigHttp: mnWizardService.stream.setupNetConfigHttp,
        enableExternalListenerHttp: mnWizardService.stream.enableExternalListenerHttp,
      }).addSuccess())
      .setPackPipe(pipe(
        withLatestFrom(mnPoolsService.stream.isEnterprise),
        map(this.getWizardValues.bind(this))
      ))
      .setPostRequest(new MnHttpGroupRequest({
        postPoolsDefault: mnAdminService.stream.postPoolsDefault,
        hostnameHttp: mnWizardService.stream.hostnameHttp,
        statsHttp: mnWizardService.stream.statsHttp
      }).addSuccess())
      .setPackPipe(map(() => ({
        services: mnWizardService.getServicesValues(
          this.wizardForm.newClusterConfig.get("services.flag")
        ).join(",")
      })))
      .setPostRequest(mnWizardService.stream.servicesHttp)
      .setPackPipe(map(this.getFinalConfig.bind(this)))
      .setPostRequest(new MnHttpGroupRequest({
        indexesHttp: mnWizardService.stream.indexesHttp,
        authHttp: mnWizardService.stream.authHttp
      })
      .addSuccess())
      .setPackPipe(map(mnWizardService.getUserCreds.bind(mnWizardService)))
      .setPostRequest(mnAuthService.stream.postUILogin)
      .clearErrors()
      .success(() => {
        mnPools.clearCache();
        uiRouter.urlRouter.sync();
      });

        // this.mnAppLoding = mnAppService.stream.loading;

    // merge(
    //   mnWizardService.stream.groupHttp.loading,
    //   mnWizardService.stream.secondGroupHttp.loading
    // ).pipe(
    //   Rx.operators.takeUntil(this.mnOnDestroy)
    // ).subscribe(this.mnAppLoding.next.bind(this.mnAppLoding));
  }

  // isNotLoading() {
  //   return !this.mnAppLoding.getValue();
  // }

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

  getHostConfigValues(isEnterprise) {
    var clusterStor = this.wizardForm.newClusterConfig.get("clusterStorage");
    var rv = new Map();

    rv.set("diskStorageHttp", clusterStor.get("storage").value);

    if (isEnterprise[1]) {
      let val = {
        afamily: clusterStor.get("hostConfig.afamily").value ? "ipv6" : "ipv4",
        nodeEncryption: clusterStor.get("hostConfig.nodeEncryption").value ? 'on' : 'off'
      };
      rv.set("enableExternalListenerHttp", val);
      rv.set("setupNetConfigHttp", val);
    }

    return rv;
  }

  getWizardValues(isEnterprise) {
    return {
      hostnameHttp: this.wizardForm.newClusterConfig.get("clusterStorage.hostname").value,
      postPoolsDefault: [this.getPoolsDefaultValues.bind(this)(isEnterprise[1]), false],
      statsHttp: this.wizardForm.newClusterConfig.get("enableStats").value
    };
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
