import {UIRouter} from '/ui/web_modules/@uirouter/angular.js';
import {MnLifeCycleHooksToStream} from './mn.core.js';
import {Component, ChangeDetectionStrategy} from '/ui/web_modules/@angular/core.js';
import {filter, map, switchMap} from '/ui/web_modules/rxjs/operators.js';
import {BehaviorSubject, Subject, pipe, empty} from '/ui/web_modules/rxjs.js';
import {MnWizardService} from './mn.wizard.service.js';
import {MnAuthService} from "./mn.auth.service.js";
import {MnFormService} from "./mn.form.service.js";
import {MnPoolsService} from "./mn.pools.service.js"
import {MnHttpGroupRequest} from './mn.http.request.js';
import {MnSecurityService} from "./mn.security.service.js"
import {MnPools} from "./ajs.upgraded.providers.js";

export {MnWizardJoinClusterComponent};

class MnWizardJoinClusterComponent extends MnLifeCycleHooksToStream {

  static get annotations() { return [
    new Component({
      templateUrl: "/ui/app/mn.wizard.join.cluster.html",
      changeDetection: ChangeDetectionStrategy.OnPush
    })
  ]}

  static get parameters() { return [
    MnPoolsService,
    MnSecurityService,
    MnWizardService,
    MnAuthService,
    MnFormService,
    UIRouter,
    MnPools
  ]}

  constructor(mnPoolsService, mnSecurityService, mnWizardService, mnAuthService, mnFormService, uiRouter, mnPools) {
    super();

    this.focusFieldSubject = new BehaviorSubject("hostname");
    this.joinClusterForm = mnWizardService.wizardForm.joinCluster;
    this.hostnameHttp = mnWizardService.stream.hostnameHttp;
    this.diskStorageHttp = mnWizardService.stream.diskStorageHttp;
    this.joinClusterHttp = mnWizardService.stream.joinClusterHttp;

    this.certificate = mnPoolsService.stream.isEnterprise
      .pipe(switchMap((v) => v ? mnSecurityService.stream.getCertificate : empty() ));

    this.form = mnFormService.create(this);

    this.form
      .setPackPipe(pipe(
        filter(this.isValid.bind(this)),
        // filter(this.isNotLoading.bind(this)),
        map(() => this.joinClusterForm.get("clusterStorage.storage").value)
      ))
      .setPostRequest(this.diskStorageHttp)
      .setPackPipe(map(() => {
        var data = this.joinClusterForm.get("clusterAdmin").value;
        var services = this.joinClusterForm.get("services.flag");
        data.newNodeHostname = this.joinClusterForm.get("clusterStorage.hostname").value;
        data.services = mnWizardService.getServicesValues(services).join(",");
        return data;
      }))
      .setPostRequest(this.joinClusterHttp)
      .setPackPipe(map(() => this.joinClusterForm.get("clusterAdmin").value))
      .setPostRequest(mnAuthService.stream.postUILogin)
      .clearErrors()
      .success(() => {
        mnPools.clearCache();
        uiRouter.urlRouter.sync();
      });

    //    this.mnAppLoding = mnAppService.stream.loading;
    // Rx
    //   .merge(this.groupHttp.loading, this.joinClusterHttp.loading)
    //   .pipe(Rx.operators.takeUntil(this.mnOnDestroy))
    //   .subscribe(this.mnAppLoding.next.bind(this.mnAppLoding));
  }

  // isNotLoading() {
  //   return !this.mnAppLoding.getValue();
  // }

  isValid() {
    return !this.joinClusterForm.invalid;
  }
}
