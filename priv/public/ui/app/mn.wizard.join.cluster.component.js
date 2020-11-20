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
import {MnPools, $rootScope} from "./ajs.upgraded.providers.js";

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
    MnPools,
    $rootScope
  ]}

  constructor(mnPoolsService, mnSecurityService, mnWizardService, mnAuthService, mnFormService, uiRouter, mnPools, $rootScope) {
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
      .showGlobalSpinner()
      .success(() => {
        $rootScope.mnGlobalSpinnerFlag = true;
        mnPools.clearCache();
        uiRouter.urlRouter.sync();
      });
  }

  isValid() {
    return !this.joinClusterForm.invalid;
  }
}
