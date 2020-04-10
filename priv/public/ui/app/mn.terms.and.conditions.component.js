import {UIRouter} from '/ui/web_modules/@uirouter/angular.js';
import {MnLifeCycleHooksToStream} from './mn.core.js';
import {Component, ChangeDetectionStrategy} from '/ui/web_modules/@angular/core.js';
import {BehaviorSubject, Subject, pipe} from '/ui/web_modules/rxjs.js';
import {takeUntil, filter, map, tap, withLatestFrom,
        switchMap} from '/ui/web_modules/rxjs/operators.js';
import {MnWizardService} from './mn.wizard.service.js';
import {MnPoolsService} from './mn.pools.service.js';
import {MnFormService} from "./mn.form.service.js";
import {MnAuthService} from "./mn.auth.service.js";
import {MnHttpGroupRequest} from "./mn.http.request.js";
import {MnAdminService} from "./mn.admin.service.js";
import {MnPools} from "./ajs.upgraded.providers.js";

export {MnTermsAndConditionsComponent};

class MnTermsAndConditionsComponent extends MnLifeCycleHooksToStream {
  static get annotations() { return [
    new Component({
      templateUrl: "/ui/app/mn.terms.and.conditions.html",
      changeDetection: ChangeDetectionStrategy.OnPush
    })
  ]}

  static get parameters() { return [
    MnAdminService,
    MnWizardService,
    MnPoolsService,
    MnFormService,
    MnAuthService,
    UIRouter,
    MnPools
  ]}

  constructor(mnAdminService, mnWizardService, mnPoolsService, mnFormService, mnAuthService, uiRouter, mnPools) {
    super();

    this.focusFieldSubject = new BehaviorSubject(true);
    this.form = mnFormService.create(this);
    this.defaultForm = mnFormService.create(this);

    mnWizardService.wizardForm.termsAndConditions.get("agree").setValue(false);

    this.uiRouter = uiRouter;
    this.isEnterprise = mnPoolsService.stream.isEnterprise;
    this.wizardForm = mnWizardService.wizardForm;
    this.initialValues = mnWizardService.initialValues;

    this.groupHttp = mnWizardService.stream.groupHttp;
    this.secondGroupHttp = mnWizardService.stream.secondGroupHttp;
    this.servicesHttp = mnWizardService.stream.servicesHttp;
    this.mnWizardService = mnWizardService;

    this.license = mnPoolsService.stream.isEnterprise
      .pipe(switchMap(this.getLicense.bind(this)));

    this.termsHref = mnPoolsService.stream.isEnterprise
      .pipe(map(this.getTermsAndCond.bind(this)));

    this.form
      .setFormGroup(mnWizardService.wizardForm.termsAndConditions)
      .setPackPipe(filter(this.isValid.bind(this)))
      .hasNoPostRequest()
      .success(this.onSuccess.bind(this));

    this.defaultForm
      .setPackPipe(pipe(
        filter(this.isValid.bind(this)),
        // filter(this.isNotLoading.bind(this)),
        withLatestFrom(mnPoolsService.stream.isEnterprise),
        map((isEnterprise) => ({
          services: 'kv,index,fts,n1ql' + (isEnterprise[1] ? ',eventing,cbas' : ''),
          setDefaultMemQuotas : true
        }))
      ))
      .setPostRequest(mnWizardService.stream.servicesHttp)
      .setPackPipe(pipe(
        withLatestFrom(mnPoolsService.stream.isEnterprise),
        map(this.getValues.bind(this))
      ))
      .setPostRequest(new MnHttpGroupRequest({
        postPoolsDefault: mnAdminService.stream.postPoolsDefault,
        hostnameHttp: mnWizardService.stream.hostnameHttp,
        statsHttp: mnWizardService.stream.statsHttp
      }).addSuccess())
      .setPackPipe(pipe(
        withLatestFrom(mnPoolsService.stream.isEnterprise),
        map(this.getSecondValues.bind(this))
      ))
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




    //     this.mnAppLoding = mnAppService.stream.loading;
    // Rx
    //   .merge(
    //     this.groupHttp.loading,
    //     this.secondGroupHttp.loading
    //   )
    //   .pipe(
    //     Rx.operators.takeUntil(this.mnOnDestroy)
    //   )
    //   .subscribe(this.mnAppLoding.next.bind(this.mnAppLoding));
  }

  // isNotLoading() {
  //   return !this.mnAppLoding.getValue();
  // }

  onSuccess() {
    this.uiRouter.stateService.go('app.wizard.clusterConfiguration', null, {location: false});
  }

  isValid() {
    return !this.form.group.invalid;
  }

  getLicense(isEnterprise) {
    return isEnterprise ?
      this.mnWizardService.getEELicense():
      this.mnWizardService.getCELicense();
  }

  getTermsAndCond(isEnterprise) {
    return isEnterprise ?
      'https://www.couchbase.com/ESLA05242016' :
      'https://www.couchbase.com/community';
  }

  getSecondValues(isEnterprise) {
    return {
      indexesHttp: {
        storageMode: isEnterprise[1] ? "plasma" : "forestdb"
      },
      authHttp: [this.wizardForm.newCluster.value.user, false]
    };
  }

  getValues(isEnterprise) {
    return {
      postPoolsDefault: [{
        clusterName: this.wizardForm.newCluster.get("clusterName").value
      }, false],
      hostnameHttp: this.initialValues.hostname,
      statsHttp: this.wizardForm.termsAndConditions.get("enableStats").value
    };
  }
}
