/*
Copyright 2020-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import {MnWizardComponent} from './mn.wizard.component.jsx';
import {MnWizardWelcomeComponent} from './mn.wizard.welcome.component.jsx';
import {MnWizardSetupNewClusterComponent} from './mn.wizard.setup.new.cluster.component.jsx';
import {MnWizardTermsAndConditionsComponent} from './mn.wizard.terms.and.conditions.component.jsx';
import {MnWizardNewClusterConfigComponent} from './mn.wizard.new.cluster.config.component.jsx';
import {MnWizardJoinClusterComponent} from './mn.wizard.join.cluster.component.jsx';


export const states = [{
  name: 'app.wizard',
  abstract: true,
  component: MnWizardComponent
}, {
  name: 'app.wizard.welcome',
  component: MnWizardWelcomeComponent
}, {
  name: "app.wizard.setupNewCluster",
  component: MnWizardSetupNewClusterComponent
}, {
  name:'app.wizard.termsAndConditions',
  component: MnWizardTermsAndConditionsComponent
}, {
  name: 'app.wizard.clusterConfiguration',
  component: MnWizardNewClusterConfigComponent
}, {
  name: 'app.wizard.joinCluster',
  component: MnWizardJoinClusterComponent
},
];

