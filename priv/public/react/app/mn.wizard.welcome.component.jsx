/*
Copyright 2020-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import React from 'react';
import { BehaviorSubject } from 'rxjs';
import { MnLifeCycleHooksToStream } from './mn.core.js';
import { MnAdminService } from './mn.admin.service.js';
import { MnPoolsService } from './mn.pools.service.js';
import { MnHelperReactService } from './mn.helper.react.service.js';
import { UISref } from '@uirouter/react';

class MnWizardWelcomeComponent extends MnLifeCycleHooksToStream {
  constructor(props) {
    super(props);
    this.state = {
      prettyVersion: null,
      isEnterprise: null,
    };
  }

  componentDidMount() {
    this.focusFieldSubject = new BehaviorSubject(true);
    this.prettyVersion = MnAdminService.stream.prettyVersion;
    this.isEnterprise = MnPoolsService.stream.isEnterprise;

    MnHelperReactService.mnFocus(this);
    MnHelperReactService.async(this, 'prettyVersion');
    MnHelperReactService.async(this, 'isEnterprise');
  }

  render() {
    const { prettyVersion, isEnterprise } = this.state;
    return (
      <div>
        <div className="panel dialog width-520 text-center">
          <div className="panel-content">
            <img
              src="/cb_logo_red_withtext.svg"
              height="157"
              width="373"
              alt="Couchbase Logo"
            />
            <div className="text-normal margin-top-1">{prettyVersion}</div>
            <UISref
              to="app.wizard.setupNewCluster"
              options={{ location: false }}
            >
              <button
                ref={(input) => {
                  this.input = input;
                }}
                className="btn-lg margin-top-2"
              >
                Setup New Cluster
              </button>
            </UISref>
            <br />
            <UISref to="app.wizard.joinCluster" options={{ location: false }}>
              <button
                className="btn-lg margin-bottom-half"
                style={{ marginTop: '12px' }}
              >
                Join Existing Cluster
              </button>
            </UISref>
          </div>
        </div>
        <div
          className="supported-browsers-520"
          title="Chrome 67+, Firefox 67+, Safari 11.1+, Edge 80+"
        >
          Chrome, Firefox, Edge, Safari
        </div>
        {!isEnterprise && (
          <div className="panel width-520 text-center margin-top-half">
            <div className="panel-content">
              <div className="text-normal">
                <a
                  href="https://www.couchbase.com/ce-ui-link/"
                  rel="noopener noreferrer"
                  target="_blank"
                >
                  Learn More
                </a>
                about why teams are moving from Community Edition to Couchbase
                Capella, Database-as-a-Service
              </div>
            </div>
          </div>
        )}
      </div>
    );
  }
}

export { MnWizardWelcomeComponent };
