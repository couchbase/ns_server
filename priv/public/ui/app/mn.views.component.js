/*
Copyright 2021-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import { Component, ChangeDetectionStrategy } from '@angular/core';

export { MnViewsComponent };

class MnViewsComponent {
  static get annotations() { return [
    new Component({
      templateUrl: "app/mn.views.html",
      changeDetection: ChangeDetectionStrategy.OnPush
    })
  ]}
}