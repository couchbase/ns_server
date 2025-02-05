import React from 'react';
import { UIView } from '@uirouter/react';
import { MnLifeCycleHooksToStream } from './mn.core.js';

class MnLogsCollectInfoComponent extends MnLifeCycleHooksToStream {
  constructor(props) {
    super(props);
  }

  render() {
    return <UIView />;
  }
}

export { MnLogsCollectInfoComponent };
