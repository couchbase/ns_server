import React from 'react';
import { MnLifeCycleHooksToStream } from './mn.core.js';
import { MnTruncate } from './mn.pipes.js';
import { MnStripPortHTML } from './mn.admin.service.js';
import { MnFormatServices } from './mn.pipes.js';
import { MnOrderServices } from './mn.pipes.js';
import { MnHelperReactService } from './mn.helper.react.service.js';

class MnSelectableNodeItemComponent extends MnLifeCycleHooksToStream {
  constructor(props) {
    super(props);

    this.state = {
      strippedHostname: null,
    };
  }

  componentDidMount() {
    super.componentDidMount();

    // Get stripped hostname
    if (this.props.mnSelectableNode.hostname) {
      this.strippedHostname = MnStripPortHTML.transform(
        this.props.mnSelectableNode.hostname
      );
      MnHelperReactService.async(this, 'strippedHostname');
    }
  }

  render() {
    const { mnSelectableNode, mnGroup } = this.props;
    const { strippedHostname } = this.state;

    return (
      <div
        className={`cbui-tablerow padding-left-half dynamic_${mnSelectableNode.status} dynamic_${mnSelectableNode.clusterMembership}`}
      >
        <span className="cbui-table-cell flex-grow-2-5">
          <input
            strict={false}
            type="checkbox"
            id={mnSelectableNode.otpNode}
            {...mnGroup.controls[mnSelectableNode.otpNode].handler('checkbox')}
          />
          <label title={strippedHostname} htmlFor={mnSelectableNode.otpNode}>
            {strippedHostname}
          </label>
        </span>

        {mnSelectableNode.groupName && (
          <span
            className="cbui-table-cell flex-grow-half resp-hide-sml"
            title={mnSelectableNode.groupName}
          >
            {MnTruncate.transform(mnSelectableNode.groupName, 20)}
          </span>
        )}

        <span className="cbui-table-cell flex-grow-2-5 row min flex-right resp-hide-xsml">
          {MnOrderServices.transform(mnSelectableNode.services).map(
            (service, i) => (
              <span key={i} className="label neutral nocaps">
                {MnFormatServices.transform(service)}
              </span>
            )
          )}
        </span>
      </div>
    );
  }
}

export { MnSelectableNodeItemComponent };
