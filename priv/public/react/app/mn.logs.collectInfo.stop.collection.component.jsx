import React from 'react';
import { MnLifeCycleHooksToStream } from './mn.core.js';
import { MnLogsCollectInfoService } from './mn.logs.collectInfo.service.js';
import { MnFormService } from './mn.form.service.js';
import { FieldGroup } from 'react-reactive-form';

class MnLogsCollectInfoStopCollectionComponent extends MnLifeCycleHooksToStream {
  constructor(props) {
    super(props);

    this.form = MnFormService.create(this)
      .setFormGroup({})
      .setPostRequest(MnLogsCollectInfoService.stream.postCancelLogsCollection)
      .success(() => {
        this.props.onDismiss();
      });
  }

  render() {
    const { onDismiss } = this.props;

    return (
      <div className="dialog-small">
        <div className="panel-header">
          <h2>Confirm Log Collection Stop</h2>
        </div>
        <FieldGroup
          control={this.form.group}
          render={() => (
            <form
              onSubmit={(e) => {
                e.preventDefault();
                this.form.submit.next();
                this.form.group.handleSubmit();
              }}
            >
              <div className="panel-content">
                <p>Are you sure you want to stop log collection?</p>
              </div>
              <div className="panel-footer">
                <a onClick={onDismiss}>Cancel</a>
                <button type="submit">Stop</button>
              </div>
            </form>
          )}
        />
      </div>
    );
  }
}

export { MnLogsCollectInfoStopCollectionComponent };
