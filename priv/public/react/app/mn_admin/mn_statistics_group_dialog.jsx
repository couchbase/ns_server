import React from 'react';
import mnStoreService from '../components/mn_store_service.js';
import mnUserRolesService from './mn_user_roles_service.js';
import mnPromiseHelper from '../components/mn_promise_helper.js';
import { MnLifeCycleHooksToStream } from 'mn.core';
import { MnHelperReactService } from '../mn.helper.react.service.js';

class MnStatisticsGroupDialog extends MnLifeCycleHooksToStream {
  constructor(props) {
    super(props);
    this.state = {
      name: '',
      desc: '',
      charts: [],
    };
  }

  componentDidMount() {
    const vm = this;
    vm.submit = submit;
    function submit() {
      var group = mnStoreService.store('groups').add(vm.state);
      mnStoreService
        .store('scenarios')
        .share()
        .find((scenario) => scenario.id === vm.props.scenarioId)
        .groups.push(group.id);

      mnPromiseHelper(vm, mnUserRolesService.saveDashboard())
        .showGlobalSpinner()
        .showGlobalSuccess('Group added successfully!')
        .onSuccess(function () {
          MnHelperReactService.rootScopeEmitter.emit('scenariosChanged');
          vm.props.onClose(group);
        });
    }
  }

  handleNameChange = (event) => {
    this.setState({ name: event.target.value });
  };

  render() {
    const vm = this;
    const { onDismiss } = vm.props;
    const { name } = vm.state;

    return (
      <div className="dialog-small">
        <div className="panel-header">
          <h2>New Group</h2>
        </div>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            vm.submit();
          }}
          className="forms"
        >
          <div className="panel-content">
            <div className="formrow">
              <label htmlFor="for-group-name">Group Name</label>
              <input
                type="text"
                id="for-group-name"
                autoFocus
                autoCorrect="off"
                spellCheck="false"
                autoCapitalize="off"
                value={name}
                onChange={vm.handleNameChange}
              />
            </div>
          </div>
          <div className="panel-footer">
            <a onClick={onDismiss}>Cancel</a>
            <button type="submit">Save</button>
          </div>
        </form>
      </div>
    );
  }
}

export { MnStatisticsGroupDialog };
