import React from 'react';
import { ModalContext } from '../uib/template/modal/window.and.backdrop';
import { UIRouter } from 'mn.react.router';
import mnStatisticsNewService from './mn_statistics_service.js';
import { MnLifeCycleHooksToStream } from '../mn.core.js';
import { MnHelperReactService } from '../mn.helper.react.service.js';
import mnUserRolesService from './mn_user_roles_service.js';
import mnStoreService from '../components/mn_store_service.js';
import {
  MnDropdown,
  MnDropdownToggle,
  MnDropdownMenu,
  MnDropdownBody,
  MnDropdownItem,
  MnDropdownFooter,
} from '../components/directives/mn_dropdown.jsx';
import { MnStatisticsScenarioDelete } from './mn_statistics_scenario_delete.jsx';

class MnStatisticsScenarioComponent extends MnLifeCycleHooksToStream {
  static contextType = ModalContext;

  constructor(props) {
    super(props);
    this.state = {
      scenario: {
        name: '',
        desc: '',
        groups: [],
      },
      copyScenario: 'true',
      isEditingMode: false,
      showRestOfMenu: false,
    };
  }

  componentDidMount() {
    var vm = this;

    vm.editScenario = editScenario;
    vm.deleteScenario = deleteScenario;
    vm.onSubmit = onSubmit;
    vm.clear = clear;

    function setEmptyScenario() {
      vm.setState({
        scenario: {
          name: '',
          desc: '',
          groups: [],
        },
      });
    }

    function clear() {
      setEmptyScenario();
      vm.setState({
        copyScenario: 'true',
        isEditingMode: false,
        showRestOfMenu: false,
      });
    }

    function deleteScenario(scenarioID) {
      this.context
        .openModal({
          component: MnStatisticsScenarioDelete,
        })
        .then(
          () => {
            mnStatisticsNewService.deleteScenario(scenarioID);
            mnUserRolesService.saveDashboard().then(() => {
              MnHelperReactService.rootScopeEmitter.emit('scenariosChanged');
              selectLastScenario();
            });
          },
          () => {}
        );
    }

    function editScenario(scenario) {
      vm.setState({
        isEditingMode: !!scenario,
        scenario: { ...scenario },
        showRestOfMenu: true,
      });
    }

    function selectLastScenario() {
      vm.props.statisticsNewCtl.setState({
        scenarioId: mnStoreService.store('scenarios').last().id,
      });
      return UIRouter.stateService.go('^.statistics', {
        scenario: mnStoreService.store('scenarios').last().id,
      });
    }

    function onSubmit(currentScenario) {
      const { scenario, isEditingMode, copyScenario } = vm.state;

      if (!scenario.name) {
        return;
      }

      if (isEditingMode) {
        mnStoreService.store('scenarios').put(scenario);
      } else {
        if (copyScenario === 'true') {
          mnStatisticsNewService.copyScenario(scenario, currentScenario);
        } else {
          mnStoreService.store('scenarios').add(scenario);
        }
      }

      mnUserRolesService.saveDashboard().then(() => {
        selectLastScenario().then(() => {
          MnHelperReactService.rootScopeEmitter.emit('scenariosChanged');
          const customEvent = new MouseEvent('click', {
            bubbles: true,
            cancelable: true,
          });
          document.querySelector('body').dispatchEvent(customEvent);
          clear();
        });
      });
    }
  }

  render() {
    const vm = this;
    const { scenario, showRestOfMenu, copyScenario, isEditingMode } = vm.state;
    const { statisticsNewCtl, rbac } = vm.props;

    return (
      <MnDropdown
        onClick={(e) => e.stopPropagation()}
        onSelect={({ scenarioId }) => {
          statisticsNewCtl.setState({ scenarioId });
          statisticsNewCtl.onSelectScenario(scenarioId);
        }}
        className="scenario-dropdown"
      >
        <MnDropdownToggle>
          {statisticsNewCtl.getSelectedScenario().name}
        </MnDropdownToggle>
        <MnDropdownMenu>
          <MnDropdownBody className={showRestOfMenu ? 'body-shorter' : ''}>
            {/* 
              In case you want sort() to not mutate the original array, but return a
              shallow-copied array like other array methods (e.g. map() ) do, use the
              toSorted() method 
            */}
            {statisticsNewCtl.state.scenarios
              .toSorted((a, b) => !!a.preset - !!b.preset)
              .map((scenario) => (
                <MnDropdownItem key={scenario.id} mnItem={scenario.id}>
                  <p>{scenario.name}</p>
                  {scenario.desc && <p>{scenario.desc}</p>}
                  {!scenario.preset && (
                    <div
                      className="scenario-controls"
                      onClick={(e) => e.stopPropagation()}
                    >
                      <span
                        title="delete scenario"
                        className="icon fa-trash dashboard-delete"
                        onClick={() => vm.deleteScenario(scenario.id)}
                      ></span>
                      <span
                        title="edit scenario"
                        className="icon fa-edit adder"
                        onClick={() => vm.editScenario(scenario)}
                      ></span>
                    </div>
                  )}
                </MnDropdownItem>
              ))}
          </MnDropdownBody>
          <MnDropdownFooter>
            <form
              onSubmit={(e) => {
                e.preventDefault();
                vm.onSubmit(statisticsNewCtl.getSelectedScenario());
              }}
              className="forms"
            >
              <div
                className={`scenario-add ${showRestOfMenu ? 'scenario-add-ext' : ''}`}
              >
                <input
                  type="text"
                  value={scenario.name}
                  onChange={(e) =>
                    vm.setState({
                      scenario: { ...scenario, name: e.target.value },
                    })
                  }
                  placeholder="new dashboard..."
                  className={!showRestOfMenu ? 'borderless cursor-pointer' : ''}
                  autoCorrect="off"
                  onClick={() => vm.setState({ showRestOfMenu: true })}
                  spellCheck="false"
                  autoCapitalize="off"
                  disabled={!rbac.bucketNames['.stats!read'].length}
                  required
                />
                {!showRestOfMenu && (
                  <span className="icon fa-plus-square"></span>
                )}
              </div>
              {showRestOfMenu && (
                <>
                  <input
                    type="text"
                    value={scenario.desc}
                    onChange={(e) =>
                      vm.setState({
                        scenario: { ...scenario, desc: e.target.value },
                      })
                    }
                    placeholder="optional description..."
                    autoCorrect="off"
                    spellCheck="false"
                    autoCapitalize="off"
                    disabled={!rbac.bucketNames['.stats!read'].length}
                    className="scenario-desc"
                  />
                  {!isEditingMode && (
                    <div className="checkbox-list margin-bottom-half">
                      <input
                        type="radio"
                        value="true"
                        checked={copyScenario === 'true'}
                        onChange={(e) =>
                          vm.setState({ copyScenario: e.target.value })
                        }
                        id="for-bucket-type-current"
                      />
                      <label htmlFor="for-bucket-type-current">
                        start w/ current charts
                      </label>
                      <input
                        type="radio"
                        value="false"
                        checked={copyScenario === 'false'}
                        onChange={(e) =>
                          vm.setState({ copyScenario: e.target.value })
                        }
                        id="for-bucket-type-blank"
                      />
                      <label htmlFor="for-bucket-type-blank">start blank</label>
                    </div>
                  )}
                  <div className="scenario-save-controls">
                    <button type="submit">Save</button>
                    <a className="width-12 text-center" onClick={vm.clear}>
                      Cancel
                    </a>
                  </div>
                </>
              )}
            </form>
          </MnDropdownFooter>
        </MnDropdownMenu>
      </MnDropdown>
    );
  }
}

export { MnStatisticsScenarioComponent };
