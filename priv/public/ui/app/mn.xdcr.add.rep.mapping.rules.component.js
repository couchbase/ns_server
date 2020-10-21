import {Component, ChangeDetectionStrategy} from '/ui/web_modules/@angular/core.js';
import {map, startWith} from '/ui/web_modules/rxjs/operators.js';
import {MnLifeCycleHooksToStream} from './mn.core.js';
import {collectionDelimiter} from './mn.xdcr.service.js';

export {MnXDCRAddRepMappingRulesComponent};

class MnXDCRAddRepMappingRulesComponent extends MnLifeCycleHooksToStream {
  static get annotations() { return [
    new Component({
      selector: "mn-xdcr-mapping-rules",
      templateUrl: "/ui/app/mn.xdcr.add.rep.mapping.rules.html",
      changeDetection: ChangeDetectionStrategy.OnPush,
      inputs: [
        "group",
        "explicitMappingRules",
        "explicitMappingMigrationRules",
        "explicitMappingGroup"
      ]
    })
  ]}

  constructor() {
    super();
  }

  ngOnInit() {
    let kvToArray = (rules) => Object.keys(rules).map(from => [from, rules[from]]);
    let migrationMode = this.group.get("collectionsMigrationMode")

    this.explicitMappingRulesKeys =
      this.explicitMappingRules.pipe(map(kvToArray));

    this.explicitMappingMigrationRulesKeys =
      this.explicitMappingMigrationRules.pipe(map(kvToArray));

    this.isMigrationMode =
      migrationMode.valueChanges.pipe(startWith(migrationMode.value));
  }

  delExplicitMappingRules(key) {
    let scopeCollection = key.split(collectionDelimiter);
    let rules = this.explicitMappingRules.getValue();
    if (scopeCollection.length == 2) {
      this.explicitMappingGroup.collections[scopeCollection[0]]
        .flags.get(scopeCollection[1]).setValue(rules[key] == null);
    } else {
      this.explicitMappingGroup.scopes.flags.get(scopeCollection[0]).setValue(false);
      Object.keys(rules).forEach(mapKey => {
        if (mapKey.startsWith(scopeCollection[0])) {
          delete rules[mapKey];
        }
      });
    }
    delete rules[key];
    this.explicitMappingRules.next(rules);
  }

  delExplicitMappingMigrationRules(key) {
    let rules = this.explicitMappingMigrationRules.getValue();
    delete rules[key];
    this.explicitMappingMigrationRules.next(rules);
  }
}
