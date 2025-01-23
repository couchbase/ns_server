import React, { createContext, useContext, useState } from 'react';
import { Dropdown } from 'react-bootstrap';

// Create context for sharing state between components
const DropdownContext = createContext();

export const MnDropdown = ({
  onSelect,
  className,
  children,
  onClick
}) => {
  // Handle dropdown selection
  const handleSelect = (item) => {
    onSelect && onSelect({ scenarioId: item });
  };

  const contextValue = {
    onSelect: handleSelect
  };

  return (
    <DropdownContext.Provider value={contextValue}>
      <Dropdown 
        className={`mn-dropdown ${className || ''}`}
        onClick={e => onClick && onClick(e)}>
        {children}
      </Dropdown>
    </DropdownContext.Provider>
  );
};

// Compound components
export const MnDropdownToggle = ({ children, iconClass }) => {
  return (
    <Dropdown.Toggle className={iconClass || 'select'}>
      {children}
    </Dropdown.Toggle>
  );
};

export const MnDropdownMenu = ({ children }) => {
  return (
    <Dropdown.Menu className="menu" style={{top: '-3px'}}>
      {children}
    </Dropdown.Menu>
  );
};

export const MnDropdownHeader = ({ children }) => {
  return children ? (
    <div className="header">
      {children}
    </div>
  ) : null;
};

export const MnDropdownBody = ({ children, className }) => {
  return (
    <div className={`body ${className || ''}`}>
      {children}
    </div>
  );
};

export const MnDropdownFooter = ({ children }) => {
  return children ? (
    <div className="footer">
      {children}
    </div>
  ) : null;
};

export const MnDropdownItem = ({ mnItem, children, onClick }) => {
  const context = useContext(DropdownContext);
  
  const handleClick = (e) => {
    if (onClick) {
      onClick(e);
    }
    context.onSelect(mnItem);
  };

  const [isMouseDown, setIsMouseDown] = useState(false);

  return (
    <Dropdown.Item
      className={isMouseDown ? 'mousedown' : ''}
      onClick={handleClick}
      onMouseDown={() => setIsMouseDown(true)}
      onMouseUp={() => setIsMouseDown(false)}>
      {children}
    </Dropdown.Item>
  );
};

// Example usage:
/*
<MnDropdown
  onSelect={(scenarioId) => handleSelect(scenarioId)}
  model={selectedValue}
  className="scenario-dropdown"
  onClick={(e) => e.stopPropagation()}>
  <MnDropdownToggle>
    {selectedScenario.name}
  </MnDropdownToggle>
  <MnDropdownMenu>
    <MnDropdownHeader>
      Optional Header Content
    </MnDropdownHeader>
    <MnDropdownBody className="body-shorter">
      {scenarios.map(scenario => (
        <MnDropdownItem
          key={scenario.id}
          mnItem={scenario.id}>
          <p>{scenario.name}</p>
          {scenario.desc && <p>{scenario.desc}</p>}
          {!scenario.preset && (
            <div 
              className="scenario-controls"
              onClick={(e) => e.stopPropagation()}>
              <span
                title="delete scenario"
                className="icon fa-trash dashboard-delete"
                onClick={() => deleteScenario(scenario.id)}
              />
              <span
                title="edit scenario"
                className="icon fa-edit adder"
                onClick={() => editScenario(scenario)}
              />
            </div>
          )}
        </MnDropdownItem>
      ))}
    </MnDropdownBody>
    <MnDropdownFooter>
      Footer Content
    </MnDropdownFooter>
  </MnDropdownMenu>
</MnDropdown>
*/ 