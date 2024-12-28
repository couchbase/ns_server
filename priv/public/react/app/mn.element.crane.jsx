/*
Copyright 2020-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import React, { createContext, useContext, useEffect, useRef } from 'react';

export { MnElementCraneProvider, MnElementCargo, MnElementDepot };

const MnElementCraneContext = createContext();

const MnElementCraneProvider = ({ children }) => {
  const depots = useRef({});

  const register = (element, name) => {
    depots.current[name] = element;
  };

  const unregister = (name) => {
    delete depots.current[name];
  };

  const get = (name) => {
    return depots.current[name];
  };

  return (
    <MnElementCraneContext.Provider value={{ register, unregister, get }}>
      {children}
    </MnElementCraneContext.Provider>
  );
};

const MnElementCargo = ({ depot, children }) => {
  const { get } = useContext(MnElementCraneContext);
  const cargoRef = useRef(null);

  useEffect(() => {
    const depotElement = get(depot);
    if (depotElement && cargoRef.current) {
      depotElement.appendChild(cargoRef.current);
    }
    return () => {
      if (depotElement && cargoRef.current) {
        depotElement.removeChild(cargoRef.current);
      }
    };
  }, [depot, get]);

  return <div ref={cargoRef}>{children}</div>;
};

const MnElementDepot = ({ name, children }) => {
  const { register, unregister } = useContext(MnElementCraneContext);
  const depotRef = useRef(null);

  useEffect(() => {
    if (depotRef.current) {
      register(depotRef.current, name);
    }
    return () => {
      unregister(name);
    };
  }, [name, register, unregister]);

  return <div ref={depotRef}>{children}</div>;
};
