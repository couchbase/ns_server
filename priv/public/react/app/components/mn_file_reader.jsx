/*
Copyright 2020-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import React from 'react';
import PropTypes from 'prop-types';

let index = 0;

class MnFileReader extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      name: 'Select File',
      index: index++,
    };
    this.fileInputRef = React.createRef();
  }

  onTextareaChange = () => {
    this.setState({ name: 'Select File' });
    if (this.fileInputRef.current) {
      this.fileInputRef.current.value = '';
    }
  };

  setNameAndRead = (file, reader) => {
    if (file) {
      if (file.size > 1024 * 1024) {
        return;
      }
      this.setState({ name: file.name });
      reader.readAsText(file);
    } else {
      this.setState({ name: 'Select File' });
      if (this.props.onChange) {
        this.props.onChange('');
      }
    }
  };

  loadFile = (event) => {
    const reader = new FileReader();
    reader.onload = (loadEvent) => {
      const result = loadEvent.target.result.toString();
      if (this.props.onChange) {
        this.props.onChange(result);
      }
    };
    const file = event.target.files[0];
    this.setNameAndRead(file, reader);
  };

  render() {
    const { classes = [], value, disabled, className } = this.props;
    const { name, index } = this.state;
    const containerClasses = [...classes, className].filter(Boolean).join(' ');

    return (
      <>
        <textarea
          rows="4"
          autoCorrect="off"
          autoComplete="off"
          spellCheck="false"
          onChange={(e) => {
            this.onTextareaChange();
            if (this.props.onChange) {
              this.props.onChange(e.target.value);
            }
          }}
          disabled={disabled}
          className={containerClasses}
          value={value || ''}
        />
        <label
          className={`btn ellipsis outline left-ellipsis margin-top-half ${containerClasses}`}
          htmlFor={`select-file-${index}`}
          disabled={disabled}
        >
          {name}
        </label>
        <input
          id={`select-file-${index}`}
          ref={this.fileInputRef}
          style={{ display: 'none' }}
          disabled={disabled}
          onChange={this.loadFile}
          type="file"
        />
      </>
    );
  }
}

MnFileReader.propTypes = {
  classes: PropTypes.array,
  value: PropTypes.string,
  disabled: PropTypes.bool,
  onChange: PropTypes.func,
  className: PropTypes.string,
};

export default MnFileReader;
