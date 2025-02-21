/*
Copyright 2015-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import React from 'react';
import PropTypes from 'prop-types';

class MnDragAndDrop extends React.Component {
  constructor(props) {
    super(props);
    this.draggedObject = null;
    this.startX = 0;
    this.startY = 0;
    this.initialMouseX = 0;
    this.initialMouseY = 0;
    this.elementRef = React.createRef();

    this.onMouseDown = this.onMouseDown.bind(this);
    this.onMouseMove = this.onMouseMove.bind(this);
    this.onMouseUp = this.onMouseUp.bind(this);
  }

  componentWillUnmount() {
    document.removeEventListener('mousemove', this.onMouseMove);
    document.removeEventListener('mouseup', this.onMouseUp);
    document.removeEventListener('touchmove', this.onMouseMove);
    document.removeEventListener('touchend', this.onMouseUp);
  }

  onMouseDown(e) {
    e = e || window.event;

    if (this.draggedObject) {
      this.onMouseUp();
      return;
    }

    const target = e.currentTarget;
    this.draggedObject = this.elementRef.current;

    if (this.props.onItemTaken) {
      this.props.onItemTaken(e);
    }

    this.startX = target.offsetLeft;
    if (this.props.baseCornerRight) {
      this.startX += target.clientWidth;
    }
    this.startY = target.offsetTop;
    this.initialMouseX = e.clientX;
    this.initialMouseY = e.clientY;

    this.draggedObject.classList.add('dragged');
    document.addEventListener('mousemove', this.onMouseMove);
    document.addEventListener('mouseup', this.onMouseUp);
    document.addEventListener('touchmove', this.onMouseMove);
    document.addEventListener('touchend', this.onMouseUp);
    document.body.classList.add('disable-text-selection');
    return false;
  }

  onMouseMove(e) {
    e = e || window.event;
    if (this.props.onItemMoved) {
      this.props.onItemMoved();
    }

    const dx = e.clientX - this.initialMouseX;
    const dy = e.clientY - this.initialMouseY;

    const move = {
      top: `${this.startY + dy}px`,
      bottom: 'auto',
    };

    if (this.props.baseCornerRight) {
      move.right = `${-(this.startX + dx)}px`;
      move.left = 'auto';
    } else {
      move.right = 'auto';
      move.left = `${this.startX + dx}px`;
    }

    Object.assign(this.draggedObject.style, move);
    return false;
  }

  onMouseUp() {
    if (this.props.onItemDropped) {
      this.props.onItemDropped();
    }

    if (this.draggedObject) {
      this.draggedObject.classList.remove('dragged');
      document.removeEventListener('mousemove', this.onMouseMove);
      document.removeEventListener('mouseup', this.onMouseUp);
      document.removeEventListener('touchmove', this.onMouseMove);
      document.removeEventListener('touchend', this.onMouseUp);
      document.body.classList.remove('disable-text-selection');
      this.draggedObject = null;
    }
  }

  render() {
    return (
      <div
        ref={this.elementRef}
        onMouseDown={this.onMouseDown}
        onTouchStart={this.onMouseDown}
        className={this.props.className}
      >
        {this.props.children}
      </div>
    );
  }
}

MnDragAndDrop.propTypes = {
  onItemTaken: PropTypes.func,
  onItemDropped: PropTypes.func,
  onItemMoved: PropTypes.func,
  baseCornerRight: PropTypes.bool,
  className: PropTypes.string,
  children: PropTypes.node,
};

export default MnDragAndDrop;
