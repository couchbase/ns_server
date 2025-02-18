import { useState } from 'react';
import { OverlayTrigger as OverlayTriggerBs } from 'react-bootstrap';

/**
 *
 * A wrapper around React Bootstrap's OverlayTrigger that adds the ability to hover from trigger to tooltip content.
 *
 * AI Generated JSDocs from OverlayTrigger documentation.
 *
 * For more props see https://react-bootstrap.netlify.app/docs/components/overlays/#overview
 *
 * @param {Object} props
 * @param {boolean} [props.allowContentHover=false] - When true, allows hovering from trigger to tooltip content. Cannot be used with `show` prop.
 * @param {React.ReactElement|function} props.children - The trigger element or render function
 * @param {('hover'|'click'|'focus'|Array<'hover'|'click'|'focus'>)} [props.trigger] - The trigger type(s)
 * @param {number|{show: number, hide: number}} [props.delay] - Delay showing and hiding the overlay (ms)
 * @param {boolean} [props.show] - Controlled visibility state
 * @param {boolean} [props.defaultShow] - Initial visibility state
 * @param {function} [props.onToggle] - Callback fired when the visibility state changes
 * @param {boolean} [props.flip] - Whether to flip the overlay when it reaches the edges
 * @param {React.ReactElement|function} props.overlay - The overlay content
 * @param {('auto-start'|'auto'|'auto-end'|'top-start'|'top'|'top-end'|'right-start'|'right'|'right-end'|'bottom-start'|'bottom'|'bottom-end'|'left-start'|'left'|'left-end')} [props.placement] - The placement of the overlay
 */
export const OverlayTrigger = ({ children, allowContentHover, ...props }) => {
  const [show, setShow] = useState(false);

  // https://github.com/react-bootstrap/react-bootstrap/issues/3791
  if (allowContentHover) {
    if (props.show) {
      throw new Error('show prop is not supported for allowContentHover');
    }

    return (
      <div
        style={{
          display: 'inline-block',
          // 48px is enough to bridge the gap between trigger and tooltip content, so that hovering from the trigger to the tooltip doesn't trigger setShow(false)
          minWidth: show ? '48px' : '0px',
        }}
        onMouseEnter={() => setShow(true)}
        onMouseLeave={() => setShow(false)}
      >
        <OverlayTriggerBs show={show} {...props}>
          {children}
        </OverlayTriggerBs>
      </div>
    );
  }

  return <OverlayTriggerBs {...props}>{children}</OverlayTriggerBs>;
};
