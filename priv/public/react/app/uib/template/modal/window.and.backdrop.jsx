import React, { useState } from 'react';
import { createPortal } from 'react-dom';

// Modal Context
const ModalContext = React.createContext({
  openModal: () => Promise.resolve(),
  dismissModal: () => {},
});

const ModalBackdrop = ({ children, index, onDismiss, animate, backdrop }) => {
  const zIndex = 1040 + (index ? 1 : 0) + index * 10;
  const handleBackdropClick = (e) => {
    if (e.target === e.currentTarget && backdrop !== 'static') {
      onDismiss();
    }
  };
  return (
    <div
      onClick={backdrop ? handleBackdropClick : undefined}
      className={`modal-backdrop ${animate ? 'in' : ''}`}
      style={{ zIndex }}
    >
      {children}
    </div>
  );
};

const ModalWindow = ({ children, index, onDismiss, windowClass, backdrop }) => {
  const zIndex = 1050 + index * 10;
  return (
    <div
      tabIndex="-1"
      role="dialog"
      className={`row flex-center items-top dialog_main_wrapper ${windowClass}`}
      style={{ zIndex }}
    >
      <div className="panel dialog">
        {/* {backdrop !== 'static' && ( */}
        <a
          className="ui-dialog-titlebar-close modal-close"
          onClick={() => onDismiss('X')}
        >
          X
        </a>
        {/* )} */}
        <div>{children}</div>
      </div>
    </div>
  );
};

// Base Modal Component
const Modal = ({ children, onDismiss, animate, index, windowClass }) => {
  const backdrop = 'static';
  return createPortal(
    <>
      <ModalBackdrop
        index={index}
        onDismiss={onDismiss}
        backdrop={backdrop}
        animate={animate}
      ></ModalBackdrop>
      ,
      <ModalWindow
        index={index}
        onDismiss={onDismiss}
        backdrop={backdrop}
        windowClass={windowClass}
      >
        {children}
      </ModalWindow>
    </>,
    document.body
  );
};

// Modal Provider Component
const ModalProvider = ({ children }) => {
  const [modalState, setModalState] = useState({
    config: null,
    resolvedProps: null,
    isLoading: false,
  });

  const openModal = (config) => {
    return new Promise((resolve, reject) => {
      setModalState({
        config,
        resolvedProps: null,
        isLoading: true,
        resolveModal: resolve,
        rejectModal: reject,
      });

      // Handle resolvers
      if (config.resolve) {
        const resolverPromises = Object.entries(config.resolve).map(
          async ([key, resolver]) => {
            try {
              const result = await resolver();
              return [key, result];
            } catch (error) {
              console.error(`Resolver for ${key} failed:`, error);
              throw error;
            }
          }
        );

        Promise.all(resolverPromises)
          .then((results) => {
            const resolvedProps = Object.fromEntries(results);
            setModalState((prev) => ({
              ...prev,
              resolvedProps,
              isLoading: false,
            }));
          })
          .catch((error) => {
            dismissModal();
            console.error('Resolver failed:', error);
          });
      } else {
        setModalState((prev) => ({
          ...prev,
          isLoading: false,
        }));
      }
    });
  };

  const dismissModal = (result) => {
    if (modalState.rejectModal) {
      modalState.rejectModal(result);
    }
    setModalState({
      config: null,
      resolvedProps: null,
      isLoading: false,
    });
  };

  const closeModal = (result) => {
    if (modalState.resolveModal) {
      modalState.resolveModal(result);
    }
    setModalState({
      config: null,
      resolvedProps: null,
      isLoading: false,
    });
  };

  return (
    <ModalContext.Provider value={{ openModal, dismissModal }}>
      {children}
      {modalState.config && (
        <Modal
          onDismiss={dismissModal}
          backdrop={modalState.config.backdrop}
          windowClass={modalState.config.windowClass}
        >
          {modalState.isLoading ? (
            <></>
          ) : (
            <modalState.config.component
              {...modalState.config.props}
              {...modalState.resolvedProps}
              onDismiss={dismissModal}
              onClose={closeModal}
            />
          )}
        </Modal>
      )}
    </ModalContext.Provider>
  );
};

export { ModalProvider, ModalContext };
