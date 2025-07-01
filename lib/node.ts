import ObjC from 'frida-objc-bridge';

import * as touch from './touch.js';

const activeInstances = {};
let keepingAlive = false;

function keepViewsAlive() {
  if (keepingAlive) {
    return;
  }
  keepingAlive = true;

  const { willMoveToWindow, originalWillMoveToWindow } = getApi();

  willMoveToWindow.implementation = ObjC.implement(willMoveToWindow, (handle, selector, window) => {
    originalWillMoveToWindow(handle, selector, window);

    const key = handle.toString();
    const nodes = activeInstances[key];

    if (window.isNull() && nodes !== undefined) {
      let view = null;
      for (const node of nodes) {
        view = node.instance;
        node.instance = null;
      }
      delete activeInstances[key];
      view.release();
    }
  });
}

export function UINode(view) {
  this.instance = view;
  keepViewsAlive();
  const activeKey = view.handle.toString();
  if (!(activeKey in activeInstances)) {
    view.retain();
    activeInstances[activeKey] = new Set([this]);
  } else {
    activeInstances[activeKey].add(this);
  }

  const api = getApi();

  if (view.isKindOfClass_(api.UIWindowClass)) {
    this.type = 'UIWindow';
  } else if (view.isKindOfClass_(api.UIButtonClass)) {
    this.type = 'UIButton';
  } else if (view.isKindOfClass_(api.UILabelClass)) {
    this.type = 'UILabel';
  } else if (view.isKindOfClass_(api.UITextFieldClass)) {
    this.type = 'UITextField';
  } else if (view.isKindOfClass_(api.UITextViewClass)) {
    this.type = 'UITextView';
  } else if (view.isKindOfClass_(api.UIWebViewClass)) {
    this.type = 'UIWebView';
  } else if (view.isKindOfClass_(api.WKWebViewClass)) {
    this.type = 'WKWebView';
  } else {
    this.type = 'UIView';
  }
  this.className = view.$className;
  this._enabled = null;
  this._label = null;

  const children = [];
  const subviews = view.subviews();
  const count = subviews.count().valueOf();
  for (let i = 0; i !== count; i++) {
    children.push(new UINode(subviews.objectAtIndex_(i)));
  }
  this.children = children;
}

UINode.prototype = {
  get enabled() {
    if (this._enabled === null) {
      const instance = this.instance;
      if (instance === null) {
        return false;
      }
      if ('enabled' in instance && instance.enabled.returnType === 'bool') {
        this._enabled = !!instance.enabled();
      } else {
        this._enabled = true;
      }
    }
    return this._enabled;
  },
  get label() {
    if (this._label === null) {
      const instance = this.instance;
      if (instance === null) {
        return '';
      }
      if ('accessibilityLabel' in instance && instance.accessibilityLabel.returnType === 'pointer') {
        const accLabel = instance.accessibilityLabel();
        if (accLabel !== null) {
          this._label = accLabel.toString();
        }
      }
      if (this._label === null) {
        if ('placeholder' in instance && instance.placeholder.returnType === 'pointer') {
          this._label = readStringProperty(instance.placeholder());
        } else if ('text' in instance && instance.text.returnType === 'pointer') {
          this._label = readStringProperty(instance.text());
        } else {
          this._label = '';
        }
      }
    }
    return this._label;
  },
  forEach(fn) {
    this._forEach(fn, 0, 0);
  },
  _forEach(fn, depth, idx) {
    fn(this, depth, idx);
    this.children.forEach((child, i) => child._forEach(fn, depth + 1, i));
  },
  find(predicate) {
    if (predicate(this)) {
      return this;
    }

    const children = this.children;
    for (let i = 0; i !== children.length; i++) {
      const child = children[i].find(predicate);
      if (child !== null) {
        return child;
      }
    }

    return null;
  },
  setText(text) {
    return performOnMainThread(() => {
      const instance = this.instance;
      if (instance === null) {
        throw new Error('View is gone');
      }

      const api = getApi();

      const delegate = instance.delegate();
      let valid = true;
      if (delegate !== null && delegate.respondsToSelector_(api.textField_shouldChangeCharactersInRange_replacementString_)) {
        const oldText = instance.text().toString();
        valid = delegate.textField_shouldChangeCharactersInRange_replacementString_(instance, [0, oldText.length], text);
      }

      if (!valid)
        return;

      instance.becomeFirstResponder();
      instance.setText_('');
      instance.deleteBackward();
      instance.insertText_(text);
      instance.resignFirstResponder();
    });
  },
  tap() {
    const view = this.instance;
    if (view === null) {
      return Promise.reject(new Error('View is gone'));
    }
    return new Promise(function (resolve, reject) {
      performOnMainThread(() => {
        const [_, [width, height]] = view.frame();
        const x = width / 2;
        const y = height / 2;
        touch.tap(view, x, y).then(resolve, reject);
      })
    });
  },
  dispose() {
    const view = this.instance;
    if (view === null) {
      return;
    }
    const activeKey = view.handle.toString();
    const nodes = activeInstances[activeKey];
    if (nodes !== undefined) {
      nodes.delete(this);
      if (nodes.size === 0) {
        delete activeInstances[activeKey];
        view.release();
      }
    }
    this.children.forEach(child => child.dispose());
  }
};

function performOnMainThread(action) {
  return new Promise(function (resolve, reject) {
    const { NSThread } = getApi();
    if (NSThread.isMainThread()) {
      performAction();
    } else {
      ObjC.schedule(ObjC.mainQueue, performAction);
    }

    function performAction() {
      try {
        const result = action();
        resolve(result);
      } catch (e) {
        reject(e);
      }
    }
  });
}

function readStringProperty(value) {
  return (value !== null) ? value.toString() : '';
}

let _api = null;

function getApi() {
  if (_api === null) {
    const willMoveToWindow = ObjC.classes.UIView['- willMoveToWindow:'];

    _api = {
      NSThread: ObjC.classes.NSThread,
      UIButtonClass: ObjC.classes.UIButton.class(),
      UILabelClass: ObjC.classes.UILabel.class(),
      UITextFieldClass: ObjC.classes.UITextField.class(),
      UITextViewClass: ObjC.classes.UITextView.class(),
      UIWindowClass: ObjC.classes.UIWindow.class(),
      UIWebViewClass: ObjC.classes.UIWebView.class(),
      WKWebViewClass: ObjC.classes.WKWebView.class(),
      textField_shouldChangeCharactersInRange_replacementString_: ObjC.selector('textField:shouldChangeCharactersInRange:replacementString:'),
      willMoveToWindow,
      originalWillMoveToWindow: willMoveToWindow.implementation,
    };
  }

  return _api;
}

