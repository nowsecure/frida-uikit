'use strict';

const touch = require('./touch');

const NSThread = ObjC.classes.NSThread;
const UIButtonClass = ObjC.classes.UIButton.class();
const UILabelClass = ObjC.classes.UILabel.class();
const UITextFieldClass = ObjC.classes.UITextField.class();
const UITextViewClass = ObjC.classes.UITextView.class();
let UIWebViewClass = null;
let WKWebViewClass = null;
const UIWindow = ObjC.classes.UIWindow;
const UIWindowClass = UIWindow.class();

const textField_shouldChangeCharactersInRange_replacementString_ = ObjC.selector('textField:shouldChangeCharactersInRange:replacementString:');
const willMoveToWindow = ObjC.classes.UIView['- willMoveToWindow:'];
const originalWillMoveToWindow = willMoveToWindow.implementation;

const activeInstances = {};
let keepingAlive = false;

function keepViewsAlive() {
  if (keepingAlive) {
    return;
  }
  keepingAlive = true;

  willMoveToWindow.implementation = ObjC.implement(willMoveToWindow, (handle, selector, window) => {
    originalWillMoveToWindow(handle, selector, window);

    const key = handle.toString();
    const node = activeInstances[key];

    if (window.isNull() && node !== undefined) {
      const view = node.instance;
      node.instance = null;
      delete activeInstances[key];
      view.release();
    }
  });
}

function UINode(view) {
  this.instance = view;
  keepViewsAlive();
  view.retain();
  activeInstances[view.handle.toString()] = this;

  if (UIWebViewClass === null) {
    // Cannot access this type early
    UIWebViewClass = ObjC.classes.UIWebView.class();
  }

  if (WKWebViewClass === null) {
    // Cannot access this type early
    WKWebViewClass = ObjC.classes.WKWebView.class();
  }

  if (view.isKindOfClass_(UIWindowClass)) {
    this.type = 'UIWindow';
  } else if (view.isKindOfClass_(UIButtonClass)) {
    this.type = 'UIButton';
  } else if (view.isKindOfClass_(UILabelClass)) {
    this.type = 'UILabel';
  } else if (view.isKindOfClass_(UITextFieldClass)) {
    this.type = 'UITextField';
  } else if (view.isKindOfClass_(UITextViewClass)) {
    this.type = 'UITextView';
  } else if (view.isKindOfClass_(UIWebViewClass)) {
    this.type = 'UIWebView';
  } else if (view.isKindOfClass_(WKWebViewClass)) {
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
      if ('enabled' in instance) {
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
      if ('accessibilityLabel' in instance) {
        const accLabel = instance.accessibilityLabel();
        if (accLabel !== null) {
          this._label = accLabel.toString();
        }
      }
      if (this._label === null) {
        if ('placeholder' in instance) {
          this._label = readStringProperty(instance.placeholder());
        } else if ('text' in instance) {
          this._label = readStringProperty(instance.text());
        } else {
          this._label = '';
        }
      }
    }
    return this._label;
  },
  forEach(fn) {
    fn(this);
    this.children.forEach(child => child.forEach(fn));
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

      const delegate = instance.delegate();
      let valid = true;
      if (delegate !== null && delegate.respondsToSelector_(textField_shouldChangeCharactersInRange_replacementString_)) {
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
  }
};

function performOnMainThread(action) {
  return new Promise(function (resolve, reject) {
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

module.exports = UINode;
