'use strict';

const CADisplayLink = ObjC.classes.CADisplayLink;
const NSAutoreleasePool = ObjC.classes.NSAutoreleasePool;
const NSRunLoop = ObjC.classes.NSRunLoop;
const UIApplication = ObjC.classes.UIApplication;
const UITouch = ObjC.classes.UITouch;

const UITouchPhaseBegan = 0;
const UITouchPhaseMoved = 1;
const UITouchPhaseStationary = 2;
const UITouchPhaseEnded = 3;
const UITouchPhaseCancelled = 4;

const CGFloat = (Process.pointerSize === 4) ? 'float' : 'double';
const CGPoint = [CGFloat, CGFloat];
const CGPointEqualToPoint = new NativeFunction(
    Module.findExportByName('CoreGraphics', 'CGPointEqualToPoint'),
    'uint8',
    [CGPoint, CGPoint]);
const CGPointZero = Memory.readPointer(Module.findExportByName('CoreGraphics', 'CGPointZero'));
const CGSize = [CGFloat, CGFloat];

const kIOHIDDigitizerEventRange = 0x00000001;
const kIOHIDDigitizerEventTouch = 0x00000002;
const kIOHIDDigitizerEventPosition = 0x00000004;
const IOHIDEventCreateDigitizerFingerEvent = new NativeFunction(
    Module.findExportByName(null, 'IOHIDEventCreateDigitizerFingerEvent'),
    'pointer',
    [
        'pointer',            // allocator
        ['uint32', 'uint32'], // timestamp
        'uint32',             // index
        'uint32',             // identity
        'uint32',             // eventMask
        CGFloat,              // x
        CGFloat,              // y
        CGFloat,              // z
        CGFloat,              // tipPressure
        CGFloat,              // twist
        'uint8',              // range
        'uint8',              // touch
        'uint32'              // options
    ]);

const kCFAllocatorDefault = Memory.readPointer(Module.findExportByName('CoreFoundation', 'kCFAllocatorDefault'));
const NSRunLoopCommonModes = Memory.readPointer(Module.findExportByName('Foundation', 'NSRunLoopCommonModes'));
const CFGetSystemUptime = new NativeFunction(
    Module.findExportByName('CoreFoundation', 'CFGetSystemUptime'),
    'double',
    []);
const CFRelease = new NativeFunction(
    Module.findExportByName('CoreFoundation', 'CFRelease'),
    'void',
    ['pointer']);

const mach_absolute_time = new NativeFunction(
    Module.findExportByName('libSystem.B.dylib', 'mach_absolute_time'),
    'uint64',
    []);

const Injector = ObjC.registerClass({
  methods: {
    '- init': function () {
      const self = this.super.init();
      if (self !== null) {
        const displayLink = CADisplayLink.displayLinkWithTarget_selector_(self, ObjC.selector('dispatchTouch:'));
        ObjC.bind(self, {
          displayLink: displayLink,
          window: null,
          touch: null,
          pending: [],
          previous: null,
          onComplete: function () {}
        });
        displayLink.addToRunLoop_forMode_(NSRunLoop.mainRunLoop(), NSRunLoopCommonModes);
        displayLink.setPaused_(false);
      }
      return self;
    },
    '- dealloc': function () {
      ObjC.unbind(this.self);
      this.super.dealloc();
    },
    '- dispatchTouch:': {
      retType: 'void',
      argTypes: ['object'],
      implementation: function (sender) {
        const priv = this.data;

        if (priv.pending.length === 0) {
          priv.displayLink.invalidate();
          priv.displayLink = null;

          priv.onComplete();
          return;
        }

        let touch, phase;
        let point = priv.pending.shift();
        const isLastTouch = priv.pending.length === 0;

        if (priv.touch === null) {
          touch = UITouch.alloc().init();
          priv.touch = touch;
          touch.setTapCount_(1);
          touch.setIsTap_(true);
          phase = UITouchPhaseBegan;
          touch.setPhase_(phase);
          touch.setWindow_(priv.window);
          touch['- _setLocationInWindow:resetPrevious:'].call(touch, point, true);
          touch.setView_(priv.window.hitTest_withEvent_(point, NULL));
          touch['- _setIsFirstTouchForView:'].call(touch, true);
        } else {
          touch = priv.touch;

          if (isLastTouch) {
            touch['- _setLocationInWindow:resetPrevious:'].call(touch, priv.previous, false);
            phase = UITouchPhaseEnded;
            point = priv.previous;
          } else {
            touch['- _setLocationInWindow:resetPrevious:'].call(touch, point, false);
            phase = CGPointEqualToPoint(point, priv.previous) ? UITouchPhaseStationary : UITouchPhaseMoved;
          }

          touch.setPhase_(phase);
        }

        const app = UIApplication.sharedApplication();
        const event = app['- _touchesEvent'].call(app);
        event['- _clearTouches'].call(event);

        const absoluteTime = mach_absolute_time();

        const timestamp = [
            absoluteTime.shr(32).toNumber(),
            absoluteTime.and(0xffffffff).toNumber()
        ];

        touch.setTimestamp_(CFGetSystemUptime());

        const eventMask = (phase === UITouchPhaseMoved)
            ? kIOHIDDigitizerEventPosition
            : (kIOHIDDigitizerEventRange | kIOHIDDigitizerEventTouch);
        const isRangeAndTouch = (phase !== UITouchPhaseEnded) ? 1 : 0;

        const hidEvent = IOHIDEventCreateDigitizerFingerEvent(
            kCFAllocatorDefault,
            timestamp,
            0,
            2,
            eventMask,
            point[0],
            point[1],
            0,
            0,
            0,
            isRangeAndTouch,
            isRangeAndTouch,
            0);

        if ('- _setHidEvent:' in touch) {
          touch['- _setHidEvent:'].call(touch, hidEvent);
        }

        event['- _setHIDEvent:'].call(event, hidEvent);
        event['- _addTouch:forDelayedDelivery:'].call(event, touch, false);

        const pool = NSAutoreleasePool.alloc().init();
        try {
          app.sendEvent_(event);
        } finally {
          pool.release();

          CFRelease(hidEvent);

          priv.previous = point;
          if (isLastTouch) {
            touch.release();
            priv.touch = null;
          }
        }
      }
    }
  }
});

function tap(view, x, y) {
  return new Promise(function (resolve) {
    const point = view.convertPoint_toView_([x, y], NULL);

    const injector = Injector.alloc().init();
    const priv = ObjC.getBoundData(injector);
    priv.window = view.window();
    priv.pending.push(point, CGPointZero);
    priv.onComplete = function () {
      injector.release();
      resolve();
    };
  });
}

module.exports = {
  tap: tap
};
